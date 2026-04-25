package main

import (
	"context"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/tobydoescode/trivy-dashboard/internal/api"
	"github.com/tobydoescode/trivy-dashboard/internal/auth"
	"github.com/tobydoescode/trivy-dashboard/internal/kube"
	"github.com/tobydoescode/trivy-dashboard/internal/metrics"
	"github.com/tobydoescode/trivy-dashboard/internal/views"
)

var vulnReportGVR = schema.GroupVersionResource{
	Group:    "aquasecurity.github.io",
	Version:  "v1alpha1",
	Resource: "vulnerabilityreports",
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	m := metrics.New(reg)

	addr := os.Getenv("TRIVY_DASHBOARD_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	token := os.Getenv("TRIVY_DASHBOARD_TOKEN")
	secureCookies := os.Getenv("TRIVY_DASHBOARD_SECURE_COOKIES") == "true"

	cfg, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			home, _ := os.UserHomeDir()
			kubeconfig = home + "/.kube/config"
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			logger.Error("failed to build kubernetes config", "err", err)
			os.Exit(1)
		}
		logger.Info("using kubeconfig", "path", kubeconfig)
	}

	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		logger.Error("failed to create dynamic client", "err", err)
		os.Exit(1)
	}

	store := kube.NewStore()
	broker := api.NewBroker(500 * time.Millisecond)
	defer broker.Shutdown()

	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dynClient, 30*time.Minute, "", nil)
	informer := factory.ForResource(vulnReportGVR).Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			handleEvent(store, obj)
			m.SetStoreSize(store.Len())
			broker.Notify()
		},
		UpdateFunc: func(_, obj interface{}) {
			handleEvent(store, obj)
			m.SetStoreSize(store.Len())
			broker.Notify()
		},
		DeleteFunc: func(obj interface{}) {
			d, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err != nil {
				logger.Warn("failed to get key for deleted object", "err", err)
				return
			}
			ns, name, _ := cache.SplitMetaNamespaceKey(d)
			store.Delete(ns, name)
			m.SetStoreSize(store.Len())
			broker.Notify()
			logger.Info("deleted vulnerability report", "namespace", ns, "name", name)
		},
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		informer.Run(ctx.Done())
	}()

	syncCtx, syncCancel := context.WithTimeout(ctx, 60*time.Second)
	defer syncCancel()
	if !cache.WaitForCacheSync(syncCtx.Done(), informer.HasSynced) {
		logger.Error("failed to sync informer cache")
		os.Exit(1)
	}
	store.MarkSynced()
	m.SetSynced(true)
	logger.Info("informer cache synced")

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !store.IsSynced() {
			http.Error(w, "not synced", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	tmpl, err := template.New("").Funcs(api.TemplateFuncs()).ParseFS(views.Templates, "templates/*.html")
	if err != nil {
		logger.Error("failed to parse templates", "err", err)
		os.Exit(1)
	}

	handler := api.NewHandler(store, tmpl, broker, api.HandlerOptions{
		AuthRequired:  token != "",
		SecureCookies: secureCookies,
	})
	mux.HandleFunc("GET /", handler.Index)
	if token != "" {
		authed := auth.Bearer(token)
		mux.Handle("POST /api/session", authed(http.HandlerFunc(handler.Session)))
		mux.Handle("GET /api/dashboard", authed(http.HandlerFunc(handler.DashboardContent)))
		mux.Handle("GET /workload/{namespace}/{report}", authed(http.HandlerFunc(handler.WorkloadDetail)))
		mux.Handle("GET /api/events", authed(http.HandlerFunc(handler.SSE)))
	} else {
		mux.HandleFunc("POST /api/session", handler.SessionNoop)
		mux.HandleFunc("GET /api/dashboard", handler.DashboardContent)
		mux.HandleFunc("GET /workload/{namespace}/{report}", handler.WorkloadDetail)
		mux.HandleFunc("GET /api/events", handler.SSE)
	}

	staticFS, err := fs.Sub(views.Static, "static")
	if err != nil {
		logger.Error("failed to create static sub-filesystem", "err", err)
		os.Exit(1)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	srv := &http.Server{
		Addr:              addr,
		Handler:           m.InstrumentHandler(api.SecurityHeaders(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		logger.Error("server error", "err", err)
		os.Exit(1)
	case <-ctx.Done():
		logger.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", "err", err)
		os.Exit(1)
	}
}

func handleEvent(store *kube.Store, obj interface{}) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		slog.Warn("failed to convert object to unstructured")
		return
	}
	report, err := kube.ParseVulnerabilityReport(u)
	if err != nil {
		slog.Warn("failed to parse vulnerability report", "err", err)
		return
	}
	store.Set(report)
	slog.Info("synced vulnerability report", "namespace", report.Namespace, "name", report.Name)
}
