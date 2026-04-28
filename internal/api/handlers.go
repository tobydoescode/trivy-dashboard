package api

import (
	"bytes"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tobydoescode/trivy-dashboard/internal/auth"
	"github.com/tobydoescode/trivy-dashboard/internal/kube"
)

// Handler serves the dashboard HTML pages and SSE stream.
type Handler struct {
	store         *kube.Store
	templates     *template.Template
	broker        *Broker
	authRequired  bool
	secureCookies bool
}

// HandlerOptions configures browser-visible auth behavior.
type HandlerOptions struct {
	AuthRequired  bool
	SecureCookies bool
}

// NewHandler creates a Handler with the given store, templates, and SSE broker.
func NewHandler(store *kube.Store, templates *template.Template, broker *Broker, opts ...HandlerOptions) *Handler {
	var opt HandlerOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	return &Handler{
		store:         store,
		templates:     templates,
		broker:        broker,
		authRequired:  opt.AuthRequired,
		secureCookies: opt.SecureCookies,
	}
}

func (h *Handler) renderTemplate(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := h.templates.ExecuteTemplate(&buf, name, data); err != nil {
		slog.Error("failed to render template", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w) //nolint:errcheck // best-effort response write
}

// Index renders the static HTML shell (no data, unauthenticated).
func (h *Handler) Index(w http.ResponseWriter, _ *http.Request) {
	h.renderTemplate(w, "index.html", struct{ AuthRequired bool }{h.authRequired})
}

// Session sets a browser session cookie after bearer authentication succeeds.
func (h *Handler) Session(w http.ResponseWriter, r *http.Request) {
	const prefix = "Bearer "
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, prefix) {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    strings.TrimPrefix(hdr, prefix),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   h.secureCookies || r.TLS != nil,
	})
	w.WriteHeader(http.StatusNoContent)
}

// SessionNoop accepts browser session setup in tokenless deployments.
func (h *Handler) SessionNoop(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// DashboardContent renders the dashboard data partial (authenticated).
func (h *Handler) DashboardContent(w http.ResponseWriter, _ *http.Request) {
	h.renderTemplate(w, "dashboard.html", BuildDashboard(h.store.All()))
}

// WorkloadDetail renders the detail page for a single workload.
func (h *Handler) WorkloadDetail(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	reportName := r.PathValue("report")

	dash := BuildDashboard(h.store.All())

	var workload *WorkloadSummary
	for i := range dash.Workloads {
		if dash.Workloads[i].Namespace == namespace && dash.Workloads[i].ReportName == reportName {
			workload = &dash.Workloads[i]
			break
		}
	}

	if workload == nil {
		http.NotFound(w, r)
		return
	}

	h.renderTemplate(w, "workload-detail.html", workload)
}

// SSE streams server-sent events to the client. A "refresh" event is
// sent whenever the vulnerability store changes.
func (h *Handler) SSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := h.broker.Subscribe()
	defer h.broker.Unsubscribe(ch)

	fmt.Fprintf(w, ": connected\n\n") //nolint:errcheck // best-effort SSE write
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case _, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: refresh\ndata: reload\n\n") //nolint:errcheck // best-effort SSE write
			flusher.Flush()
		}
	}
}
