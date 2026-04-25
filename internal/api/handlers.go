package api

import (
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
	store     *kube.Store
	templates *template.Template
	broker    *Broker
}

// NewHandler creates a Handler with the given store, templates, and SSE broker.
func NewHandler(store *kube.Store, templates *template.Template, broker *Broker) *Handler {
	return &Handler{store: store, templates: templates, broker: broker}
}

// Index renders the static HTML shell (no data, unauthenticated).
func (h *Handler) Index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "index.html", nil); err != nil {
		slog.Error("failed to render template", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
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
		Secure:   r.TLS != nil,
	})
	w.WriteHeader(http.StatusNoContent)
}

// SessionNoop accepts browser session setup in tokenless deployments.
func (h *Handler) SessionNoop(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// DashboardContent renders the dashboard data partial (authenticated).
func (h *Handler) DashboardContent(w http.ResponseWriter, _ *http.Request) {
	dash := BuildDashboard(h.store.All())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "dashboard.html", dash); err != nil {
		slog.Error("failed to render dashboard content", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// WorkloadDetail renders the detail page for a single workload.
func (h *Handler) WorkloadDetail(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	name := r.PathValue("name")

	dash := BuildDashboard(h.store.All())

	var workload *WorkloadSummary
	for i := range dash.Workloads {
		if dash.Workloads[i].Namespace == namespace && dash.Workloads[i].WorkloadName == name {
			workload = &dash.Workloads[i]
			break
		}
	}

	if workload == nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "workload-detail.html", workload); err != nil {
		slog.Error("failed to render workload detail", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
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

	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case _, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: refresh\ndata: reload\n\n")
			flusher.Flush()
		}
	}
}
