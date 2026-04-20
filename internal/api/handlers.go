package api

import (
	"html/template"
	"log/slog"
	"net/http"

	"github.com/tobydoescode/trivy-dashboard/internal/kube"
)

// Handler serves the dashboard HTML pages.
type Handler struct {
	store     *kube.Store
	templates *template.Template
}

// NewHandler creates a Handler with the given store and parsed templates.
func NewHandler(store *kube.Store, templates *template.Template) *Handler {
	return &Handler{store: store, templates: templates}
}

// Index renders the static HTML shell (no data, unauthenticated).
func (h *Handler) Index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "index.html", nil); err != nil {
		slog.Error("failed to render template", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
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
