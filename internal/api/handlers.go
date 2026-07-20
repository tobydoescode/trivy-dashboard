package api

import (
	"bytes"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/tobydoescode/trivy-dashboard/internal/auth"
	"github.com/tobydoescode/trivy-dashboard/internal/kube"
)

var sseHeartbeatInterval = 30 * time.Second

// Handler serves the dashboard HTML pages and SSE stream.
type Handler struct {
	store         *kube.Store
	templates     *template.Template
	broker        *Broker
	sessions      *auth.SessionStore
	authRequired  bool
	secureCookies bool
}

// HandlerOptions configures browser-visible auth behavior.
type HandlerOptions struct {
	AuthRequired  bool
	SecureCookies bool
	Sessions      *auth.SessionStore
}

// NewHandler creates a Handler with the given store, templates, and SSE broker.
func NewHandler(store *kube.Store, templates *template.Template, broker *Broker, opts HandlerOptions) *Handler {
	return &Handler{
		store:         store,
		templates:     templates,
		broker:        broker,
		sessions:      opts.Sessions,
		authRequired:  opts.AuthRequired,
		secureCookies: opts.SecureCookies,
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

// Session mints a random server-side session ID and sets it as an HTTP-only
// cookie. Bearer authentication happens in middleware before this runs, so
// the token itself never has to be stored client-side.
func (h *Handler) Session(w http.ResponseWriter, r *http.Request) {
	if h.sessions == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    h.sessions.Create(),
		Path:     "/",
		MaxAge:   int(h.sessions.TTL().Seconds()),
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

// SignOut revokes the caller's session and expires the cookie.
func (h *Handler) SignOut(w http.ResponseWriter, r *http.Request) {
	if h.sessions != nil {
		if cookie, err := r.Cookie(auth.SessionCookieName); err == nil {
			h.sessions.Delete(cookie.Value)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   h.secureCookies || r.TLS != nil,
	})
	w.WriteHeader(http.StatusNoContent)
}

// DashboardContent renders the dashboard data partial (authenticated).
func (h *Handler) DashboardContent(w http.ResponseWriter, _ *http.Request) {
	h.renderTemplate(w, "dashboard.html", BuildDashboard(h.store.All()))
}

// WorkloadDetail renders the detail page for a single workload.
func (h *Handler) WorkloadDetail(w http.ResponseWriter, r *http.Request) {
	report, ok := h.store.Get(r.PathValue("namespace"), r.PathValue("report"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	ws := buildWorkloadSummary(report)
	h.renderTemplate(w, "workload-detail.html", &ws)
}

// SSE streams server-sent events to the client. A "refresh" event is
// sent whenever the vulnerability store changes; comment pings keep the
// connection alive through proxies.
func (h *Handler) SSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// The server-wide WriteTimeout would sever the stream; SSE responses
	// never complete, so clear the deadline for this response only.
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{}) //nolint:errcheck // test recorders lack deadline support

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := h.broker.Subscribe()
	defer h.broker.Unsubscribe(ch)

	fmt.Fprintf(w, ": connected\n\n") //nolint:errcheck // best-effort SSE write
	flusher.Flush()

	heartbeat := time.NewTicker(sseHeartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			fmt.Fprintf(w, ": ping\n\n") //nolint:errcheck // best-effort SSE write
			flusher.Flush()
		case _, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: refresh\ndata: reload\n\n") //nolint:errcheck // best-effort SSE write
			flusher.Flush()
		}
	}
}
