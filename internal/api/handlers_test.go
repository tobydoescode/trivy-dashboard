package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tobydoescode/trivy-dashboard/internal/auth"
	"github.com/tobydoescode/trivy-dashboard/internal/kube"
	"github.com/tobydoescode/trivy-dashboard/internal/views"
)

func testHandler(t *testing.T, reports ...*kube.VulnerabilityReport) *Handler {
	return testHandlerWithOptions(t, HandlerOptions{}, reports...)
}

func testHandlerWithOptions(t *testing.T, opts HandlerOptions, reports ...*kube.VulnerabilityReport) *Handler {
	t.Helper()
	tmpl, err := template.New("").Funcs(TemplateFuncs()).ParseFS(views.Templates, "templates/*.html")
	if err != nil {
		t.Fatalf("failed to parse templates: %v", err)
	}
	store := kube.NewStore()
	for _, r := range reports {
		store.Set(r)
	}
	broker := NewBroker(10 * time.Millisecond)
	t.Cleanup(broker.Shutdown)
	return NewHandler(store, tmpl, broker, opts)
}

func sampleReport() *kube.VulnerabilityReport {
	return &kube.VulnerabilityReport{
		Name:      "replicaset-nginx-abc-nginx",
		Namespace: "web",
		Labels: map[string]string{
			"trivy-operator.resource.kind": "ReplicaSet",
			"trivy-operator.resource.name": "nginx-abc",
		},
		Report: kube.Report{
			Artifact: kube.Artifact{Repository: "library/nginx", Tag: "1.25"},
			Summary:  kube.Summary{Critical: 1, High: 0, Medium: 0, Low: 0},
			Vulns: []kube.Vulnerability{
				{ID: "CVE-2024-0001", Severity: "CRITICAL", Score: 9.8, Resource: "libcurl", InstalledVersion: "7.88", FixedVersion: "8.0", PrimaryLink: "https://avd.aquasec.com/nvd/cve-2024-0001"},
			},
		},
	}
}

func TestIndex(t *testing.T) {
	h := testHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	h.Index(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Vulnerability Dashboard") {
		t.Error("response missing 'Vulnerability Dashboard' title")
	}
	if !strings.Contains(body, "app.js") {
		t.Error("response missing app.js script reference")
	}
	if !strings.Contains(body, `id="auth-required" data-required="false"`) {
		t.Error("response should expose tokenless auth mode")
	}
}

func TestIndex_AuthRequired(t *testing.T) {
	h := testHandlerWithOptions(t, HandlerOptions{AuthRequired: true})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	h.Index(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `id="auth-required" data-required="true"`) {
		t.Error("response should expose required auth mode")
	}
}

func TestSession_SetsRandomSessionIDCookie(t *testing.T) {
	sessions := auth.NewSessionStore(time.Hour)
	h := testHandlerWithOptions(t, HandlerOptions{AuthRequired: true, Sessions: sessions})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/session", nil)

	h.Session(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	got := cookies[0]
	if got.Name != auth.SessionCookieName {
		t.Fatalf("cookie name = %q, want %q", got.Name, auth.SessionCookieName)
	}
	if !sessions.Valid(got.Value) {
		t.Fatal("cookie value should be a live session ID")
	}
	if got.Path != "/" {
		t.Fatalf("cookie path = %q, want /", got.Path)
	}
	if got.MaxAge != int(time.Hour.Seconds()) {
		t.Fatalf("cookie MaxAge = %d, want %d", got.MaxAge, int(time.Hour.Seconds()))
	}
	if !got.HttpOnly {
		t.Fatal("cookie should be HttpOnly")
	}
	if got.SameSite != http.SameSiteStrictMode {
		t.Fatalf("SameSite = %v, want Strict", got.SameSite)
	}
}

func TestSession_CanForceSecureCookieBehindProxy(t *testing.T) {
	sessions := auth.NewSessionStore(time.Hour)
	h := testHandlerWithOptions(t, HandlerOptions{AuthRequired: true, SecureCookies: true, Sessions: sessions})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/session", nil)

	h.Session(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	if !cookies[0].Secure {
		t.Fatal("cookie should be Secure when SecureCookies is enabled")
	}
}

func TestSession_MarksCookieSecureOverTLS(t *testing.T) {
	sessions := auth.NewSessionStore(time.Hour)
	h := testHandlerWithOptions(t, HandlerOptions{AuthRequired: true, Sessions: sessions})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/session", nil)
	req.TLS = &tls.ConnectionState{}

	h.Session(rec, req)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	if !cookies[0].Secure {
		t.Fatal("cookie should be Secure on a TLS request")
	}
}

func TestSession_NilSessionStoreSetsNoCookie(t *testing.T) {
	h := testHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/session", nil)

	h.Session(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("no cookie should be set without a session store")
	}
}

func TestSessionNoop(t *testing.T) {
	h := testHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/session", nil)

	h.SessionNoop(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("noop should not set cookies")
	}
}

func TestSession_MiddlewareRejectsMissingBearerToken(t *testing.T) {
	sessions := auth.NewSessionStore(time.Hour)
	h := testHandlerWithOptions(t, HandlerOptions{AuthRequired: true, Sessions: sessions})
	protected := auth.Bearer("secret", sessions)(http.HandlerFunc(h.Session))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/session", nil)

	protected.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("no cookie should be set without authentication")
	}
}

func TestSignOut_RevokesSessionAndExpiresCookie(t *testing.T) {
	sessions := auth.NewSessionStore(time.Hour)
	id := sessions.Create()
	h := testHandlerWithOptions(t, HandlerOptions{AuthRequired: true, Sessions: sessions})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/session", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: id})

	h.SignOut(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if sessions.Valid(id) {
		t.Fatal("session should be revoked after sign-out")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	if cookies[0].MaxAge >= 0 {
		t.Fatalf("cookie MaxAge = %d, want negative (expired)", cookies[0].MaxAge)
	}
}

func TestRenderTemplate_UnknownTemplateReturns500(t *testing.T) {
	h := testHandler(t)
	rec := httptest.NewRecorder()

	h.renderTemplate(rec, "does-not-exist.html", nil)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestDashboardContent_Empty(t *testing.T) {
	h := testHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/dashboard", nil)
	h.DashboardContent(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "rag-green") {
		t.Error("empty dashboard should have rag-green summary")
	}
	if !strings.Contains(body, "0 Critical") {
		t.Error("empty dashboard should show 0 Critical")
	}
}

func TestDashboardContent_WithData(t *testing.T) {
	h := testHandler(t, sampleReport())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/dashboard", nil)
	h.DashboardContent(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "rag-red") {
		t.Error("dashboard with critical vuln should have rag-red")
	}
	if !strings.Contains(body, "1 Critical") {
		t.Error("dashboard should show 1 Critical")
	}
	if !strings.Contains(body, "web/nginx-abc") {
		t.Error("dashboard should contain workload name")
	}
	if !strings.Contains(body, "library/nginx:1.25") {
		t.Error("dashboard should contain image name")
	}
}

func TestWorkloadDetail_Found(t *testing.T) {
	h := testHandler(t, sampleReport())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/workload/web/replicaset-nginx-abc-nginx", nil)
	req.SetPathValue("namespace", "web")
	req.SetPathValue("report", "replicaset-nginx-abc-nginx")
	h.WorkloadDetail(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "CVE-2024-0001") {
		t.Error("detail should contain CVE ID")
	}
	if !strings.Contains(body, "CRITICAL") {
		t.Error("detail should contain severity")
	}
	if !strings.Contains(body, "libcurl") {
		t.Error("detail should contain affected package")
	}
	if !strings.Contains(body, "https://avd.aquasec.com/nvd/cve-2024-0001") {
		t.Error("detail should contain primary link")
	}
}

func TestWorkloadDetail_UsesReportNameToDisambiguateSameWorkload(t *testing.T) {
	apiReport := sampleReport()
	apiReport.Name = "replicaset-api-api"
	apiReport.Labels["trivy-operator.resource.name"] = "api"
	apiReport.Report.Artifact = kube.Artifact{Repository: "myorg/api", Tag: "v1"}
	apiReport.Report.Vulns = []kube.Vulnerability{{ID: "CVE-API", Severity: "HIGH", Resource: "api"}}

	sidecarReport := sampleReport()
	sidecarReport.Name = "replicaset-api-sidecar"
	sidecarReport.Labels = map[string]string{
		"trivy-operator.resource.kind": "ReplicaSet",
		"trivy-operator.resource.name": "api",
	}
	sidecarReport.Report.Artifact = kube.Artifact{Repository: "myorg/sidecar", Tag: "v1"}
	sidecarReport.Report.Vulns = []kube.Vulnerability{{ID: "CVE-SIDECAR", Severity: "HIGH", Resource: "sidecar"}}

	h := testHandler(t, apiReport, sidecarReport)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/workload/web/replicaset-api-sidecar", nil)
	req.SetPathValue("namespace", "web")
	req.SetPathValue("report", "replicaset-api-sidecar")
	h.WorkloadDetail(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "CVE-SIDECAR") {
		t.Fatalf("detail should contain sidecar CVE, got %q", body)
	}
	if strings.Contains(body, "CVE-API") {
		t.Fatalf("detail should not contain API CVE, got %q", body)
	}
}

func TestWorkloadDetail_NotFound(t *testing.T) {
	h := testHandler(t, sampleReport())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/workload/nope/nope", nil)
	req.SetPathValue("namespace", "nope")
	req.SetPathValue("report", "nope")
	h.WorkloadDetail(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestSSE_ConnectsWithSessionCookie(t *testing.T) {
	h := testHandler(t)
	sessions := auth.NewSessionStore(time.Hour)
	id := sessions.Create()
	protected := auth.Bearer("secret", sessions)(http.HandlerFunc(h.SSE))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/events", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: id})
	rec := newFlushRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		protected.ServeHTTP(rec, req)
	}()

	select {
	case <-rec.wrote:
	case <-time.After(500 * time.Millisecond):
		cancel()
		t.Fatal("timed out waiting for SSE greeting")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SSE handler did not exit after context cancellation")
	}

	if rec.code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.code, http.StatusOK)
	}
	if !strings.HasPrefix(rec.header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", rec.header.Get("Content-Type"))
	}
	if !strings.Contains(rec.body.String(), ": connected\n\n") {
		t.Fatalf("SSE response missing connected greeting: %q", rec.body.String())
	}
}

type noFlushWriter struct {
	header http.Header
	code   int
}

func (w *noFlushWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *noFlushWriter) Write(p []byte) (int, error) { return len(p), nil }

func (w *noFlushWriter) WriteHeader(code int) { w.code = code }

func TestSSE_RequiresFlusher(t *testing.T) {
	h := testHandler(t)
	rec := &noFlushWriter{}
	req := httptest.NewRequest(http.MethodGet, "/api/events", nil)

	h.SSE(rec, req)

	if rec.code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.code, http.StatusInternalServerError)
	}
}

func TestSSE_ExitsWhenBrokerShutsDown(t *testing.T) {
	h := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/events", nil)
	rec := newFlushRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.SSE(rec, req)
	}()

	select {
	case <-rec.wrote:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for SSE greeting")
	}

	h.broker.Shutdown()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SSE handler did not exit after broker shutdown")
	}
}

func TestSSE_SendsHeartbeat(t *testing.T) {
	orig := sseHeartbeatInterval
	sseHeartbeatInterval = 10 * time.Millisecond
	defer func() { sseHeartbeatInterval = orig }()

	h := testHandler(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/events", nil)
	rec := newFlushRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.SSE(rec, req)
	}()

	deadline := time.After(500 * time.Millisecond)
	for {
		rec.mu.Lock()
		got := strings.Contains(rec.body.String(), ": ping\n\n")
		rec.mu.Unlock()
		if got {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for heartbeat ping")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	<-done
}

func TestAuthenticatedSSE_RejectsQueryToken(t *testing.T) {
	h := testHandler(t)
	protected := auth.Bearer("secret", nil)(http.HandlerFunc(h.SSE))

	req := httptest.NewRequest(http.MethodGet, "/api/events?token=secret", nil)
	rec := httptest.NewRecorder()

	protected.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

type flushRecorder struct {
	mu     sync.Mutex
	header http.Header
	body   bytes.Buffer
	code   int
	once   sync.Once
	wrote  chan struct{}
}

func newFlushRecorder() *flushRecorder {
	return &flushRecorder{
		header: make(http.Header),
		code:   http.StatusOK,
		wrote:  make(chan struct{}),
	}
}

func (r *flushRecorder) Header() http.Header {
	return r.header
}

func (r *flushRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	n, err := r.body.Write(p)
	r.mu.Unlock()
	r.once.Do(func() {
		close(r.wrote)
	})
	return n, err
}

func (r *flushRecorder) WriteHeader(code int) {
	r.code = code
}

func (r *flushRecorder) Flush() {}
