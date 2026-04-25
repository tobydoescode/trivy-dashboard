package api

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tobydoescode/trivy-dashboard/internal/auth"
	"github.com/tobydoescode/trivy-dashboard/internal/kube"
	"github.com/tobydoescode/trivy-dashboard/internal/views"
)

func testHandler(t *testing.T, reports ...*kube.VulnerabilityReport) *Handler {
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
	return NewHandler(store, tmpl, broker)
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
}

func TestSession_SetsHttpOnlyCookie(t *testing.T) {
	h := testHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/session", nil)
	req.Header.Set("Authorization", "Bearer secret")

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
	if got.Value != "secret" {
		t.Fatalf("cookie value = %q, want secret", got.Value)
	}
	if got.Path != "/" {
		t.Fatalf("cookie path = %q, want /", got.Path)
	}
	if !got.HttpOnly {
		t.Fatal("cookie should be HttpOnly")
	}
	if got.SameSite != http.SameSiteStrictMode {
		t.Fatalf("SameSite = %v, want Strict", got.SameSite)
	}
}

func TestSession_RejectsMissingBearerToken(t *testing.T) {
	h := testHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/session", nil)

	h.Session(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
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
	req := httptest.NewRequest("GET", "/workload/web/nginx-abc", nil)
	req.SetPathValue("namespace", "web")
	req.SetPathValue("name", "nginx-abc")
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

func TestWorkloadDetail_NotFound(t *testing.T) {
	h := testHandler(t, sampleReport())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/workload/nope/nope", nil)
	req.SetPathValue("namespace", "nope")
	req.SetPathValue("name", "nope")
	h.WorkloadDetail(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}
