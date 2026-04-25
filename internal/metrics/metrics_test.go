package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestInstrumentHandler(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := m.InstrumentHandler(inner)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/dashboard", nil)
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	metricsRec := httptest.NewRecorder()
	metricsReq := httptest.NewRequest("GET", "/metrics", nil)
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(metricsRec, metricsReq)

	body := metricsRec.Body.String()
	if !strings.Contains(body, "http_request_duration_seconds") {
		t.Error("metrics output should contain http_request_duration_seconds")
	}
}

func TestStoreMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.SetStoreSize(42)
	m.SetSynced(true)

	metricsRec := httptest.NewRecorder()
	metricsReq := httptest.NewRequest("GET", "/metrics", nil)
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(metricsRec, metricsReq)

	body := metricsRec.Body.String()
	if !strings.Contains(body, "trivy_dashboard_store_reports 42") {
		t.Errorf("expected store_reports 42, got:\n%s", body)
	}
	if !strings.Contains(body, "trivy_dashboard_store_synced 1") {
		t.Errorf("expected store_synced 1, got:\n%s", body)
	}
}
