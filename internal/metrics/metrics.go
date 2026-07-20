package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for the dashboard.
type Metrics struct {
	requestDuration *prometheus.HistogramVec
	storeReports    prometheus.Gauge
	storeSynced     prometheus.Gauge
	watchHealthy    prometheus.Gauge
	watchErrors     prometheus.Counter
}

// New creates and registers all metrics with the given registry.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "code"}),
		storeReports: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "trivy_dashboard_store_reports",
			Help: "Number of vulnerability reports in store.",
		}),
		storeSynced: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "trivy_dashboard_store_synced",
			Help: "Whether the informer cache is synced (1=yes, 0=no).",
		}),
		watchHealthy: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "trivy_dashboard_watch_healthy",
			Help: "Whether the report watch is healthy (1=yes, 0=last attempt errored).",
		}),
		watchErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "trivy_dashboard_watch_errors_total",
			Help: "Total watch/list errors from the informer.",
		}),
	}
	reg.MustRegister(m.requestDuration, m.storeReports, m.storeSynced, m.watchHealthy, m.watchErrors)
	return m
}

// InstrumentHandler wraps an http.Handler with request duration tracking.
func (m *Metrics) InstrumentHandler(next http.Handler) http.Handler {
	return promhttp.InstrumentHandlerDuration(m.requestDuration, next)
}

// SetStoreSize sets the store reports gauge.
func (m *Metrics) SetStoreSize(n int) {
	m.storeReports.Set(float64(n))
}

// SetSynced sets the synced gauge (1 or 0).
func (m *Metrics) SetSynced(synced bool) {
	if synced {
		m.storeSynced.Set(1)
	} else {
		m.storeSynced.Set(0)
	}
}

// SetWatchHealthy sets the watch health gauge (1 or 0).
func (m *Metrics) SetWatchHealthy(healthy bool) {
	if healthy {
		m.watchHealthy.Set(1)
	} else {
		m.watchHealthy.Set(0)
	}
}

// IncWatchErrors increments the watch error counter.
func (m *Metrics) IncWatchErrors() {
	m.watchErrors.Inc()
}
