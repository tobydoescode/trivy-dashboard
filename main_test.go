package main

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/tobydoescode/trivy-dashboard/internal/kube"
)

func vulnReportObj(name, namespace string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"report": map[string]interface{}{
				"summary": map[string]interface{}{
					"criticalCount": int64(1),
				},
			},
		},
	}
}

func TestHandleEvent_StoresParsedReport(t *testing.T) {
	store := kube.NewStore()

	handleEvent(store, vulnReportObj("report-a", "web"))

	got, ok := store.Get("web", "report-a")
	if !ok {
		t.Fatal("report should be stored")
	}
	if got.Report.Summary.Critical != 1 {
		t.Errorf("critical = %d, want 1", got.Report.Summary.Critical)
	}
}

func TestHandleEvent_IgnoresNonUnstructured(t *testing.T) {
	store := kube.NewStore()

	handleEvent(store, "not-an-object")

	if store.Len() != 0 {
		t.Errorf("store len = %d, want 0", store.Len())
	}
}

func TestHandleEvent_IgnoresUnparseableReport(t *testing.T) {
	store := kube.NewStore()
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"name":      "broken",
				"namespace": "web",
			},
			// no report field
		},
	}

	handleEvent(store, obj)

	if store.Len() != 0 {
		t.Errorf("store len = %d, want 0", store.Len())
	}
}
