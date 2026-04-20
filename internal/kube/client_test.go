package kube

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestParseVulnerabilityReport(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "aquasecurity.github.io/v1alpha1",
			"kind":       "VulnerabilityReport",
			"metadata": map[string]interface{}{
				"name":      "replicaset-nginx-abc123-nginx",
				"namespace": "default",
				"labels": map[string]interface{}{
					"trivy-operator.resource.kind": "ReplicaSet",
					"trivy-operator.resource.name": "nginx-abc123",
				},
			},
			"report": map[string]interface{}{
				"artifact": map[string]interface{}{
					"repository": "library/nginx",
					"tag":        "1.25",
				},
				"summary": map[string]interface{}{
					"criticalCount": int64(1),
					"highCount":     int64(2),
					"mediumCount":   int64(3),
					"lowCount":      int64(0),
					"unknownCount":  int64(0),
				},
				"vulnerabilities": []interface{}{
					map[string]interface{}{
						"vulnerabilityID":  "CVE-2024-1234",
						"severity":         "CRITICAL",
						"score":            9.8,
						"title":            "Buffer overflow in libcurl",
						"resource":         "libcurl",
						"installedVersion": "7.88.0",
						"fixedVersion":     "8.0.0",
						"primaryLink":      "https://avd.aquasec.com/nvd/cve-2024-1234",
					},
				},
			},
		},
	}

	report, err := ParseVulnerabilityReport(obj)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Name != "replicaset-nginx-abc123-nginx" {
		t.Errorf("name = %q, want %q", report.Name, "replicaset-nginx-abc123-nginx")
	}
	if report.Namespace != "default" {
		t.Errorf("namespace = %q, want %q", report.Namespace, "default")
	}
	if report.Report.Summary.Critical != 1 {
		t.Errorf("critical = %d, want 1", report.Report.Summary.Critical)
	}
	if report.Report.Summary.High != 2 {
		t.Errorf("high = %d, want 2", report.Report.Summary.High)
	}
	if len(report.Report.Vulns) != 1 {
		t.Fatalf("vulns count = %d, want 1", len(report.Report.Vulns))
	}
	v := report.Report.Vulns[0]
	if v.ID != "CVE-2024-1234" {
		t.Errorf("vuln ID = %q, want CVE-2024-1234", v.ID)
	}
	if v.Score != 9.8 {
		t.Errorf("score = %f, want 9.8", v.Score)
	}
	if v.FixedVersion != "8.0.0" {
		t.Errorf("fixedVersion = %q, want 8.0.0", v.FixedVersion)
	}
}

func TestStore(t *testing.T) {
	s := NewStore()
	if s.IsSynced() {
		t.Error("store should not be synced initially")
	}
	r := &VulnerabilityReport{Name: "test-report", Namespace: "default"}
	s.Set(r)
	all := s.All() // all is now []VulnerabilityReport, not []*VulnerabilityReport
	if len(all) != 1 {
		t.Fatalf("expected 1 report, got %d", len(all))
	}
	if all[0].Name != "test-report" {
		t.Errorf("name = %q, want test-report", all[0].Name)
	}
	s.Delete("default", "test-report")
	if len(s.All()) != 0 {
		t.Error("expected 0 reports after delete")
	}
	s.MarkSynced()
	if !s.IsSynced() {
		t.Error("store should be synced after MarkSynced")
	}
}
