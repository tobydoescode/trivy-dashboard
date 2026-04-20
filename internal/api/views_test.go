package api

import (
	"testing"

	"github.com/tobydoescode/trivy-dashboard/internal/kube"
)

func TestBuildDashboard(t *testing.T) {
	reports := []kube.VulnerabilityReport{
		{
			Name:      "replicaset-nginx-abc-nginx",
			Namespace: "web",
			Labels: map[string]string{
				"trivy-operator.resource.kind": "ReplicaSet",
				"trivy-operator.resource.name": "nginx-abc",
			},
			Report: kube.Report{
				Artifact: kube.Artifact{Repository: "library/nginx", Tag: "1.25"},
				Summary:  kube.Summary{Critical: 1, High: 2, Medium: 0, Low: 1},
				Vulns: []kube.Vulnerability{
					{ID: "CVE-2024-0001", Severity: "CRITICAL", Score: 9.8, Resource: "libcurl", InstalledVersion: "7.88", FixedVersion: "8.0", PrimaryLink: "https://avd.aquasec.com/nvd/cve-2024-0001"},
					{ID: "CVE-2024-0002", Severity: "HIGH", Score: 7.5, Resource: "openssl", InstalledVersion: "3.0", FixedVersion: "3.1", PrimaryLink: "https://avd.aquasec.com/nvd/cve-2024-0002"},
					{ID: "CVE-2024-0003", Severity: "HIGH", Score: 7.2, Resource: "zlib", InstalledVersion: "1.2", FixedVersion: "", PrimaryLink: "https://avd.aquasec.com/nvd/cve-2024-0003"},
					{ID: "CVE-2024-0004", Severity: "LOW", Score: 2.0, Resource: "bash", InstalledVersion: "5.1", FixedVersion: "5.2", PrimaryLink: "https://avd.aquasec.com/nvd/cve-2024-0004"},
				},
			},
		},
		{
			Name:      "replicaset-api-def-api",
			Namespace: "backend",
			Labels: map[string]string{
				"trivy-operator.resource.kind": "ReplicaSet",
				"trivy-operator.resource.name": "api-def",
			},
			Report: kube.Report{
				Artifact: kube.Artifact{Repository: "myorg/api", Tag: "v2"},
				Summary:  kube.Summary{Critical: 0, High: 0, Medium: 1, Low: 0},
				Vulns: []kube.Vulnerability{
					{ID: "CVE-2024-0005", Severity: "MEDIUM", Score: 5.0, Resource: "glibc", InstalledVersion: "2.35", FixedVersion: "2.36", PrimaryLink: "https://avd.aquasec.com/nvd/cve-2024-0005"},
				},
			},
		},
	}

	dash := BuildDashboard(reports)

	if dash.Summary.Critical != 1 {
		t.Errorf("summary critical = %d, want 1", dash.Summary.Critical)
	}
	if dash.Summary.High != 2 {
		t.Errorf("summary high = %d, want 2", dash.Summary.High)
	}
	if dash.Summary.Medium != 1 {
		t.Errorf("summary medium = %d, want 1", dash.Summary.Medium)
	}
	if dash.Summary.RAG != RAGRed {
		t.Errorf("summary RAG = %q, want %q", dash.Summary.RAG, RAGRed)
	}

	if len(dash.Workloads) != 2 {
		t.Fatalf("workloads count = %d, want 2", len(dash.Workloads))
	}

	w0 := dash.Workloads[0]
	if w0.Namespace != "web" {
		t.Errorf("first workload namespace = %q, want web", w0.Namespace)
	}
	if w0.RAG != RAGRed {
		t.Errorf("first workload RAG = %q, want %q", w0.RAG, RAGRed)
	}

	w1 := dash.Workloads[1]
	if w1.RAG != RAGAmber {
		t.Errorf("second workload RAG = %q, want %q", w1.RAG, RAGAmber)
	}
}

func TestBuildDashboard_Empty(t *testing.T) {
	dash := BuildDashboard(nil)
	if dash.Summary.RAG != RAGGreen {
		t.Errorf("empty dashboard RAG = %q, want %q", dash.Summary.RAG, RAGGreen)
	}
	if len(dash.Workloads) != 0 {
		t.Errorf("workloads = %d, want 0", len(dash.Workloads))
	}
}

func TestRAGStatus(t *testing.T) {
	tests := []struct {
		summary kube.Summary
		want    RAG
	}{
		{kube.Summary{Critical: 1}, RAGRed},
		{kube.Summary{High: 1}, RAGRed},
		{kube.Summary{Medium: 1}, RAGAmber},
		{kube.Summary{Low: 1}, RAGGreen},
		{kube.Summary{}, RAGGreen},
	}
	for _, tt := range tests {
		got := ragFromSummary(tt.summary)
		if got != tt.want {
			t.Errorf("ragFromSummary(%+v) = %q, want %q", tt.summary, got, tt.want)
		}
	}
}
