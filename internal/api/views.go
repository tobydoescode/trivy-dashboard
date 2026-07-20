package api

import (
	"sort"

	"github.com/tobydoescode/trivy-dashboard/internal/kube"
)

// RAG represents a Red/Amber/Green status indicator.
type RAG string

const (
	RAGRed   RAG = "red"
	RAGAmber RAG = "amber"
	RAGGreen RAG = "green"
)

// Dashboard is the top-level view model for the dashboard page.
type Dashboard struct {
	Summary   DashboardSummary
	Workloads []WorkloadSummary
}

// DashboardSummary holds aggregate vulnerability counts across all workloads.
type DashboardSummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
	RAG      RAG
}

// WorkloadSummary holds vulnerability data for a single workload.
type WorkloadSummary struct {
	Namespace    string
	ReportName   string
	WorkloadName string
	WorkloadKind string
	Image        string
	Critical     int
	High         int
	Medium       int
	Low          int
	Unknown      int
	RAG          RAG
	Vulns        []kube.Vulnerability
}

// BuildDashboard transforms a slice of VulnerabilityReports into a Dashboard view model.
func BuildDashboard(reports []kube.VulnerabilityReport) Dashboard {
	var dash Dashboard

	for _, r := range reports {
		dash.Workloads = append(dash.Workloads, buildWorkloadSummary(r))

		dash.Summary.Critical += r.Report.Summary.Critical
		dash.Summary.High += r.Report.Summary.High
		dash.Summary.Medium += r.Report.Summary.Medium
		dash.Summary.Low += r.Report.Summary.Low
		dash.Summary.Unknown += r.Report.Summary.Unknown
	}

	dash.Summary.RAG = ragFromSummary(kube.Summary{
		Critical: dash.Summary.Critical,
		High:     dash.Summary.High,
		Medium:   dash.Summary.Medium,
		Low:      dash.Summary.Low,
		Unknown:  dash.Summary.Unknown,
	})

	sort.Slice(dash.Workloads, func(i, j int) bool {
		a, b := dash.Workloads[i], dash.Workloads[j]
		if a.Critical != b.Critical {
			return a.Critical > b.Critical
		}
		if a.High != b.High {
			return a.High > b.High
		}
		if a.Medium != b.Medium {
			return a.Medium > b.Medium
		}
		return a.Namespace+"/"+a.WorkloadName < b.Namespace+"/"+b.WorkloadName
	})

	return dash
}

func buildWorkloadSummary(r kube.VulnerabilityReport) WorkloadSummary {
	image := r.Report.Artifact.Repository
	if r.Report.Artifact.Tag != "" {
		image += ":" + r.Report.Artifact.Tag
	}

	return WorkloadSummary{
		Namespace:    r.Namespace,
		ReportName:   r.Name,
		WorkloadName: r.Labels["trivy-operator.resource.name"],
		WorkloadKind: r.Labels["trivy-operator.resource.kind"],
		Image:        image,
		Critical:     r.Report.Summary.Critical,
		High:         r.Report.Summary.High,
		Medium:       r.Report.Summary.Medium,
		Low:          r.Report.Summary.Low,
		Unknown:      r.Report.Summary.Unknown,
		RAG:          ragFromSummary(r.Report.Summary),
		Vulns:        r.Report.Vulns,
	}
}

// ragFromSummary buckets a summary: Red for any CRITICAL/HIGH, Amber for
// MEDIUM or UNKNOWN (unscored vulns must not read as clean), Green otherwise.
func ragFromSummary(s kube.Summary) RAG {
	if s.Critical > 0 || s.High > 0 {
		return RAGRed
	}
	if s.Medium > 0 || s.Unknown > 0 {
		return RAGAmber
	}
	return RAGGreen
}
