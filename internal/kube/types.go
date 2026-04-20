// Package kube provides Kubernetes client utilities for watching
// Trivy VulnerabilityReport CRDs.
package kube

// VulnerabilityReport represents a parsed Trivy VulnerabilityReport CRD.
type VulnerabilityReport struct {
	Name      string
	Namespace string
	Labels    map[string]string
	Report    Report
}

// Report contains the vulnerability scan results.
type Report struct {
	Artifact Artifact
	Summary  Summary
	Vulns    []Vulnerability
}

// Artifact identifies the scanned container image.
type Artifact struct {
	Repository string
	Tag        string
}

// Summary holds vulnerability counts by severity.
type Summary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

// Vulnerability describes a single detected vulnerability.
type Vulnerability struct {
	ID               string
	Severity         string
	Score            float64
	Title            string
	Resource         string
	InstalledVersion string
	FixedVersion     string
	PrimaryLink      string
}
