package kube

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ParseVulnerabilityReport converts an unstructured Kubernetes object into a
// VulnerabilityReport.
func ParseVulnerabilityReport(obj *unstructured.Unstructured) (*VulnerabilityReport, error) {
	report := &VulnerabilityReport{
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
		Labels:    obj.GetLabels(),
	}
	r, ok := obj.Object["report"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing or invalid report field")
	}
	if artifact, ok := r["artifact"].(map[string]interface{}); ok {
		report.Report.Artifact.Repository, _ = artifact["repository"].(string)
		report.Report.Artifact.Tag, _ = artifact["tag"].(string)
	}
	if summary, ok := r["summary"].(map[string]interface{}); ok {
		report.Report.Summary.Critical = intFromUnstructured(summary, "criticalCount")
		report.Report.Summary.High = intFromUnstructured(summary, "highCount")
		report.Report.Summary.Medium = intFromUnstructured(summary, "mediumCount")
		report.Report.Summary.Low = intFromUnstructured(summary, "lowCount")
		report.Report.Summary.Unknown = intFromUnstructured(summary, "unknownCount")
	}
	if vulns, ok := r["vulnerabilities"].([]interface{}); ok {
		for _, vi := range vulns {
			vm, ok := vi.(map[string]interface{})
			if !ok {
				continue
			}
			v := Vulnerability{
				ID:               strField(vm, "vulnerabilityID"),
				Severity:         strField(vm, "severity"),
				Title:            strField(vm, "title"),
				Resource:         strField(vm, "resource"),
				InstalledVersion: strField(vm, "installedVersion"),
				FixedVersion:     strField(vm, "fixedVersion"),
				PrimaryLink:      strField(vm, "primaryLink"),
			}
			if score, ok := vm["score"].(float64); ok {
				v.Score = score
			}
			report.Report.Vulns = append(report.Report.Vulns, v)
		}
	}
	return report, nil
}

func intFromUnstructured(m map[string]interface{}, key string) int {
	switch v := m[key].(type) {
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

func strField(m map[string]interface{}, key string) string {
	s, _ := m[key].(string)
	return s
}
