package kube

import "sync"

// Store is a thread-safe in-memory store for VulnerabilityReports.
type Store struct {
	mu      sync.RWMutex
	reports map[string]*VulnerabilityReport
	synced  bool
}

// NewStore creates an empty Store.
func NewStore() *Store {
	return &Store{reports: make(map[string]*VulnerabilityReport)}
}

// Set adds or updates a report in the store.
func (s *Store) Set(report *VulnerabilityReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports[report.Namespace+"/"+report.Name] = report
}

// Delete removes a report from the store by namespace and name.
func (s *Store) Delete(namespace, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.reports, namespace+"/"+name)
}

// All returns a snapshot of all reports in the store as value copies.
func (s *Store) All() []VulnerabilityReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]VulnerabilityReport, 0, len(s.reports))
	for _, r := range s.reports {
		result = append(result, cloneReport(r))
	}
	return result
}

func cloneReport(r *VulnerabilityReport) VulnerabilityReport {
	clone := *r
	if r.Labels != nil {
		clone.Labels = make(map[string]string, len(r.Labels))
		for k, v := range r.Labels {
			clone.Labels[k] = v
		}
	}
	if r.Report.Vulns != nil {
		clone.Report.Vulns = append([]Vulnerability(nil), r.Report.Vulns...)
	}
	return clone
}

// Len returns the number of reports in the store.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.reports)
}

// MarkSynced marks the store as having completed initial sync.
func (s *Store) MarkSynced() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.synced = true
}

// IsSynced returns whether the store has completed initial sync.
func (s *Store) IsSynced() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.synced
}
