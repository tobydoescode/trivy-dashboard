package api

import (
	"testing"
)

func TestSafeURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://avd.aquasec.com/nvd/cve-2024-0001", "https://avd.aquasec.com/nvd/cve-2024-0001"},
		{"http://example.com/vuln", "http://example.com/vuln"},
		{"javascript:alert('xss')", "#"},
		{"data:text/html,<script>alert(1)</script>", "#"},
		{"", "#"},
		{"vbscript:msgbox", "#"},
		{"HTTPS://EXAMPLE.COM", "HTTPS://EXAMPLE.COM"},
		{"//example.com/path", "#"},
		{"ftp://files.example.com", "#"},
	}
	for _, tt := range tests {
		got := safeURL(tt.input)
		if got != tt.want {
			t.Errorf("safeURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
