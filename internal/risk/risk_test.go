package risk

import (
	"testing"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

func TestPortRules(t *testing.T) {
	result := &models.ScanResult{
		Services: []models.Service{
			{Host: "db.example.com", Port: 3306, Protocol: "tcp", ServiceName: "mysql"},
			{Host: "web.example.com", Port: 80, Protocol: "tcp", ServiceName: "http"},
			{Host: "ssh.example.com", Port: 22, Protocol: "tcp", ServiceName: "ssh"},
		},
	}

	findings := Score(result)

	// Should have findings for ports 3306 (critical), 22 (medium)
	found3306 := false
	found22 := false
	for _, f := range findings {
		if f.Port == 3306 && f.Severity == "critical" {
			found3306 = true
		}
		if f.Port == 22 && f.Severity == "medium" {
			found22 = true
		}
	}

	if !found3306 {
		t.Error("expected critical finding for port 3306 (MySQL)")
	}
	if !found22 {
		t.Error("expected medium finding for port 22 (SSH)")
	}
}

func TestTLSRules(t *testing.T) {
	result := &models.ScanResult{
		TLS: []models.TLSInfo{
			{Host: "expired.com", Expired: true, Expiry: time.Now().Add(-24 * time.Hour), Issuer: "Test CA"},
			{Host: "expiring.com", DaysLeft: 7, Expiry: time.Now().Add(7 * 24 * time.Hour), Issuer: "Test CA"},
			{Host: "selfsigned.com", SelfSigned: true},
			{Host: "oldtls.com", Version: "TLS 1.0"},
		},
	}

	findings := Score(result)

	issues := map[string]bool{}
	for _, f := range findings {
		issues[f.Asset+":"+f.Title] = true
	}

	if !issues["expired.com:TLS certificate expired"] {
		t.Error("expected expired TLS finding")
	}
	if !issues["expiring.com:TLS certificate expiring in under 14 days"] {
		t.Error("expected expiring TLS finding")
	}
	if !issues["selfsigned.com:Self-signed TLS certificate"] {
		t.Error("expected self-signed TLS finding")
	}
	if !issues["oldtls.com:Weak TLS version negotiated: TLS 1.0"] {
		t.Error("expected weak TLS version finding")
	}
}

func TestCORSSeverity(t *testing.T) {
	tests := []struct {
		issue    string
		expected string
	}{
		{"reflects_origin_with_credentials", "critical"},
		{"wildcard_with_credentials", "critical"},
		{"wildcard", "high"},
		{"reflects_origin", "medium"},
		{"null_origin", "medium"},
		{"unknown", "low"},
	}

	for _, tt := range tests {
		t.Run(tt.issue, func(t *testing.T) {
			if got := corsIssueSeverity(tt.issue); got != tt.expected {
				t.Errorf("corsIssueSeverity(%q) = %q, want %q", tt.issue, got, tt.expected)
			}
		})
	}
}

func TestMaxSeverity(t *testing.T) {
	tests := []struct {
		name     string
		findings []models.Finding
		expected string
	}{
		{"empty", nil, ""},
		{"single", []models.Finding{{Severity: "medium"}}, "medium"},
		{"mixed", []models.Finding{
			{Severity: "low"},
			{Severity: "critical"},
			{Severity: "medium"},
		}, "critical"},
		{"all info", []models.Finding{
			{Severity: "info"},
			{Severity: "info"},
		}, "info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MaxSeverity(tt.findings); got != tt.expected {
				t.Errorf("MaxSeverity() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestMeetsThreshold(t *testing.T) {
	tests := []struct {
		maxSev    string
		threshold string
		expected  bool
	}{
		{"critical", "high", true},
		{"high", "high", true},
		{"medium", "high", false},
		{"low", "critical", false},
		{"critical", "low", true},
	}

	for _, tt := range tests {
		t.Run(tt.maxSev+"_vs_"+tt.threshold, func(t *testing.T) {
			if got := MeetsThreshold(tt.maxSev, tt.threshold); got != tt.expected {
				t.Errorf("MeetsThreshold(%q, %q) = %v, want %v", tt.maxSev, tt.threshold, got, tt.expected)
			}
		})
	}
}

func TestSortFindings(t *testing.T) {
	findings := []models.Finding{
		{Severity: "low", Title: "low1"},
		{Severity: "critical", Title: "crit1"},
		{Severity: "medium", Title: "med1"},
		{Severity: "info", Title: "info1"},
		{Severity: "high", Title: "high1"},
	}

	sorted := sortFindings(findings)

	expectedOrder := []string{"critical", "high", "medium", "low", "info"}
	for i, expected := range expectedOrder {
		if sorted[i].Severity != expected {
			t.Errorf("sorted[%d].Severity = %q, want %q", i, sorted[i].Severity, expected)
		}
	}
}
