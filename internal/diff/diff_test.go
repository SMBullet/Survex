package diff

import (
	"testing"

	"github.com/SMBullet/Survex/internal/models"
)

func TestComputeNilPrev(t *testing.T) {
	curr := &models.ScanResult{}
	d := Compute(nil, curr)
	if d != nil {
		t.Error("Compute(nil, curr) should return nil diff for first scan")
	}
}

func TestComputeNewSubdomains(t *testing.T) {
	prev := &models.ScanResult{
		Subdomains: []models.Subdomain{
			{Name: "old.example.com"},
			{Name: "both.example.com"},
		},
	}
	curr := &models.ScanResult{
		Subdomains: []models.Subdomain{
			{Name: "both.example.com"},
			{Name: "new.example.com"},
		},
	}

	d := Compute(prev, curr)
	if d == nil {
		t.Fatal("expected non-nil diff")
	}

	if len(d.NewSubdomains) != 1 || d.NewSubdomains[0] != "new.example.com" {
		t.Errorf("NewSubdomains = %v, want [new.example.com]", d.NewSubdomains)
	}
	if len(d.RemovedSubdomains) != 1 || d.RemovedSubdomains[0] != "old.example.com" {
		t.Errorf("RemovedSubdomains = %v, want [old.example.com]", d.RemovedSubdomains)
	}
}

func TestComputeNewPorts(t *testing.T) {
	prev := &models.ScanResult{
		Services: []models.Service{
			{Host: "a.com", Port: 80, Protocol: "tcp"},
		},
	}
	curr := &models.ScanResult{
		Services: []models.Service{
			{Host: "a.com", Port: 80, Protocol: "tcp"},
			{Host: "a.com", Port: 443, Protocol: "tcp"},
		},
	}

	d := Compute(prev, curr)
	if d == nil {
		t.Fatal("expected non-nil diff")
	}

	if len(d.NewOpenPorts) != 1 {
		t.Fatalf("NewOpenPorts = %d, want 1", len(d.NewOpenPorts))
	}
	if d.NewOpenPorts[0].Port != 443 {
		t.Errorf("new port = %d, want 443", d.NewOpenPorts[0].Port)
	}
}

func TestComputeNewHTTP(t *testing.T) {
	prev := &models.ScanResult{
		HTTP: []models.HTTPService{
			{Host: "a.com", URL: "https://a.com"},
		},
	}
	curr := &models.ScanResult{
		HTTP: []models.HTTPService{
			{Host: "a.com", URL: "https://a.com"},
			{Host: "b.com", URL: "https://b.com"},
		},
	}

	d := Compute(prev, curr)
	if d == nil {
		t.Fatal("expected non-nil diff")
	}

	if len(d.NewHTTPURLs) != 1 || d.NewHTTPURLs[0] != "https://b.com" {
		t.Errorf("NewHTTPURLs = %v, want [https://b.com]", d.NewHTTPURLs)
	}
}

func TestComputeTLSChanges(t *testing.T) {
	prev := &models.ScanResult{
		HTTP: []models.HTTPService{
			{Host: "a.com", URL: "https://a.com", TLSIssuer: "Let's Encrypt"},
		},
	}
	curr := &models.ScanResult{
		HTTP: []models.HTTPService{
			{Host: "a.com", URL: "https://a.com", TLSIssuer: "DigiCert"},
		},
	}

	d := Compute(prev, curr)
	if d == nil {
		t.Fatal("expected non-nil diff")
	}

	if len(d.TLSChanges) != 1 {
		t.Fatalf("TLSChanges = %d, want 1", len(d.TLSChanges))
	}
}

func TestComputeNoDiff(t *testing.T) {
	same := &models.ScanResult{
		Subdomains: []models.Subdomain{{Name: "a.com"}},
		Services:   []models.Service{{Host: "a.com", Port: 80, Protocol: "tcp"}},
		HTTP:       []models.HTTPService{{Host: "a.com", URL: "https://a.com"}},
	}

	d := Compute(same, same)
	if d == nil {
		t.Fatal("expected non-nil diff")
	}
	if len(d.NewSubdomains) != 0 || len(d.RemovedSubdomains) != 0 ||
		len(d.NewOpenPorts) != 0 || len(d.RemovedPorts) != 0 ||
		len(d.NewHTTPURLs) != 0 || len(d.TLSChanges) != 0 {
		t.Error("expected no changes when comparing same result")
	}
}
