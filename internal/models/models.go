package models

import "time"

type Scan struct {
	ID         string     `json:"id"`
	Client     string     `json:"client"`
	Target     string     `json:"target"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Status     string     `json:"status"` // running | done | failed
}

type Subdomain struct {
	Name      string   `json:"name"`
	IPAddress string   `json:"ip_address,omitempty"`
	CNAMEs    []string `json:"cnames,omitempty"`
	Sources   []string `json:"sources,omitempty"` // subfinder, crts, amass
}

type Service struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	ServiceName string `json:"service_name,omitempty"`
	Banner      string `json:"banner,omitempty"`
}

type HTTPService struct {
	Host       string   `json:"host"`
	URL        string   `json:"url"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title,omitempty"`
	TechStack  []string `json:"tech_stack,omitempty"`
	WebServer  string   `json:"web_server,omitempty"`
	TLSIssuer  string   `json:"tls_issuer,omitempty"`
	TLSExpiry  string   `json:"tls_expiry,omitempty"`
}

type DNSRecord struct {
	Host  string `json:"host"`
	Type  string `json:"type"` // A | CNAME | MX | TXT
	Value string `json:"value"`
}

// TLSInfo holds the result of a direct TLS handshake analysis.
type TLSInfo struct {
	Host       string    `json:"host"`
	Issuer     string    `json:"issuer"`
	Subject    string    `json:"subject"`
	Expiry     time.Time `json:"expiry"`
	DaysLeft   int       `json:"days_left"`
	Version    string    `json:"version"` // TLS 1.0 / 1.1 / 1.2 / 1.3
	SelfSigned bool      `json:"self_signed"`
	Expired    bool      `json:"expired"`
	SANs       []string  `json:"sans,omitempty"`
}

// WAFDetection holds WAF fingerprinting results for a host.
type WAFDetection struct {
	Host     string `json:"host"`
	Detected bool   `json:"detected"`
	Name     string `json:"name,omitempty"` // Cloudflare, Akamai, Sucuri, etc.
	Evidence string `json:"evidence,omitempty"`
}

// Vulnerability holds a finding from the nuclei scanner.
type Vulnerability struct {
	Host       string `json:"host"`
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"` // info | low | medium | high | critical
	URL        string `json:"url"`
	Detail     string `json:"detail,omitempty"`
}

type Finding struct {
	Asset     string    `json:"asset"`
	Port      int       `json:"port,omitempty"`
	Severity  string    `json:"severity"` // info | low | medium | high | critical
	Title     string    `json:"title"`
	Detail    string    `json:"detail,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	New       bool      `json:"new"`
}

type Diff struct {
	NewSubdomains     []string  `json:"new_subdomains"`
	RemovedSubdomains []string  `json:"removed_subdomains"`
	NewOpenPorts      []Service `json:"new_open_ports"`
	RemovedPorts      []Service `json:"removed_ports"`
	TLSChanges        []string  `json:"tls_changes"`
}

type ScanResult struct {
	Scan            Scan            `json:"scan"`
	Subdomains      []Subdomain     `json:"subdomains"`
	Services        []Service       `json:"services"`
	HTTP            []HTTPService   `json:"http"`
	DNS             []DNSRecord     `json:"dns"`
	TLS             []TLSInfo       `json:"tls,omitempty"`
	WAF             []WAFDetection  `json:"waf,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	Findings        []Finding       `json:"findings"`
	Diff            *Diff           `json:"diff,omitempty"`
}
