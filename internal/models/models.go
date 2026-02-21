package models

import "time"

// ── Core scan metadata ─────────────────────────────────────────────────────

type Scan struct {
	ID         string     `json:"id"`
	Client     string     `json:"client"`
	Target     string     `json:"target"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Status     string     `json:"status"` // running | done | failed
}

// ── Enumeration ────────────────────────────────────────────────────────────

type Subdomain struct {
	Name      string   `json:"name"`
	IPAddress string   `json:"ip_address,omitempty"`
	CNAMEs    []string `json:"cnames,omitempty"`
	Sources   []string `json:"sources,omitempty"` // subfinder, crts, amass, tls-san, config
}

// ── Network / Port scanning ────────────────────────────────────────────────

type Service struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	ServiceName string `json:"service_name,omitempty"`
	Banner      string `json:"banner,omitempty"`
}

// ── HTTP / Web ─────────────────────────────────────────────────────────────

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

// SecurityHeaders holds the result of an HTTP security headers audit.
type SecurityHeaders struct {
	Host    string            `json:"host"`
	URL     string            `json:"url"`
	Present map[string]string `json:"present"` // header name → value
	Missing []string          `json:"missing"`
	Score   string            `json:"score"` // A / B / C / D / F
}

// CORSResult holds the result of a CORS misconfiguration test.
type CORSResult struct {
	Host       string `json:"host"`
	URL        string `json:"url"`
	Vulnerable bool   `json:"vulnerable"`
	// Issue describes the type of misconfiguration:
	//   reflects_origin | reflects_origin_with_credentials | null_origin | wildcard_with_credentials
	Issue    string `json:"issue,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

// CookieResult holds cookie security flag analysis for a single URL.
type CookieResult struct {
	Host    string         `json:"host"`
	URL     string         `json:"url"`
	Cookies []CookieDetail `json:"cookies"`
}

// CookieDetail holds security attributes of a single Set-Cookie entry.
type CookieDetail struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"` // Strict | Lax | None | ""
}

// HistoricalURL holds a URL discovered from passive historical sources.
type HistoricalURL struct {
	URL    string `json:"url"`
	Source string `json:"source"` // gau | wayback | katana
}

// Screenshot holds metadata about a captured screenshot.
type Screenshot struct {
	Host string `json:"host"`
	URL  string `json:"url"`
	Path string `json:"path"` // relative path within scan output directory
}

// ── Cloud / Infrastructure ─────────────────────────────────────────────────

// S3Bucket holds the result of a cloud storage bucket exposure check.
type S3Bucket struct {
	Host      string `json:"host"`
	BucketURL string `json:"bucket_url"`
	Public    bool   `json:"public"`
	Listable  bool   `json:"listable"`
	Provider  string `json:"provider"` // aws | gcs | azure
}

// ShodanHost holds enrichment data from the Shodan API for a single IP.
type ShodanHost struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
	Vulns     []string `json:"vulns,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	ISP       string   `json:"isp,omitempty"`
	Country   string   `json:"country,omitempty"`
	Org       string   `json:"org,omitempty"`
}

// ── TLS / PKI ──────────────────────────────────────────────────────────────

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

// ── WAF ────────────────────────────────────────────────────────────────────

// WAFDetection holds WAF fingerprinting results for a host.
type WAFDetection struct {
	Host     string `json:"host"`
	Detected bool   `json:"detected"`
	Name     string `json:"name,omitempty"` // Cloudflare, Akamai, Sucuri, etc.
	Evidence string `json:"evidence,omitempty"`
}

// ── DNS ────────────────────────────────────────────────────────────────────

type DNSRecord struct {
	Host  string `json:"host"`
	Type  string `json:"type"` // A | CNAME | MX | TXT
	Value string `json:"value"`
}

// ── Email Security ─────────────────────────────────────────────────────────

// EmailSecurityResult holds SPF / DMARC / DKIM analysis for a root domain.
type EmailSecurityResult struct {
	Domain       string `json:"domain"`
	SPFPresent   bool   `json:"spf_present"`
	SPF          string `json:"spf,omitempty"`
	DMARCPresent bool   `json:"dmarc_present"`
	DMARC        string `json:"dmarc,omitempty"`
	DKIMPresent  bool   `json:"dkim_present"`
	DKIMSelector string `json:"dkim_selector,omitempty"`
	DKIM         string `json:"dkim,omitempty"`
}

// ── Subdomain Takeover ─────────────────────────────────────────────────────

// TakeoverResult holds the outcome of a subdomain takeover check for a single host.
type TakeoverResult struct {
	Host       string `json:"host"`
	CNAME      string `json:"cname"`             // the resolved CNAME target
	Service    string `json:"service"`           // e.g. "GitHub Pages", "AWS S3"
	Vulnerable bool   `json:"vulnerable"`        // true only when confirmed unclaimed
	Evidence   string `json:"evidence,omitempty"` // NXDOMAIN / HTTP fingerprint detail
}

// ── Vulnerabilities / Findings ────────────────────────────────────────────

// Vulnerability holds a finding from the nuclei scanner.
type Vulnerability struct {
	Host       string `json:"host"`
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"` // info | low | medium | high | critical
	URL        string `json:"url"`
	Detail     string `json:"detail,omitempty"`
}

// Finding is a risk-scored, deduplicated finding surfaced to the operator.
type Finding struct {
	Asset     string    `json:"asset"`
	Port      int       `json:"port,omitempty"`
	Severity  string    `json:"severity"` // info | low | medium | high | critical
	Title     string    `json:"title"`
	Detail    string    `json:"detail,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	New       bool      `json:"new"`
}

// ── Diff ───────────────────────────────────────────────────────────────────

type Diff struct {
	NewSubdomains     []string  `json:"new_subdomains"`
	RemovedSubdomains []string  `json:"removed_subdomains"`
	NewOpenPorts      []Service `json:"new_open_ports"`
	RemovedPorts      []Service `json:"removed_ports"`
	NewHTTPURLs       []string  `json:"new_http_urls"`
	TLSChanges        []string  `json:"tls_changes"`
}

// ── Aggregated scan result ─────────────────────────────────────────────────

type ScanResult struct {
	Scan            Scan             `json:"scan"`
	Subdomains      []Subdomain      `json:"subdomains"`
	Services        []Service        `json:"services"`
	HTTP            []HTTPService    `json:"http"`
	DNS             []DNSRecord      `json:"dns"`
	TLS             []TLSInfo        `json:"tls,omitempty"`
	WAF             []WAFDetection   `json:"waf,omitempty"`
	SecurityHeaders []SecurityHeaders `json:"security_headers,omitempty"`
	CORS            []CORSResult     `json:"cors,omitempty"`
	Cookies         []CookieResult   `json:"cookies,omitempty"`
	S3Buckets       []S3Bucket       `json:"s3_buckets,omitempty"`
	HistoricalURLs  []HistoricalURL  `json:"historical_urls,omitempty"`
	Screenshots     []Screenshot     `json:"screenshots,omitempty"`
	ShodanHosts     []ShodanHost     `json:"shodan_hosts,omitempty"`
	EmailSecurity   []EmailSecurityResult `json:"email_security,omitempty"`
	Takeovers       []TakeoverResult      `json:"takeovers,omitempty"`
	Vulnerabilities []Vulnerability  `json:"vulnerabilities,omitempty"`
	Findings        []Finding        `json:"findings"`
	Diff            *Diff            `json:"diff,omitempty"`
}
