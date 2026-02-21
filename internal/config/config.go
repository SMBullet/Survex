package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for a Survex scan.
// Either a config file or inline CLI flags produce one of these.
type Config struct {
	Client  string   `yaml:"client"`  // name used for storage and report grouping
	Target  string   `yaml:"target"`  // legacy single-target field (merged into AllTargets)
	Targets []string `yaml:"targets"` // domains, IPs, CIDRs, or paths to .txt files

	// Modules lists which scan modules to run.
	// Use ["all"] to run everything, or name specific modules:
	//   subfinder  amass  crts  dns  nmap  httpx  tls  waf
	//   headers  cors  cookies  s3  gau  katana  screenshot  nuclei  shodan
	Modules []string `yaml:"modules"`

	Scan   ScanOptions   `yaml:"scan"`
	Nuclei NucleiOptions `yaml:"nuclei"`
	Shodan ShodanOptions `yaml:"shodan"`
	Output OutputOptions `yaml:"output"`
	Alerts AlertOptions  `yaml:"alerts"`
}

// ScanOptions controls scan behavior and performance tuning.
type ScanOptions struct {
	// NoSubs skips all subdomain enumeration steps (subfinder, crts, amass,
	// tls-san). The provided targets are treated as the final host list.
	// Useful when you already have a specific host list or want to scan a
	// single subdomain without discovery.
	NoSubs bool `yaml:"no_subs"`

	// Passive limits the scan to passive recon only (crts, dns, shodan).
	// No active port scanning, HTTP probing, or vulnerability scanning.
	Passive bool `yaml:"passive"`

	// Ports controls which ports nmap scans.
	// Options: top-100 | top-1000 | full | web | db | stealth | "80,443,8080"
	// Default: top-1000
	Ports string `yaml:"ports"`

	// Profile selects a predefined module set if --modules is not specified.
	// Options: quick | web | full | passive | stealth | cloud
	Profile string `yaml:"profile"`

	// Rate is the maximum requests per second across all HTTP operations.
	// Default: 150
	Rate int `yaml:"rate"`

	// Threads is the concurrency level for HTTP probing (httpx --threads).
	// Default: 50
	Threads int `yaml:"threads"`

	// Timeout is the per-request timeout in seconds.
	// Default: 10
	Timeout int `yaml:"timeout"`

	// Proxy routes all HTTP requests through the specified proxy.
	// Format: http://127.0.0.1:8080 or socks5://127.0.0.1:1080
	Proxy string `yaml:"proxy"`
}

// NucleiOptions controls nuclei vulnerability scanner behavior.
type NucleiOptions struct {
	// Severity filters which nuclei findings to include.
	// Default: "critical,high,medium,info"
	Severity string `yaml:"severity"`

	// Tags restricts scanning to templates with these tags.
	// Example: ["cve", "rce", "sqli"]
	Tags []string `yaml:"tags"`

	// ExcludeTags skips templates with these tags.
	// Default: ["dos", "fuzz", "generic-tokens", "tls-sni-proxy"]
	ExcludeTags []string `yaml:"exclude_tags"`

	// Templates adds extra template directories beyond the built-in ASM set.
	// Example: ["/path/to/custom-templates/"]
	Templates []string `yaml:"templates"`

	// ExcludeTemplates skips specific template IDs or paths.
	ExcludeTemplates []string `yaml:"exclude_templates"`

	// UpdateBefore runs nuclei -update-templates before the scan.
	UpdateBefore bool `yaml:"update_before_scan"`
}

// ShodanOptions enables Shodan passive host enrichment.
type ShodanOptions struct {
	// APIKey is your Shodan API key. Get one at https://account.shodan.io/
	APIKey string `yaml:"api_key"`

	// Enabled must be true AND APIKey must be set for Shodan lookups to run.
	Enabled bool `yaml:"enabled"`
}

// OutputOptions controls where and how scan results are written.
type OutputOptions struct {
	Dir         string `yaml:"dir"`
	Format      string `yaml:"format"` // json (only supported format currently)
	KeepHistory bool   `yaml:"keep_history"`
}

// AlertOptions controls CI/CD exit code behavior.
type AlertOptions struct {
	FailOn string `yaml:"fail_on"` // low | medium | high | critical
}

// profileModules maps scan profile names to their module lists.
var profileModules = map[string][]string{
	// quick: Fast passive+HTTP scan, no port scanning or vuln scanning.
	"quick": {"crts", "dns", "httpx", "tls", "headers"},

	// web: Full web-focused scan with enumeration and vuln scanning.
	"web": {"subfinder", "crts", "amass", "dns", "httpx", "tls", "waf", "headers", "cors", "cookies", "nuclei"},

	// full: Every module. Slowest but most thorough.
	"full": {"all"},

	// passive: Zero active probing. Only passive data sources.
	"passive": {"crts", "dns", "shodan"},

	// stealth: Minimal footprint. Slow timing, no vuln scanning.
	"stealth": {"crts", "dns", "httpx", "tls", "waf"},

	// cloud: Cloud asset discovery and misconfiguration focus.
	"cloud": {"subfinder", "crts", "dns", "httpx", "s3", "nuclei"},
}

// HasModule returns true if the named module is enabled.
// "all" enables every module.
func (c *Config) HasModule(name string) bool {
	for _, m := range c.Modules {
		if m == "all" || strings.EqualFold(m, name) {
			return true
		}
	}
	return false
}

// AllTargets returns the deduplicated, merged list of targets from both
// the legacy Target field and the Targets list.
func (c *Config) AllTargets() []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" {
			return
		}
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	if c.Target != "" {
		add(c.Target)
	}
	for _, t := range c.Targets {
		add(t)
	}
	return out
}

// ResolveProfile sets Modules from the named profile if Modules is empty.
// This is called by scan.Run before execution begins.
func (c *Config) ResolveProfile() {
	if c.Scan.Profile == "" || len(c.Modules) > 0 {
		return
	}
	if mods, ok := profileModules[strings.ToLower(c.Scan.Profile)]; ok {
		c.Modules = mods
	}
}

// EffectiveRate returns the configured rate or the default (150).
func (c *Config) EffectiveRate() int {
	if c.Scan.Rate <= 0 {
		return 150
	}
	return c.Scan.Rate
}

// EffectiveThreads returns the configured thread count or the default (50).
func (c *Config) EffectiveThreads() int {
	if c.Scan.Threads <= 0 {
		return 50
	}
	return c.Scan.Threads
}

// EffectiveTimeout returns the configured timeout or the default (10).
func (c *Config) EffectiveTimeout() int {
	if c.Scan.Timeout <= 0 {
		return 10
	}
	return c.Scan.Timeout
}

// EffectivePorts returns the configured port spec or the default (top-1000).
func (c *Config) EffectivePorts() string {
	if c.Scan.Ports == "" {
		return "top-1000"
	}
	return c.Scan.Ports
}

// NucleiSeverity returns the configured severity or the default.
func (c *Config) NucleiSeverity() string {
	if c.Nuclei.Severity == "" {
		return "critical,high,medium,info"
	}
	return c.Nuclei.Severity
}

// NucleiExcludeTags returns the exclude tags list (with defaults if empty).
func (c *Config) NucleiExcludeTags() []string {
	if len(c.Nuclei.ExcludeTags) == 0 {
		return []string{"dos", "fuzz", "generic-tokens", "tls-sni-proxy"}
	}
	return c.Nuclei.ExcludeTags
}

// ShodanEnabled returns true if Shodan is enabled and an API key is set.
func (c *Config) ShodanEnabled() bool {
	return c.Shodan.Enabled && c.Shodan.APIKey != ""
}

// Load reads and validates a YAML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	return validate(&cfg)
}

// validate checks required fields and sets defaults.
func validate(cfg *Config) (*Config, error) {
	if cfg.Client == "" {
		return nil, fmt.Errorf("config must specify a client name")
	}
	if len(cfg.AllTargets()) == 0 {
		return nil, fmt.Errorf("config must specify at least one target")
	}
	// Modules can be empty if a profile is set — ResolveProfile() will fill it in.
	if len(cfg.Modules) == 0 && cfg.Scan.Profile == "" {
		return nil, fmt.Errorf("config must specify modules (use [\"all\"] to run everything) or a scan.profile")
	}
	if cfg.Output.Format == "" {
		cfg.Output.Format = "json"
	}
	return cfg, nil
}
