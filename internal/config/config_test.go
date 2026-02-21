package config

import (
	"testing"
)

func TestHasModule(t *testing.T) {
	tests := []struct {
		name     string
		modules  []string
		query    string
		expected bool
	}{
		{"exact match", []string{"httpx", "nmap"}, "httpx", true},
		{"no match", []string{"httpx", "nmap"}, "nuclei", false},
		{"all matches any", []string{"all"}, "nuclei", true},
		{"all matches built-in", []string{"all"}, "dns", true},
		{"case insensitive", []string{"HTTPx"}, "httpx", true},
		{"empty modules", []string{}, "httpx", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Modules: tt.modules}
			if got := cfg.HasModule(tt.query); got != tt.expected {
				t.Errorf("HasModule(%q) = %v, want %v", tt.query, got, tt.expected)
			}
		})
	}
}

func TestAllTargets(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		targets  []string
		expected int
	}{
		{"single target", "example.com", nil, 1},
		{"multiple targets", "", []string{"a.com", "b.com"}, 2},
		{"legacy + new merged", "a.com", []string{"b.com"}, 2},
		{"dedup", "a.com", []string{"a.com", "b.com"}, 2},
		{"empty", "", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Target: tt.target, Targets: tt.targets}
			got := cfg.AllTargets()
			if len(got) != tt.expected {
				t.Errorf("AllTargets() returned %d targets, want %d", len(got), tt.expected)
			}
		})
	}
}

func TestEffectiveRate(t *testing.T) {
	tests := []struct {
		name     string
		rate     int
		expected int
	}{
		{"default", 0, 150},
		{"negative", -1, 150},
		{"custom", 100, 100},
		{"high rate", 500, 500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Scan: ScanOptions{Rate: tt.rate}}
			if got := cfg.EffectiveRate(); got != tt.expected {
				t.Errorf("EffectiveRate() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestEffectivePorts(t *testing.T) {
	tests := []struct {
		name     string
		ports    string
		expected string
	}{
		{"default", "", "top-1000"},
		{"custom", "80,443", "80,443"},
		{"named", "web", "web"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Scan: ScanOptions{Ports: tt.ports}}
			if got := cfg.EffectivePorts(); got != tt.expected {
				t.Errorf("EffectivePorts() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestResolveProfile(t *testing.T) {
	tests := []struct {
		name            string
		profile         string
		existingModules []string
		expectModules   bool
	}{
		{"quick profile", "quick", nil, true},
		{"web profile", "web", nil, true},
		{"no-op if modules set", "full", []string{"httpx"}, true},
		{"unknown profile", "nonexistent", nil, false},
		{"empty profile", "", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Scan:    ScanOptions{Profile: tt.profile},
				Modules: tt.existingModules,
			}
			cfg.ResolveProfile()
			if tt.expectModules && len(cfg.Modules) == 0 && tt.profile != "nonexistent" && tt.profile != "" {
				t.Errorf("ResolveProfile(%q) did not set modules", tt.profile)
			}
			// If modules were pre-set, they should be unchanged
			if len(tt.existingModules) > 0 && len(cfg.Modules) != len(tt.existingModules) {
				t.Errorf("ResolveProfile should not override existing modules")
			}
		})
	}
}

func TestNucleiSeverity(t *testing.T) {
	cfg := &Config{}
	if got := cfg.NucleiSeverity(); got != "critical,high,medium,info" {
		t.Errorf("NucleiSeverity() default = %q, want %q", got, "critical,high,medium,info")
	}

	cfg.Nuclei.Severity = "critical,high"
	if got := cfg.NucleiSeverity(); got != "critical,high" {
		t.Errorf("NucleiSeverity() custom = %q, want %q", got, "critical,high")
	}
}

func TestShodanEnabled(t *testing.T) {
	cfg := &Config{}
	if cfg.ShodanEnabled() {
		t.Error("ShodanEnabled() should be false with no key")
	}

	cfg.Shodan.Enabled = true
	if cfg.ShodanEnabled() {
		t.Error("ShodanEnabled() should be false with enabled but no key")
	}

	cfg.Shodan.APIKey = "test-key"
	if !cfg.ShodanEnabled() {
		t.Error("ShodanEnabled() should be true with enabled + key")
	}
}
