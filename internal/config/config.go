package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type ScanOptions struct {
	Targets    []string `yaml:"targets"`    // explicit host list — skips enumeration when set
	Subdomains bool     `yaml:"subdomains"`
	DNS        bool     `yaml:"dns"`
	Ports      bool     `yaml:"ports"`
	HTTP       bool     `yaml:"http"`
	Nuclei     bool     `yaml:"nuclei"`
	Screenshot bool     `yaml:"screenshot"`
}

type OutputOptions struct {
	Dir         string `yaml:"dir"`
	Format      string `yaml:"format"` // json | markdown | html
	KeepHistory bool   `yaml:"keep_history"`
}

type AlertOptions struct {
	FailOn string `yaml:"fail_on"` // low | medium | high | critical
}

type Config struct {
	Client string        `yaml:"client"`
	Target string        `yaml:"target"`
	Scan   ScanOptions   `yaml:"scan"`
	Output OutputOptions `yaml:"output"`
	Alerts AlertOptions  `yaml:"alerts"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if cfg.Target == "" {
		return nil, fmt.Errorf("config must specify a target domain")
	}
	if cfg.Client == "" {
		return nil, fmt.Errorf("config must specify a client name")
	}
	if cfg.Output.Format == "" {
		cfg.Output.Format = "json"
	}

	return &cfg, nil
}
