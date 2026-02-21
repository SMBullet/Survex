package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"

	"github.com/SMBullet/Survex/internal/config"
	"github.com/SMBullet/Survex/internal/risk"
	"github.com/SMBullet/Survex/internal/scan"
	"github.com/SMBullet/Survex/internal/store"
	"github.com/SMBullet/Survex/internal/tools"
	"github.com/spf13/cobra"
)

const dbPath = "survex.db"

var rootCmd = &cobra.Command{
	Use:   "survex",
	Short: "Attack surface management CLI",
	Long: `Survex — Modular Attack Surface Management

Enumerate, monitor, and score your external attack surface.
Run 'survex modules' to list all available modules.
Run 'survex scan --help' for scan options.`,
}

// ── Subcommands ────────────────────────────────────────────────────────────────

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a scan against one or more targets",
	Long: `Run a full or partial ASM scan against targets.

Examples:
  # Config file
  survex scan --config clients/example.yaml

  # Inline: specific modules
  survex scan -t example.com -m "subfinder,crts,httpx,tls,headers,cors" --client test

  # Inline: all modules, quick profile
  survex scan -t example.com -m all --profile quick --client test

  # Single subdomain (no enumeration)
  survex scan -t app.example.com -m "httpx,headers,cors,cookies,nuclei" --no-subs --client test

  # Passive only (no active probing)
  survex scan -t example.com -m all --passive --client test

  # Custom port scan
  survex scan -t example.com -m "nmap,httpx" --ports "80,443,8080,8443" --client test

  # Full scan with nuclei CVE coverage
  survex scan -t example.com -m all --nuclei-severity "critical,high,medium" --client test`,
	RunE: runScan,
}

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show changes between the last two scans",
	RunE:  runDiff,
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Show findings from the last scan",
	RunE:  runReport,
}

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "List past scans for a client",
	RunE:  runHistory,
}

var modulesCmd = &cobra.Command{
	Use:   "modules",
	Short: "List all available modules and their installation status",
	RunE:  runModules,
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update external tool templates (nuclei, etc.)",
	RunE:  runUpdate,
}

// ── Flag variables ─────────────────────────────────────────────────────────────

var (
	configFile string
	outputDir  string

	// inline scan flags (no config file needed)
	flagTarget  string
	flagModules string
	flagClient  string

	// scan behavior
	flagNoSubs  bool
	flagPassive bool
	flagProfile string
	flagPorts   string
	flagRate    int
	flagThreads int
	flagTimeout int
	flagProxy   string

	// nuclei control
	flagNucleiSeverity  string
	flagNucleiTags      string
	flagNucleiExclude   string
	flagNucleiTemplates string
	flagUpdateTemplates bool

	// shodan
	flagShodanKey string

	// output / alerts
	flagFailOn string

	// update subcommand
	flagUpdateAll bool
)

func init() {
	// ── scan flags ─────────────────────────────────────────────────────────────
	scanCmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to client config YAML")
	scanCmd.Flags().StringVarP(&flagTarget, "target", "t", "", "Comma-separated targets (domains, IPs, CIDRs, file paths)")
	scanCmd.Flags().StringVarP(&flagModules, "modules", "m", "", `Comma-separated modules, or "all". See 'survex modules'`)
	scanCmd.Flags().StringVar(&flagClient, "client", "", "Client name for storage and reports (required with --target)")
	scanCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory (overrides config)")
	scanCmd.Flags().StringVar(&flagFailOn, "fail-on", "", "Exit 1 if findings at or above this severity: low|medium|high|critical")

	// scan behavior
	scanCmd.Flags().BoolVar(&flagNoSubs, "no-subs", false, "Skip subdomain enumeration — treat targets as final host list")
	scanCmd.Flags().BoolVar(&flagPassive, "passive", false, "Passive recon only (crts, dns, shodan — no active probing)")
	scanCmd.Flags().StringVar(&flagProfile, "profile", "", "Scan profile: quick|web|full|passive|stealth|cloud")
	scanCmd.Flags().StringVar(&flagPorts, "ports", "", "Port profile: top-100|top-1000|full|web|db|stealth|\"80,443,8080\"")
	scanCmd.Flags().IntVar(&flagRate, "rate", 0, "Requests per second (default 150)")
	scanCmd.Flags().IntVar(&flagThreads, "threads", 0, "Concurrency level (default 50)")
	scanCmd.Flags().IntVar(&flagTimeout, "timeout", 0, "Per-request timeout in seconds (default 10)")
	scanCmd.Flags().StringVar(&flagProxy, "proxy", "", "HTTP proxy URL (e.g. http://127.0.0.1:8080)")

	// nuclei
	scanCmd.Flags().StringVar(&flagNucleiSeverity, "nuclei-severity", "", "Nuclei severity filter (default: critical,high,medium,info)")
	scanCmd.Flags().StringVar(&flagNucleiTags, "nuclei-tags", "", "Comma-separated nuclei tags to include (e.g. cve,rce)")
	scanCmd.Flags().StringVar(&flagNucleiExclude, "nuclei-exclude", "", "Comma-separated nuclei tags to exclude")
	scanCmd.Flags().StringVar(&flagNucleiTemplates, "nuclei-templates", "", "Additional nuclei template directories (comma-separated)")
	scanCmd.Flags().BoolVar(&flagUpdateTemplates, "update-templates", false, "Update nuclei templates before scan")

	// shodan
	scanCmd.Flags().StringVar(&flagShodanKey, "shodan-key", "", "Shodan API key (enables shodan module)")

	// ── diff / report flags ───────────────────────────────────────────────────
	diffCmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to client config YAML")
	diffCmd.Flags().StringVar(&flagClient, "client", "", "Client name")

	reportCmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to client config YAML")
	reportCmd.Flags().StringVar(&flagClient, "client", "", "Client name")

	// ── history flags ─────────────────────────────────────────────────────────
	historyCmd.Flags().StringVar(&flagClient, "client", "", "Client name")
	historyCmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to client config YAML")

	// ── update flags ─────────────────────────────────────────────────────────
	updateCmd.Flags().BoolVar(&flagUpdateAll, "all", false, "Update all supported tools (currently nuclei templates)")
	updateCmd.Flags().Bool("nuclei", false, "Update nuclei templates")

	rootCmd.AddCommand(scanCmd, diffCmd, reportCmd, historyCmd, modulesCmd, updateCmd)
}

// ── Config resolution ─────────────────────────────────────────────────────────

// buildConfig creates a Config from inline CLI flags (no config file).
func buildConfig() (*config.Config, error) {
	if flagClient == "" {
		return nil, fmt.Errorf("--client is required when using --target")
	}
	if flagTarget == "" {
		return nil, fmt.Errorf("--target is required when not using --config")
	}

	var targets []string
	for _, t := range strings.Split(flagTarget, ",") {
		if t = strings.TrimSpace(t); t != "" {
			targets = append(targets, t)
		}
	}

	var modules []string
	if flagModules != "" {
		for _, m := range strings.Split(flagModules, ",") {
			if m = strings.TrimSpace(m); m != "" {
				modules = append(modules, m)
			}
		}
	}

	cfg := &config.Config{
		Client:  flagClient,
		Targets: targets,
		Modules: modules,
		Output: config.OutputOptions{
			Format:      "json",
			KeepHistory: true,
		},
	}
	if outputDir != "" {
		cfg.Output.Dir = outputDir
	}
	applyFlagsToConfig(cfg)
	return cfg, nil
}

// applyFlagsToConfig overlays CLI flags onto a config (whether from file or inline).
func applyFlagsToConfig(cfg *config.Config) {
	if outputDir != "" {
		cfg.Output.Dir = outputDir
	}
	if flagFailOn != "" {
		cfg.Alerts.FailOn = flagFailOn
	}
	if flagNoSubs {
		cfg.Scan.NoSubs = true
	}
	if flagPassive {
		cfg.Scan.Passive = true
	}
	if flagProfile != "" {
		cfg.Scan.Profile = flagProfile
	}
	if flagPorts != "" {
		cfg.Scan.Ports = flagPorts
	}
	if flagRate > 0 {
		cfg.Scan.Rate = flagRate
	}
	if flagThreads > 0 {
		cfg.Scan.Threads = flagThreads
	}
	if flagTimeout > 0 {
		cfg.Scan.Timeout = flagTimeout
	}
	if flagProxy != "" {
		cfg.Scan.Proxy = flagProxy
	}
	if flagNucleiSeverity != "" {
		cfg.Nuclei.Severity = flagNucleiSeverity
	}
	if flagNucleiTags != "" {
		for _, t := range strings.Split(flagNucleiTags, ",") {
			if t = strings.TrimSpace(t); t != "" {
				cfg.Nuclei.Tags = append(cfg.Nuclei.Tags, t)
			}
		}
	}
	if flagNucleiExclude != "" {
		for _, t := range strings.Split(flagNucleiExclude, ",") {
			if t = strings.TrimSpace(t); t != "" {
				cfg.Nuclei.ExcludeTags = append(cfg.Nuclei.ExcludeTags, t)
			}
		}
	}
	if flagNucleiTemplates != "" {
		for _, t := range strings.Split(flagNucleiTemplates, ",") {
			if t = strings.TrimSpace(t); t != "" {
				cfg.Nuclei.Templates = append(cfg.Nuclei.Templates, t)
			}
		}
	}
	if flagUpdateTemplates {
		cfg.Nuclei.UpdateBefore = true
	}
	if flagShodanKey != "" {
		cfg.Shodan.APIKey = flagShodanKey
		cfg.Shodan.Enabled = true
	}
}

func resolveConfig() (*config.Config, error) {
	if configFile != "" {
		cfg, err := config.Load(configFile)
		if err != nil {
			return nil, err
		}
		applyFlagsToConfig(cfg)
		return cfg, nil
	}
	return buildConfig()
}

func resolveClient() (string, error) {
	if flagClient != "" {
		return flagClient, nil
	}
	if configFile != "" {
		cfg, err := config.Load(configFile)
		if err != nil {
			return "", err
		}
		return cfg.Client, nil
	}
	return "", fmt.Errorf("provide either --config or --client")
}

func initStore() error {
	return store.Init(dbPath)
}

// ── Command implementations ───────────────────────────────────────────────────

func runScan(cmd *cobra.Command, args []string) error {
	if configFile == "" && flagTarget == "" {
		return fmt.Errorf("provide either --config <file> or --target <target> --modules <modules> --client <name>")
	}
	if configFile == "" && flagModules == "" && flagProfile == "" {
		return fmt.Errorf("provide --modules <modules> or --profile <profile> when using --target")
	}

	if err := initStore(); err != nil {
		return fmt.Errorf("initializing store: %w", err)
	}

	cfg, err := resolveConfig()
	if err != nil {
		return err
	}

	result, err := scan.Run(cfg)
	if err != nil {
		return err
	}

	maxSev := risk.MaxSeverity(result.Findings)
	fmt.Printf("\nScan complete: %s\n", result.Scan.ID)
	fmt.Printf("  Subdomains   : %d\n", len(result.Subdomains))
	fmt.Printf("  Services     : %d\n", len(result.Services))
	fmt.Printf("  HTTP         : %d\n", len(result.HTTP))
	fmt.Printf("  CORS vulns   : %d\n", func() int {
		n := 0
		for _, c := range result.CORS {
			if c.Vulnerable {
				n++
			}
		}
		return n
	}())
	fmt.Printf("  S3 buckets   : %d\n", len(result.S3Buckets))
	fmt.Printf("  Nuclei vulns : %d\n", len(result.Vulnerabilities))
	fmt.Printf("  Findings     : %d (max severity: %s)\n", len(result.Findings), maxSev)

	if result.Diff != nil {
		fmt.Printf("  New subs     : %d\n", len(result.Diff.NewSubdomains))
		fmt.Printf("  New ports    : %d\n", len(result.Diff.NewOpenPorts))
	}

	effectiveFailOn := flagFailOn
	if effectiveFailOn == "" {
		effectiveFailOn = cfg.Alerts.FailOn
	}
	if effectiveFailOn != "" && maxSev != "" && risk.MeetsThreshold(maxSev, effectiveFailOn) {
		fmt.Fprintf(os.Stderr, "\nfindings at or above '%s' severity detected — exiting 1\n", effectiveFailOn)
		os.Exit(1)
	}

	return nil
}

func runDiff(cmd *cobra.Command, args []string) error {
	if err := initStore(); err != nil {
		return fmt.Errorf("initializing store: %w", err)
	}

	client, err := resolveClient()
	if err != nil {
		return err
	}

	last, err := store.LoadLast(client)
	if err != nil || last == nil {
		return fmt.Errorf("no previous scan found for client '%s'", client)
	}

	if last.Diff == nil {
		fmt.Println("no diff available (this was the first scan)")
		return nil
	}

	b, _ := json.MarshalIndent(last.Diff, "", "  ")
	fmt.Println(string(b))
	return nil
}

func runReport(cmd *cobra.Command, args []string) error {
	if err := initStore(); err != nil {
		return fmt.Errorf("initializing store: %w", err)
	}

	client, err := resolveClient()
	if err != nil {
		return err
	}

	last, err := store.LoadLast(client)
	if err != nil || last == nil {
		return fmt.Errorf("no scan found for client '%s'", client)
	}

	b, _ := json.MarshalIndent(last.Findings, "", "  ")
	fmt.Println(string(b))
	return nil
}

func runHistory(cmd *cobra.Command, args []string) error {
	if err := initStore(); err != nil {
		return fmt.Errorf("initializing store: %w", err)
	}

	client, err := resolveClient()
	if err != nil {
		return err
	}

	scans, err := store.ListScans(client, 20)
	if err != nil {
		return fmt.Errorf("loading history: %w", err)
	}

	if len(scans) == 0 {
		fmt.Printf("No scans found for client '%s'\n", client)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "SCAN ID\tTARGET\tSTARTED\tSTATUS")
	for _, s := range scans {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			s.ID, s.Target, s.StartedAt.Format("2006-01-02 15:04"), s.Status)
	}
	w.Flush()
	return nil
}

func runModules(cmd *cobra.Command, args []string) error {
	type moduleInfo struct {
		name        string
		kind        string // built-in | external | api
		description string
		binary      string // executable name to check, or ""
		installCmd  string
	}

	modules := []moduleInfo{
		{"subfinder", "external", "Subdomain enumeration via OSINT sources", "subfinder", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
		{"amass", "external", "Subdomain enumeration via OSINT (more sources)", "amass", "go install github.com/owasp-amass/amass/v4/...@master"},
		{"crts", "built-in", "Certificate transparency (crt.sh lookup)", "", ""},
		{"dns", "built-in", "DNS resolution (A, CNAME, MX, TXT records)", "", ""},
		{"nmap", "external", "Port scanning and service detection", "nmap", "apt install nmap  /  choco install nmap"},
		{"httpx", "external", "HTTP/S probing, title, tech stack detection", "httpx", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"},
		{"tls", "built-in", "TLS certificate analysis (expiry, version, SANs)", "", ""},
		{"waf", "built-in", "WAF fingerprinting (Cloudflare, Akamai, AWS, etc.)", "", ""},
		{"headers", "built-in", "HTTP security headers audit (HSTS, CSP, X-Frame, etc.)", "", ""},
		{"cors", "built-in", "CORS misconfiguration testing (origin reflection, wildcard)", "", ""},
		{"cookies", "built-in", "Cookie security (Secure, HttpOnly, SameSite flags)", "", ""},
		{"s3", "built-in", "Cloud storage bucket exposure (AWS, GCS, Azure)", "", ""},
		{"gau", "external", "Historical URL discovery from Wayback Machine", "gau", "go install github.com/lc/gau/v2/cmd/gau@latest"},
		{"katana", "external", "JS-aware web crawler for endpoint discovery", "katana", "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
		{"screenshot", "external", "Visual recon — screenshots via gowitness", "gowitness", "go install github.com/sensepost/gowitness@latest"},
		{"nuclei", "external", "Vulnerability scanning (CVEs, misconfigs, exposures)", "nuclei", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
		{"shodan", "api", "Passive host enrichment via Shodan API (needs API key)", "", "Set SHODAN_API_KEY or use --shodan-key"},
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "MODULE\tTYPE\tSTATUS\tDESCRIPTION")
	for _, m := range modules {
		status := "ready"
		if m.kind == "external" && m.binary != "" {
			if _, err := exec.LookPath(m.binary); err != nil {
				status = "not installed"
			}
		} else if m.kind == "api" {
			status = "needs API key"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", m.name, m.kind, status, m.description)
	}
	w.Flush()

	fmt.Println("\nInstall commands for missing external tools:")
	for _, m := range modules {
		if m.kind == "external" && m.binary != "" && m.installCmd != "" {
			if _, err := exec.LookPath(m.binary); err != nil {
				fmt.Printf("  %-12s %s\n", m.name+":", m.installCmd)
			}
		}
	}

	return nil
}

func runUpdate(cmd *cobra.Command, args []string) error {
	updateAll, _ := cmd.Flags().GetBool("all")
	updateNuclei, _ := cmd.Flags().GetBool("nuclei")

	if !updateAll && !updateNuclei {
		fmt.Println("Specify what to update: --nuclei or --all")
		return nil
	}

	if updateAll || updateNuclei {
		fmt.Print("Updating nuclei templates... ")
		if err := tools.UpdateTemplates(); err != nil {
			fmt.Printf("ERROR: %v\n", err)
		} else {
			fmt.Println("done.")
		}
	}

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
