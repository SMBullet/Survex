package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/SMBullet/Survex/internal/api"
	"github.com/SMBullet/Survex/internal/config"
	"github.com/SMBullet/Survex/internal/db"
	"github.com/SMBullet/Survex/internal/queue"
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

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Continuously monitor targets and alert on changes",
	Long: `Continuously run scans on a schedule and notify on new findings.

Watch mode runs the full scan pipeline repeatedly at the configured interval.
After each scan, Survex compares results to the previous scan and fires any
configured webhooks if new subdomains or findings appear.

The command blocks until interrupted (Ctrl+C).

Examples:
  survex watch --config clients/example.yaml --interval 24h
  survex watch -t example.com -m all --client example --interval 6h`,
	RunE: runWatch,
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Survex web UI (API + dashboard)",
	Long: `Start the full Survex web platform: REST API, WebSocket log streaming,
and a Next.js dashboard for managing scans from the browser.

The server handles user authentication (JWT), queues scans, streams live
log output over WebSockets, and serves the built frontend as static files.

Examples:
  survex serve                             # listen on 0.0.0.0:8080
  survex serve --addr 127.0.0.1:9000      # custom address
  survex serve --db /var/lib/survex.db    # custom database path
  survex serve --frontend web/out         # serve built frontend

To use the web UI, build the frontend first:
  cd web && npm install && npm run build  # produces web/out/
  survex serve --frontend web/out`,
	RunE: runServe,
}

var installCmd = &cobra.Command{
	Use:   "install [tool...]",
	Short: "Install and verify all external tools required by Survex",
	Long: `Install and verify all external tools required by Survex.

Go tools (subfinder, httpx, nuclei, katana, etc.) are installed automatically
via 'go install'. System tools (nmap) must be installed via your package manager.
Conflicts — such as Kali Linux's Python httpx shadowing the Go version — are
detected and resolved automatically.

Examples:
  survex install                    # Install all missing Go tools + fix PATH
  survex install nuclei httpx       # Install specific tools only
  survex install --check            # Only check status, do not install anything
  survex install --fix-path         # Only add ~/go/bin to shell config files`,
	RunE: runInstall,
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

	// install subcommand
	flagInstallCheck   bool
	flagInstallFixPath bool

	// serve subcommand
	flagServeAddr     string
	flagServeDB       string
	flagServeFrontend string

	// watch subcommand
	flagWatchInterval string

	// new scan flags
	flagWebhook     string // comma-separated webhook URLs
	flagGitHubToken string
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

	// notifications
	scanCmd.Flags().StringVar(&flagWebhook, "webhook", "", "Webhook URL(s) for notifications (comma-separated). Slack/Discord/generic supported.")

	// github
	scanCmd.Flags().StringVar(&flagGitHubToken, "github-token", "", "GitHub personal access token (improves rate limits for github module)")

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

	// ── install flags ─────────────────────────────────────────────────────
	installCmd.Flags().BoolVar(&flagInstallCheck, "check", false, "Only verify status — do not install anything")
	installCmd.Flags().BoolVar(&flagInstallFixPath, "fix-path", false, "Add ~/go/bin to shell config files without installing tools")

	// ── serve flags ───────────────────────────────────────────────────────
	serveCmd.Flags().StringVar(&flagServeAddr, "addr", "0.0.0.0:8080", "Listen address (host:port)")
	serveCmd.Flags().StringVar(&flagServeDB, "db", "survex-web.db", "Path to the SQLite database file")
	serveCmd.Flags().StringVar(&flagServeFrontend, "frontend", "", "Path to built Next.js output dir (web/out). Leave empty for API-only mode.")

	// ── watch flags ───────────────────────────────────────────────────────
	watchCmd.Flags().StringVar(&flagWatchInterval, "interval", "24h", "How often to re-scan (e.g. 1h, 6h, 24h, 7d)")
	watchCmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to client config YAML")
	watchCmd.Flags().StringVarP(&flagTarget, "target", "t", "", "Comma-separated targets")
	watchCmd.Flags().StringVarP(&flagModules, "modules", "m", "", `Comma-separated modules, or "all"`)
	watchCmd.Flags().StringVar(&flagClient, "client", "", "Client name")
	watchCmd.Flags().StringVar(&flagProfile, "profile", "", "Scan profile")

	rootCmd.AddCommand(scanCmd, diffCmd, reportCmd, historyCmd, modulesCmd, updateCmd, installCmd, serveCmd, watchCmd)
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
	if flagGitHubToken != "" {
		cfg.GitHub.Token = flagGitHubToken
		cfg.GitHub.Enabled = true
	}
	if flagWebhook != "" {
		for _, u := range strings.Split(flagWebhook, ",") {
			u = strings.TrimSpace(u)
			if u != "" {
				cfg.Alerts.Webhooks = append(cfg.Alerts.Webhooks, config.WebhookConfig{
					URL: u,
					On:  "new_findings",
				})
			}
		}
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

	// Create a context that cancels on SIGINT / SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	result, err := scan.Run(ctx, cfg)
	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "\n[survex] scan cancelled by user\n")
			os.Exit(130)
		}
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
	kindName := map[tools.ToolKind]string{
		tools.KindGoTool:  "go-tool",
		tools.KindSystem:  "system",
		tools.KindBuiltIn: "built-in",
		tools.KindAPI:     "api",
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "MODULE\tTYPE\tSTATUS\tDESCRIPTION")

	var issues []tools.ToolStatus
	for _, def := range tools.AllTools {
		st := tools.CheckStatus(def)

		statusStr := func() string {
			switch st.State {
			case "ok":
				// Show version if available, otherwise just "installed"
				if st.Version != "" {
					return "installed (" + st.Version + ")"
				}
				return "installed"
			case "conflict":
				return "CONFLICT"
			case "missing":
				return "not installed"
			case "needs-key":
				return "needs API key"
			case "built-in":
				return "ready"
			}
			return st.State
		}()

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", def.Name, kindName[def.Kind], statusStr, def.Description)

		if st.State == "missing" || st.State == "conflict" {
			issues = append(issues, st)
		}
	}
	w.Flush()

	if len(issues) == 0 {
		fmt.Println("\nAll tools installed. Run 'survex install --check' to re-verify.")
		return nil
	}

	fmt.Println()
	hasConflicts := false
	for _, st := range issues {
		if st.State == "conflict" {
			hasConflicts = true
			fmt.Printf("  [CONFLICT] %s\n", st.Conflict)
			if st.Def.Kind == tools.KindGoTool {
				fmt.Printf("             Fix: go install %s\n", st.Def.GoInstall)
				fmt.Printf("             Then ensure ~/go/bin appears before /usr/bin in PATH.\n")
			}
		} else {
			fmt.Printf("  %-12s %s\n", st.Def.Name+":", st.InstallHint)
		}
	}

	fmt.Println()
	if hasConflicts {
		fmt.Println("Run 'survex install' to auto-install PD versions and fix PATH conflicts.")
	} else {
		fmt.Println("Run 'survex install' to auto-install all missing Go tools.")
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

func runInstall(cmd *cobra.Command, args []string) error {
	// args = optional list of specific tool names to target
	filter := args

	// ── PATH fix ───────────────────────────────────────────────────────────────
	// Always run EnsureGoPath so installed tools are findable within this session.
	if !flagInstallCheck {
		modified, err := tools.EnsureGoPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not update shell PATH: %v\n", err)
		} else if len(modified) > 0 {
			fmt.Println("[+] Added ~/go/bin to PATH in:")
			for _, f := range modified {
				fmt.Printf("    %s\n", f)
			}
			fmt.Println("    Run 'source ~/.bashrc' (or open a new terminal) to apply.")
		} else {
			fmt.Println("[✓] ~/go/bin already present in your shell PATH config.")
		}
		fmt.Println()
	}

	if flagInstallFixPath {
		return nil
	}

	// ── Install / verify ───────────────────────────────────────────────────────
	doInstall := !flagInstallCheck
	results := tools.RunInstall(filter, doInstall, func(msg string) {
		fmt.Println(msg)
	})

	// Print results table.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "TOOL\tSTATUS\tDETAIL")

	actionIcon := map[string]string{
		"ok":        "[✓]",
		"installed": "[+]",
		"built-in":  "[✓]",
		"needs-key": "[-]",
		"missing":   "[!]",
		"conflict":  "[✗]",
		"failed":    "[✗]",
	}

	var missing, failed, conflicts int
	for _, r := range results {
		icon := actionIcon[r.Action]
		if icon == "" {
			icon = "[ ]"
		}
		fmt.Fprintf(w, "%s %-12s\t%s\t%s\n", icon, r.Tool, r.Action, r.Message)
		switch r.Action {
		case "missing":
			missing++
		case "failed":
			failed++
		case "conflict":
			conflicts++
		}
	}
	w.Flush()

	// ── Summary ────────────────────────────────────────────────────────────────
	fmt.Println()
	if failed > 0 {
		fmt.Printf("[✗] %d tool(s) failed to install — check the output above.\n", failed)
	}
	if conflicts > 0 {
		fmt.Printf("[✗] %d naming conflict(s) — ensure ~/go/bin is before /usr/bin in PATH.\n", conflicts)
		fmt.Println("    Run: survex install --fix-path")
	}
	if missing > 0 && !doInstall {
		fmt.Printf("[!] %d tool(s) not yet installed.\n", missing)
		fmt.Println("    Run 'survex install' (without --check) to install them automatically.")
	}
	if missing == 0 && failed == 0 && conflicts == 0 {
		if doInstall {
			fmt.Println("[✓] All tools ready.")
		} else {
			fmt.Println("[✓] All tools verified.")
		}
	}

	// Remind about system tools on Linux.
	hasSystemMissing := false
	for _, r := range results {
		if r.Action == "missing" {
			for _, def := range tools.AllTools {
				if def.Name == r.Tool && def.Kind == tools.KindSystem {
					hasSystemMissing = true
				}
			}
		}
	}
	if hasSystemMissing {
		fmt.Println()
		fmt.Println("System tools (nmap) require manual install:")
		fmt.Println("  sudo apt install -y nmap     # Debian / Ubuntu / Kali")
		fmt.Println("  brew install nmap            # macOS")
	}

	return nil
}

func runWatch(cmd *cobra.Command, args []string) error {
	// Parse interval
	intervalStr := flagWatchInterval
	if intervalStr == "" {
		intervalStr = "24h"
	}

	// Support "7d" shorthand (not supported by time.ParseDuration)
	if len(intervalStr) > 1 && intervalStr[len(intervalStr)-1] == 'd' {
		days := intervalStr[:len(intervalStr)-1]
		intervalStr = days + "h"
		// Multiply by 24 manually — parse as hours then multiply
		d, err := time.ParseDuration(intervalStr)
		if err == nil {
			intervalStr = fmt.Sprintf("%dh", int(d.Hours())*24)
		}
	}
	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		return fmt.Errorf("invalid --interval %q: %w", flagWatchInterval, err)
	}

	if err := initStore(); err != nil {
		return fmt.Errorf("initializing store: %w", err)
	}

	cfg, err := resolveConfig()
	if err != nil {
		return err
	}

	// Signal handling: SIGINT / SIGTERM stop the loop cleanly.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	log.Printf("[survex] watch mode started — scanning every %s", interval)
	log.Printf("[survex] press Ctrl+C to stop\n")

	scanNum := 0
	for {
		scanNum++
		log.Printf("[survex] watch: starting scan #%d for %s", scanNum, cfg.Client)

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		result, scanErr := scan.Run(ctx, cfg)
		stop()

		if scanErr != nil {
			if ctx.Err() != nil {
				fmt.Fprintf(os.Stderr, "\n[survex] watch: interrupted\n")
				return nil
			}
			log.Printf("[survex] watch: scan #%d failed: %v", scanNum, scanErr)
		} else {
			maxSev := risk.MaxSeverity(result.Findings)
			newSubs := 0
			if result.Diff != nil {
				newSubs = len(result.Diff.NewSubdomains)
			}
			log.Printf("[survex] watch: scan #%d complete — findings: %d (max: %s), new subs: %d",
				scanNum, len(result.Findings), maxSev, newSubs)
		}

		log.Printf("[survex] watch: next scan in %s (at %s)", interval, time.Now().Add(interval).Format("2006-01-02 15:04:05"))

		select {
		case <-time.After(interval):
			// continue loop
		case <-sigCh:
			fmt.Fprintf(os.Stderr, "\n[survex] watch: stopped\n")
			return nil
		}
	}
}

func runServe(cmd *cobra.Command, args []string) error {
	// Resolve the frontend dir to an absolute path so Fiber's file serving
	// works correctly regardless of the working directory.
	frontendDir := flagServeFrontend
	if frontendDir != "" {
		abs, err := filepath.Abs(frontendDir)
		if err == nil {
			frontendDir = abs
		}
	}

	database, err := db.Open(flagServeDB)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer database.Close()

	q := queue.New(database)

	app := api.New(database, q, frontendDir)

	// Graceful shutdown on Ctrl+C / SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\n[survex] shutting down…")
		_ = app.Shutdown()
	}()

	fmt.Printf("Survex web UI  → http://%s\n", flagServeAddr)
	fmt.Printf("Database       : %s\n", flagServeDB)
	if frontendDir != "" {
		fmt.Printf("Frontend       : %s\n", frontendDir)
	} else {
		fmt.Printf("Frontend       : API-only mode (no frontend dir set)\n")
	}
	fmt.Printf("Press Ctrl+C to stop.\n\n")

	return app.Listen(flagServeAddr)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
