package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/SMBullet/Survex/internal/config"
	"github.com/SMBullet/Survex/internal/risk"
	"github.com/SMBullet/Survex/internal/scan"
	"github.com/SMBullet/Survex/internal/store"
	"github.com/spf13/cobra"
)

const dbPath = "survex.db"

var rootCmd = &cobra.Command{
	Use:   "survex",
	Short: "Attack surface management CLI",
	Long:  "Survex enumerates, monitors, and scores the external attack surface of a target domain.",
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a full scan against a target",
	RunE:  runScan,
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

var (
	configFile string
	outputDir  string
	failOn     string
)

func init() {
	scanCmd.Flags().StringVarP(&configFile, "config", "c", "", "path to client config file (required)")
	scanCmd.Flags().StringVarP(&outputDir, "output", "o", "", "output directory (overrides config)")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "", "exit 1 if findings at or above this severity exist (low|medium|high|critical)")
	_ = scanCmd.MarkFlagRequired("config")

	diffCmd.Flags().StringVarP(&configFile, "config", "c", "", "path to client config file (required)")
	_ = diffCmd.MarkFlagRequired("config")

	reportCmd.Flags().StringVarP(&configFile, "config", "c", "", "path to client config file (required)")
	_ = reportCmd.MarkFlagRequired("config")

	rootCmd.AddCommand(scanCmd, diffCmd, reportCmd)
}

func initStore() error {
	return store.Init(dbPath)
}

func loadConfig() (*config.Config, error) {
	return config.Load(configFile)
}

func runScan(cmd *cobra.Command, args []string) error {
	if err := initStore(); err != nil {
		return fmt.Errorf("initializing store: %w", err)
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	if outputDir != "" {
		cfg.Output.Dir = outputDir
	}

	result, err := scan.Run(cfg)
	if err != nil {
		return err
	}

	// Print summary to stdout
	maxSev := risk.MaxSeverity(result.Findings)
	fmt.Printf("\nScan complete: %s\n", result.Scan.ID)
	fmt.Printf("  Subdomains : %d\n", len(result.Subdomains))
	fmt.Printf("  Services   : %d\n", len(result.Services))
	fmt.Printf("  HTTP       : %d\n", len(result.HTTP))
	fmt.Printf("  Findings   : %d (max severity: %s)\n", len(result.Findings), maxSev)

	if result.Diff != nil {
		fmt.Printf("  New subs   : %d\n", len(result.Diff.NewSubdomains))
		fmt.Printf("  New ports  : %d\n", len(result.Diff.NewOpenPorts))
	}

	// Optional: exit 1 if findings meet the threshold (for CI pipelines)
	if failOn != "" && maxSev != "" && risk.MeetsThreshold(maxSev, failOn) {
		fmt.Fprintf(os.Stderr, "\nfindings at or above '%s' severity detected — exiting 1\n", failOn)
		os.Exit(1)
	}

	return nil
}

func runDiff(cmd *cobra.Command, args []string) error {
	if err := initStore(); err != nil {
		return fmt.Errorf("initializing store: %w", err)
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	last, err := store.LoadLast(cfg.Client)
	if err != nil || last == nil {
		return fmt.Errorf("no previous scan found for client '%s'", cfg.Client)
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

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	last, err := store.LoadLast(cfg.Client)
	if err != nil || last == nil {
		return fmt.Errorf("no scan found for client '%s'", cfg.Client)
	}

	b, _ := json.MarshalIndent(last.Findings, "", "  ")
	fmt.Println(string(b))
	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
