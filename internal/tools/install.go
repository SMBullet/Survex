package tools

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ─── Tool Registry ─────────────────────────────────────────────────────────────

// ToolKind categorizes how a tool is installed and verified.
type ToolKind int

const (
	KindGoTool  ToolKind = iota // installed via go install
	KindSystem                  // installed via apt / brew / choco
	KindBuiltIn                 // no binary required (pure Go)
	KindAPI                     // no binary; just needs an API key
)

// ToolDef describes one external dependency used by Survex.
type ToolDef struct {
	Name        string
	Binary      string // executable name to look for (empty for built-in / api)
	Kind        ToolKind
	Description string
	GoInstall   string // full go install argument (for KindGoTool)
	AptPackage  string // apt package name (for KindSystem on Linux)
	BrewFormula string // homebrew formula (for KindSystem on macOS)
	WinChoco    string // chocolatey package (for KindSystem on Windows)
	VersionFlag string // flag or subcommand to print version (default: -version)
	// PDTool: when true, verify the version output contains "projectdiscovery"
	// to guard against same-named system packages (e.g., Python httpx on Kali Linux).
	PDTool bool
}

// AllTools is the canonical registry of every tool Survex can use.
// This is the single source of truth used by both 'modules' and 'install'.
var AllTools = []ToolDef{
	{
		Name:        "subfinder",
		Binary:      "subfinder",
		Kind:        KindGoTool,
		Description: "Subdomain enumeration via OSINT sources",
		GoInstall:   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		VersionFlag: "-version",
		PDTool:      true,
	},
	{
		Name:        "amass",
		Binary:      "amass",
		Kind:        KindGoTool,
		Description: "Subdomain enumeration via OSINT (more sources, slower)",
		GoInstall:   "github.com/owasp-amass/amass/v4/...@master",
		VersionFlag: "-version",
	},
	{
		Name:        "crts",
		Kind:        KindBuiltIn,
		Description: "Certificate transparency lookup (crt.sh)",
	},
	{
		Name:        "dns",
		Kind:        KindBuiltIn,
		Description: "DNS resolution (A, CNAME, MX, TXT records)",
	},
	{
		Name:        "nmap",
		Binary:      "nmap",
		Kind:        KindSystem,
		Description: "Port scanning and service detection",
		AptPackage:  "nmap",
		BrewFormula: "nmap",
		WinChoco:    "nmap",
		VersionFlag: "--version",
	},
	{
		Name:        "httpx",
		Binary:      "httpx",
		Kind:        KindGoTool,
		Description: "HTTP/S probing, title, status code, tech stack",
		GoInstall:   "github.com/projectdiscovery/httpx/cmd/httpx@latest",
		VersionFlag: "-version",
		PDTool:      true,
	},
	{
		Name:        "tls",
		Kind:        KindBuiltIn,
		Description: "TLS certificate analysis (expiry, version, SANs)",
	},
	{
		Name:        "waf",
		Kind:        KindBuiltIn,
		Description: "WAF fingerprinting (Cloudflare, Akamai, AWS WAF, etc.)",
	},
	{
		Name:        "headers",
		Kind:        KindBuiltIn,
		Description: "HTTP security headers audit (HSTS, CSP, X-Frame-Options, etc.)",
	},
	{
		Name:        "cors",
		Kind:        KindBuiltIn,
		Description: "CORS misconfiguration testing (origin reflection, wildcard)",
	},
	{
		Name:        "cookies",
		Kind:        KindBuiltIn,
		Description: "Cookie security analysis (Secure, HttpOnly, SameSite flags)",
	},
	{
		Name:        "s3",
		Kind:        KindBuiltIn,
		Description: "Cloud storage bucket exposure (AWS S3, GCS, Azure Blob)",
	},
	{
		Name:        "gau",
		Binary:      "gau",
		Kind:        KindGoTool,
		Description: "Historical URL discovery from Wayback Machine / Common Crawl",
		GoInstall:   "github.com/lc/gau/v2/cmd/gau@latest",
		VersionFlag: "--version",
	},
	{
		Name:        "katana",
		Binary:      "katana",
		Kind:        KindGoTool,
		Description: "JS-aware web crawler for endpoint and parameter discovery",
		GoInstall:   "github.com/projectdiscovery/katana/cmd/katana@latest",
		VersionFlag: "-version",
		PDTool:      true,
	},
	{
		Name:        "screenshot",
		Binary:      "gowitness",
		Kind:        KindGoTool,
		Description: "Visual recon — browser screenshots via gowitness",
		GoInstall:   "github.com/sensepost/gowitness@latest",
		VersionFlag: "version", // gowitness uses a subcommand, not a flag
	},
	{
		Name:        "nuclei",
		Binary:      "nuclei",
		Kind:        KindGoTool,
		Description: "Vulnerability scanning (CVEs, misconfigs, exposures, default creds)",
		GoInstall:   "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		VersionFlag: "-version",
		PDTool:      true,
	},
	{
		Name:        "shodan",
		Kind:        KindAPI,
		Description: "Passive host enrichment via Shodan API (requires API key)",
	},
}

// ─── Status Checking ───────────────────────────────────────────────────────────

// ToolStatus is the result of probing a single tool.
type ToolStatus struct {
	Def         ToolDef
	State       string // "ok" | "missing" | "conflict" | "needs-key" | "built-in"
	Path        string // resolved binary path (when found)
	Version     string // first line of version output (when found)
	Conflict    string // description of the conflict (when State == "conflict")
	InstallHint string // human-readable install command
}

// CheckStatus probes a single tool and returns its current state.
//
// For PDTool entries (httpx, subfinder, nuclei, katana) it verifies that the
// binary belongs to ProjectDiscovery by checking for "projectdiscovery" in
// the version output. This catches Kali Linux's Python httpx, system amass v3,
// and similar naming conflicts.
func CheckStatus(def ToolDef) ToolStatus {
	st := ToolStatus{Def: def, InstallHint: installToolHint(def)}

	switch def.Kind {
	case KindBuiltIn:
		st.State = "built-in"
		return st
	case KindAPI:
		st.State = "needs-key"
		return st
	}

	// Gather candidate paths — Go bin dirs first, then PATH.
	candidates := gatherCandidatePaths(def.Binary)
	if len(candidates) == 0 {
		st.State = "missing"
		return st
	}

	var lastConflict string
	for _, p := range candidates {
		out, err := queryToolVersion(p, def.VersionFlag)
		if err != nil && strings.TrimSpace(out) == "" {
			// Binary exists on disk but cannot execute (wrong arch, permission denied, etc.)
			continue
		}

		lower := strings.ToLower(out)
		if def.PDTool && !isPDOutput(lower) {
			// Same binary name, wrong tool (e.g., Python httpx on Kali Linux).
			lastConflict = fmt.Sprintf(
				"'%s' at %s is NOT the ProjectDiscovery version (got: %s)",
				def.Binary, p, versionFirstLine(out),
			)
			// Keep searching — the PD version might be installed at a later candidate.
			continue
		}

		// Good binary found.
		st.State = "ok"
		st.Path = p
		st.Version = versionFirstLine(out)
		return st
	}

	// All candidates found but all conflicted — report the conflict.
	if lastConflict != "" {
		st.State = "conflict"
		st.Conflict = lastConflict
		return st
	}

	st.State = "missing"
	return st
}

// CheckAll returns the status of every tool in AllTools.
func CheckAll() []ToolStatus {
	results := make([]ToolStatus, len(AllTools))
	for i, def := range AllTools {
		results[i] = CheckStatus(def)
	}
	return results
}

// ─── Installation ──────────────────────────────────────────────────────────────

// InstallResult is the outcome of attempting to install or verify a single tool.
type InstallResult struct {
	Tool    string
	Action  string // "ok" | "installed" | "built-in" | "needs-key" | "missing" | "conflict" | "failed"
	Message string
}

// RunInstall checks and optionally installs external tools.
//
//   - filter:    if non-empty, only process tools whose names appear in the list.
//   - doInstall: if true, attempt go install for missing/conflicted Go tools.
//   - logFn:     progress callback (pass nil to suppress output).
func RunInstall(filter []string, doInstall bool, logFn func(string)) []InstallResult {
	if logFn == nil {
		logFn = func(string) {}
	}

	var results []InstallResult

	for _, def := range AllTools {
		if len(filter) > 0 && !installSliceHas(filter, def.Name) {
			continue
		}

		st := CheckStatus(def)
		res := InstallResult{Tool: def.Name}

		switch st.State {

		case "built-in":
			res.Action = "built-in"
			res.Message = "no external binary required"

		case "needs-key":
			res.Action = "needs-key"
			res.Message = "set --shodan-key or SHODAN_API_KEY env var"

		case "ok":
			res.Action = "ok"
			if st.Version != "" {
				res.Message = st.Version
			} else {
				res.Message = st.Path
			}

		case "conflict":
			res.Action = "conflict"
			res.Message = st.Conflict
			if doInstall && def.Kind == KindGoTool {
				logFn(fmt.Sprintf("[!] Conflict — installing ProjectDiscovery %s to ~/go/bin ...", def.Name))
				if err := execGoInstall(def, logFn); err != nil {
					res.Action = "failed"
					res.Message = err.Error()
				} else {
					// Re-probe after install.
					if st2 := CheckStatus(def); st2.State == "ok" {
						res.Action = "installed"
						res.Message = "conflict resolved → " + st2.Version
					} else {
						res.Message += "\n    Installed, but ensure ~/go/bin comes before /usr/bin in PATH"
					}
				}
			}

		case "missing":
			if !doInstall {
				res.Action = "missing"
				res.Message = st.InstallHint
			} else if def.Kind == KindGoTool {
				logFn(fmt.Sprintf("[*] Installing %s ...", def.Name))
				if err := execGoInstall(def, logFn); err != nil {
					res.Action = "failed"
					res.Message = err.Error()
				} else {
					if st2 := CheckStatus(def); st2.State == "ok" {
						res.Action = "installed"
						res.Message = st2.Version
					} else {
						res.Action = "installed"
						res.Message = "done — restart terminal or source ~/.bashrc"
					}
				}
			} else {
				// System tool — cannot be installed automatically.
				res.Action = "missing"
				res.Message = "manual install required: " + st.InstallHint
			}
		}

		results = append(results, res)
	}

	return results
}

// EnsureGoPath ensures ~/go/bin is in PATH for the current process and
// persists the export line to common shell config files (.bashrc, .zshrc, etc.).
// Returns the list of files that were modified.
func EnsureGoPath() (modified []string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}

	goBin := filepath.Join(home, "go", "bin")

	// Activate for the current process immediately so installed tools are
	// findable by subsequent CheckStatus calls without a shell restart.
	cur := os.Getenv("PATH")
	if !strings.Contains(cur, goBin) {
		_ = os.Setenv("PATH", goBin+string(os.PathListSeparator)+cur)
	}

	if runtime.GOOS == "windows" {
		// Windows PATH management requires registry edits or session restarts.
		// We activate it for the current process above; guide the user for persistence.
		return nil, nil
	}

	exportLine := `export PATH="` + goBin + `:$PATH"`
	marker := "# Added by survex install"

	// Shell config files to update (only if they already exist).
	shellConfigs := []string{
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".profile"),
	}

	for _, f := range shellConfigs {
		data, readErr := os.ReadFile(f)
		if readErr != nil {
			continue // file does not exist — skip
		}
		if strings.Contains(string(data), goBin) {
			continue // already configured
		}
		fh, openErr := os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0o644)
		if openErr != nil {
			continue
		}
		_, _ = fmt.Fprintf(fh, "\n%s\n%s\n", marker, exportLine)
		fh.Close()
		modified = append(modified, f)
	}

	return modified, nil
}

// ─── Private helpers ───────────────────────────────────────────────────────────

// execGoInstall runs `go install <def.GoInstall>` and streams output via logFn.
func execGoInstall(def ToolDef, logFn func(string)) error {
	if def.GoInstall == "" {
		return fmt.Errorf("no go install path defined for %s", def.Name)
	}
	cmd := exec.Command("go", "install", def.GoInstall)
	out, err := cmd.CombinedOutput()
	if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
		logFn(trimmed)
	}
	if err != nil {
		return fmt.Errorf("go install %s failed: %w", def.GoInstall, err)
	}
	return nil
}

// gatherCandidatePaths returns filesystem paths to consider for a binary,
// with Go install dirs listed before system paths like /usr/bin.
// This ensures the PD version is preferred over any same-named system package.
func gatherCandidatePaths(binary string) []string {
	seen := map[string]bool{}
	var result []string

	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		if _, statErr := os.Stat(p); statErr == nil {
			result = append(result, p)
		}
	}

	// 1. ~/go/bin — where `go install` puts binaries by default.
	if home, homeErr := os.UserHomeDir(); homeErr == nil {
		add(filepath.Join(home, "go", "bin", binary))
		if runtime.GOOS == "windows" {
			add(filepath.Join(home, "go", "bin", binary+".exe"))
		}
	}

	// 2. $GOPATH/bin — alternative GOPATH location.
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		add(filepath.Join(gopath, "bin", binary))
	}

	// 3. Whatever PATH resolution produces (may include /usr/bin, etc.).
	if p, lookErr := exec.LookPath(binary); lookErr == nil {
		add(p)
	}

	return result
}

// queryToolVersion executes `path <flag>` and returns combined stdout+stderr.
func queryToolVersion(path, flag string) (string, error) {
	if flag == "" {
		flag = "-version"
	}
	out, err := exec.Command(path, flag).CombinedOutput()
	return string(out), err
}

// versionFirstLine extracts a clean version string from tool output.
// ProjectDiscovery tools print ASCII art banners before the actual version,
// so we prefer a line containing a semver pattern (vX.Y.Z) when present.
func versionFirstLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")

	// Pass 1: return the first line that contains a semver-like token (v1.2.3).
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if containsVersion(line) {
			return line
		}
	}

	// Pass 2: return the first line that looks like readable text (not ASCII art).
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !isAsciiArt(line) {
			return line
		}
	}

	return strings.TrimSpace(s)
}

// containsVersion reports whether s contains a version token like v1.2.3.
func containsVersion(s string) bool {
	// Simple check: "v" followed by a digit then "." somewhere in the string.
	for i := 0; i < len(s)-2; i++ {
		if s[i] == 'v' && s[i+1] >= '0' && s[i+1] <= '9' {
			for j := i + 2; j < len(s); j++ {
				if s[j] == '.' {
					return true
				}
				if s[j] < '0' || s[j] > '9' {
					break
				}
			}
		}
	}
	return false
}

// isAsciiArt reports whether a line is likely banner/logo art (mostly non-letter chars).
func isAsciiArt(s string) bool {
	if len(s) == 0 {
		return false
	}
	artChars := 0
	for _, r := range s {
		if r == '_' || r == '/' || r == '\\' || r == '|' || r == ' ' ||
			r == '-' || r == '.' || r == '(' || r == ')' {
			artChars++
		}
	}
	return float64(artChars)/float64(len(s)) > 0.55
}

// isPDOutput reports whether version output belongs to a ProjectDiscovery tool.
//
// Older PD builds printed "projectdiscovery.io" in the banner. Newer builds
// (subfinder v2.12+, nuclei v3.7+) removed the branding but still use the
// gologger "[INF]" prefix, which is unique to the PD Go toolchain.
func isPDOutput(lower string) bool {
	return strings.Contains(lower, "projectdiscovery") ||
		strings.Contains(lower, "[inf]")
}

// installToolHint returns a human-readable install command for a tool.
func installToolHint(def ToolDef) string {
	switch def.Kind {
	case KindGoTool:
		return "go install " + def.GoInstall
	case KindSystem:
		switch runtime.GOOS {
		case "linux":
			return "sudo apt install -y " + def.AptPackage
		case "darwin":
			return "brew install " + def.BrewFormula
		case "windows":
			return "choco install " + def.WinChoco
		}
	case KindAPI:
		return "set --shodan-key or SHODAN_API_KEY env var"
	}
	return ""
}

// installSliceHas reports whether ss contains s (case-insensitive).
func installSliceHas(ss []string, s string) bool {
	for _, v := range ss {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
