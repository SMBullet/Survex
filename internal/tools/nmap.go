package tools

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/SMBullet/Survex/internal/models"
)

// portProfiles maps profile names to nmap port arguments.
// Custom port specs (e.g. "80,443,8080") are passed through directly.
var portProfiles = map[string][]string{
	"top-100":  {"--top-ports", "100"},
	"top-1000": {"--top-ports", "1000"}, // default
	"full":     {"-p-"},
	"web":      {"-p", "80,443,8080,8443,8000,8888,3000,4000,5000,9000,9090,9100,9443,10000"},
	"db":       {"-p", "3306,5432,27017,6379,1433,1521,5984,9200,9300,11211,27018,5672,15432,6380"},
	"stealth":  {"--top-ports", "100", "-T2"}, // slow, minimal footprint
}

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress  `xml:"address"`
	Hostnames []nmapHostname `xml:"hostnames>hostname"`
	Ports     []nmapPort     `xml:"ports>port"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// RunNmap scans all provided hosts in a single nmap invocation.
// portSpec accepts a named profile (top-100, top-1000, full, web, db, stealth)
// or a custom port list (e.g. "80,443,8080-8090"). Defaults to "top-1000".
func RunNmap(hosts []string, portSpec string) ([]models.Service, error) {
	if _, err := exec.LookPath("nmap"); err != nil {
		return nil, fmt.Errorf("nmap not found in PATH: install via your OS package manager (apt install nmap / choco install nmap)")
	}
	if len(hosts) == 0 {
		return nil, nil
	}

	// Write host list to a temp file so nmap reads it with -iL
	tmp, err := os.CreateTemp("", "survex-nmap-*.txt")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(strings.Join(hosts, "\n")); err != nil {
		return nil, fmt.Errorf("writing nmap input: %w", err)
	}
	tmp.Close()

	xmlOut := filepath.Join(os.TempDir(), "survex-nmap-out.xml")
	defer os.Remove(xmlOut)

	args := buildNmapArgs(portSpec, xmlOut, tmp.Name())
	cmd := exec.Command("nmap", args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if _, statErr := os.Stat(xmlOut); statErr != nil {
			return nil, fmt.Errorf("nmap failed: %w\n%s", err, stderr.String())
		}
	}

	xmlData, err := os.ReadFile(xmlOut)
	if err != nil {
		return nil, fmt.Errorf("reading nmap output: %w", err)
	}

	var run nmapRun
	if err := xml.Unmarshal(xmlData, &run); err != nil {
		return nil, fmt.Errorf("parsing nmap XML: %w", err)
	}

	return parseNmapRun(&run), nil
}

// buildNmapArgs constructs the nmap argument list for the given port spec.
func buildNmapArgs(portSpec, xmlOut, hostFile string) []string {
	args := []string{
		"-sV",      // service/version detection
		"-T4",      // aggressive timing (override with stealth profile)
		"--open",   // only show open ports
		"-oX", xmlOut,
		"-iL", hostFile,
	}

	// Named profiles override default port args (including timing for stealth)
	if spec := strings.ToLower(strings.TrimSpace(portSpec)); spec != "" {
		if profileArgs, ok := portProfiles[spec]; ok {
			// stealth profile sets its own timing; replace -T4
			if spec == "stealth" {
				// Remove -T4 that was already added
				filtered := args[:0]
				for _, a := range args {
					if a != "-T4" {
						filtered = append(filtered, a)
					}
				}
				args = filtered
			}
			args = append(args, profileArgs...)
		} else {
			// Custom port list: "80,443,8080"
			args = append(args, "-p", spec)
		}
	} else {
		// Default: top 1000
		args = append(args, "--top-ports", "1000")
	}

	return args
}

func parseNmapRun(run *nmapRun) []models.Service {
	var services []models.Service
	for _, h := range run.Hosts {
		hostname := bestHostname(h)
		for _, p := range h.Ports {
			if p.State.State != "open" {
				continue
			}
			svcName := p.Service.Name
			if p.Service.Product != "" {
				if p.Service.Version != "" {
					svcName = fmt.Sprintf("%s (%s %s)", p.Service.Name, p.Service.Product, p.Service.Version)
				} else {
					svcName = fmt.Sprintf("%s (%s)", p.Service.Name, p.Service.Product)
				}
			}
			services = append(services, models.Service{
				Host:        hostname,
				Port:        p.PortID,
				Protocol:    p.Protocol,
				ServiceName: svcName,
			})
		}
	}
	return services
}

// bestHostname prefers user-supplied DNS names over PTR records over raw IPs.
func bestHostname(h nmapHost) string {
	for _, hn := range h.Hostnames {
		if hn.Type == "user" && hn.Name != "" {
			return hn.Name
		}
	}
	for _, hn := range h.Hostnames {
		if hn.Name != "" {
			return hn.Name
		}
	}
	for _, addr := range h.Addresses {
		if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
			return addr.Addr
		}
	}
	return ""
}
