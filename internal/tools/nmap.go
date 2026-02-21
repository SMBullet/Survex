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
// This is far more efficient than one process per host.
func RunNmap(hosts []string) ([]models.Service, error) {
	if _, err := exec.LookPath("nmap"); err != nil {
		return nil, fmt.Errorf("nmap not found in PATH: install via your OS package manager (apt install nmap)")
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

	cmd := exec.Command(
		"nmap",
		"-sV",           // service/version detection
		"--top-ports", "1000",
		"-T4",           // aggressive timing
		"--open",        // only show open ports
		"-oX", xmlOut,   // XML output to file
		"-iL", tmp.Name(),
	)

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
