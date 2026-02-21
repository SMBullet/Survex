package diff

import (
	"fmt"

	"github.com/SMBullet/Survex/internal/models"
)

// Compute compares a new scan result against the previous one and returns
// a Diff describing what changed. If prev is nil, it means this is the first
// scan and there is nothing to compare against.
func Compute(prev, curr *models.ScanResult) *models.Diff {
	if prev == nil {
		return nil
	}

	d := &models.Diff{}

	// Index previous subdomains
	prevSubs := make(map[string]bool)
	for _, s := range prev.Subdomains {
		prevSubs[s.Name] = true
	}
	currSubs := make(map[string]bool)
	for _, s := range curr.Subdomains {
		currSubs[s.Name] = true
	}

	for name := range currSubs {
		if !prevSubs[name] {
			d.NewSubdomains = append(d.NewSubdomains, name)
		}
	}
	for name := range prevSubs {
		if !currSubs[name] {
			d.RemovedSubdomains = append(d.RemovedSubdomains, name)
		}
	}

	// Index previous services by key
	prevPorts := make(map[string]bool)
	for _, s := range prev.Services {
		prevPorts[serviceKey(s)] = true
	}
	for _, s := range curr.Services {
		if !prevPorts[serviceKey(s)] {
			d.NewOpenPorts = append(d.NewOpenPorts, s)
		}
	}

	currPorts := make(map[string]bool)
	for _, s := range curr.Services {
		currPorts[serviceKey(s)] = true
	}
	for _, s := range prev.Services {
		if !currPorts[serviceKey(s)] {
			d.RemovedPorts = append(d.RemovedPorts, s)
		}
	}

	// TLS issuer changes
	prevTLS := make(map[string]string)
	for _, h := range prev.HTTP {
		if h.TLSIssuer != "" {
			prevTLS[h.Host] = h.TLSIssuer
		}
	}
	for _, h := range curr.HTTP {
		if h.TLSIssuer != "" {
			if old, ok := prevTLS[h.Host]; ok && old != h.TLSIssuer {
				d.TLSChanges = append(d.TLSChanges,
					fmt.Sprintf("%s: %s -> %s", h.Host, old, h.TLSIssuer),
				)
			}
		}
	}

	return d
}

func serviceKey(s models.Service) string {
	return fmt.Sprintf("%s:%d/%s", s.Host, s.Port, s.Protocol)
}
