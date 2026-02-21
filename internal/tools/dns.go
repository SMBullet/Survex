package tools

import (
	"context"
	"net"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

var resolver = &net.Resolver{
	PreferGo: true,
}

// ResolveDNS resolves A, CNAME, MX, and TXT records for a hostname.
// Uses Go's built-in net package — no external tool required.
func ResolveDNS(host string) []models.DNSRecord {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var records []models.DNSRecord

	// A records
	addrs, err := resolver.LookupHost(ctx, host)
	if err == nil {
		for _, addr := range addrs {
			records = append(records, models.DNSRecord{
				Host:  host,
				Type:  "A",
				Value: addr,
			})
		}
	}

	// CNAME
	cname, err := resolver.LookupCNAME(ctx, host)
	if err == nil && cname != host+"." && cname != "" {
		records = append(records, models.DNSRecord{
			Host:  host,
			Type:  "CNAME",
			Value: cname,
		})
	}

	// MX
	mxRecords, err := resolver.LookupMX(ctx, host)
	if err == nil {
		for _, mx := range mxRecords {
			records = append(records, models.DNSRecord{
				Host:  host,
				Type:  "MX",
				Value: mx.Host,
			})
		}
	}

	// TXT
	txtRecords, err := resolver.LookupTXT(ctx, host)
	if err == nil {
		for _, txt := range txtRecords {
			records = append(records, models.DNSRecord{
				Host:  host,
				Type:  "TXT",
				Value: txt,
			})
		}
	}

	return records
}

// ResolveIP returns the first IPv4 address for a hostname, or empty string.
func ResolveIP(host string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := resolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	return addrs[0]
}
