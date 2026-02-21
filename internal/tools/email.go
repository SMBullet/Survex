package tools

import (
	"fmt"
	"net"
	"strings"

	"github.com/SMBullet/Survex/internal/models"
)

// dkimSelectors lists common DKIM selector names to probe.
// We stop at the first hit, so order matters — most common first.
var dkimSelectors = []string{
	"google", "default", "mail", "dkim",
	"selector1", "selector2",
	"k1", "k2", "s1", "s2",
	"email", "smtp", "mx", "mta",
}

// RunEmailSecurity checks SPF, DMARC, and DKIM records for each root domain.
// It should be called with the user-specified domain targets, not subdomains.
func RunEmailSecurity(domains []string) []models.EmailSecurityResult {
	var results []models.EmailSecurityResult
	for _, domain := range domains {
		results = append(results, checkEmailSecurity(domain))
	}
	return results
}

func checkEmailSecurity(domain string) models.EmailSecurityResult {
	r := models.EmailSecurityResult{Domain: domain}

	// SPF — TXT record on the domain itself starting with "v=spf1"
	if txts, err := net.LookupTXT(domain); err == nil {
		for _, txt := range txts {
			if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
				r.SPFPresent = true
				r.SPF = txt
				break
			}
		}
	}

	// DMARC — TXT record on _dmarc.<domain> starting with "v=DMARC1"
	if txts, err := net.LookupTXT("_dmarc." + domain); err == nil {
		for _, txt := range txts {
			if strings.HasPrefix(strings.ToLower(txt), "v=dmarc1") {
				r.DMARCPresent = true
				r.DMARC = txt
				break
			}
		}
	}

	// DKIM — probe common selectors: <selector>._domainkey.<domain>
	for _, sel := range dkimSelectors {
		host := fmt.Sprintf("%s._domainkey.%s", sel, domain)
		txts, err := net.LookupTXT(host)
		if err != nil {
			continue
		}
		for _, txt := range txts {
			low := strings.ToLower(txt)
			if strings.Contains(low, "v=dkim1") || strings.Contains(low, "p=") {
				r.DKIMPresent = true
				r.DKIMSelector = sel
				r.DKIM = txt
				break
			}
		}
		if r.DKIMPresent {
			break
		}
	}

	return r
}
