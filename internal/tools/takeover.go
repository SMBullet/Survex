package tools

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// takeoverSignature describes a service that is vulnerable to subdomain takeover
// when a CNAME points to it but the resource is unclaimed.
type takeoverSignature struct {
	Service     string   // e.g. "GitHub Pages", "AWS S3", "Heroku"
	CNames      []string // CNAME patterns to match (suffix match)
	Fingerprint []string // HTTP response body or header fingerprints indicating unclaimed
	NXDomain    bool     // If true, NXDOMAIN on CNAME target means vulnerable
}

// takeoverSignatures is a curated database of services vulnerable to subdomain takeover.
// Sources: https://github.com/EdOverflow/can-i-take-over-xyz
var takeoverSignatures = []takeoverSignature{
	{
		Service:     "GitHub Pages",
		CNames:      []string{".github.io"},
		Fingerprint: []string{"There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/)"},
		NXDomain:    false,
	},
	{
		Service:     "Heroku",
		CNames:      []string{".herokuapp.com", ".herokussl.com", ".herokudns.com"},
		Fingerprint: []string{"No such app", "no-such-app", "herokucdn.com/error-pages/no-such-app"},
		NXDomain:    false,
	},
	{
		Service:     "AWS S3",
		CNames:      []string{".s3.amazonaws.com", ".s3-website"},
		Fingerprint: []string{"NoSuchBucket", "The specified bucket does not exist"},
		NXDomain:    false,
	},
	{
		Service:     "AWS Elastic Beanstalk",
		CNames:      []string{".elasticbeanstalk.com"},
		Fingerprint: []string{},
		NXDomain:    true,
	},
	{
		Service:     "Azure",
		CNames:      []string{".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com", ".trafficmanager.net", ".blob.core.windows.net", ".azure-api.net", ".azurehdinsight.net", ".azureedge.net", ".azurecontainer.io", ".azurefd.net"},
		Fingerprint: []string{},
		NXDomain:    true,
	},
	{
		Service:     "Shopify",
		CNames:      []string{"shops.myshopify.com"},
		Fingerprint: []string{"Sorry, this shop is currently unavailable", "Only one step left!"},
		NXDomain:    false,
	},
	{
		Service:     "Fastly",
		CNames:      []string{".fastly.net", ".fastlylb.net"},
		Fingerprint: []string{"Fastly error: unknown domain"},
		NXDomain:    false,
	},
	{
		Service:     "Pantheon",
		CNames:      []string{".pantheonsite.io"},
		Fingerprint: []string{"404 error unknown site", "The gods are wise"},
		NXDomain:    false,
	},
	{
		Service:     "Tumblr",
		CNames:      []string{".tumblr.com"},
		Fingerprint: []string{"There's nothing here.", "Whatever you were looking for doesn't currently exist at this address"},
		NXDomain:    false,
	},
	{
		Service:     "WordPress.com",
		CNames:      []string{".wordpress.com"},
		Fingerprint: []string{"Do you want to register"},
		NXDomain:    false,
	},
	{
		Service:     "Surge.sh",
		CNames:      []string{".surge.sh"},
		Fingerprint: []string{"project not found"},
		NXDomain:    false,
	},
	{
		Service:     "Fly.io",
		CNames:      []string{".fly.dev"},
		Fingerprint: []string{},
		NXDomain:    true,
	},
	{
		Service:     "Notion",
		CNames:      []string{".notion.site"},
		Fingerprint: []string{},
		NXDomain:    true,
	},
	{
		Service:     "Cargo Collective",
		CNames:      []string{".cargocollective.com"},
		Fingerprint: []string{"404 Not Found"},
		NXDomain:    false,
	},
	{
		Service:     "Strikingly",
		CNames:      []string{".strikinglydns.com", ".s.strikinglydns.com"},
		Fingerprint: []string{"page not found", "But if you're looking to build your own website"},
		NXDomain:    false,
	},
	{
		Service:     "Unbounce",
		CNames:      []string{".unbouncepages.com"},
		Fingerprint: []string{"The requested URL was not found on this server"},
		NXDomain:    false,
	},
	{
		Service:     "HubSpot",
		CNames:      []string{".hs-sites.com", ".hubspot.net"},
		Fingerprint: []string{},
		NXDomain:    true,
	},
	{
		Service:     "Bitbucket",
		CNames:      []string{".bitbucket.io"},
		Fingerprint: []string{"Repository not found"},
		NXDomain:    false,
	},
	{
		Service:     "Ghost",
		CNames:      []string{".ghost.io"},
		Fingerprint: []string{"The thing you were looking for is no longer here"},
		NXDomain:    false,
	},
	{
		Service:     "Netlify",
		CNames:      []string{".netlify.app", ".netlify.com"},
		Fingerprint: []string{"Not Found - Request ID"},
		NXDomain:    false,
	},
	{
		Service:     "Vercel",
		CNames:      []string{".vercel.app", ".now.sh"},
		Fingerprint: []string{},
		NXDomain:    true,
	},
	{
		Service:     "Zendesk",
		CNames:      []string{".zendesk.com"},
		Fingerprint: []string{"Help Center Closed"},
		NXDomain:    false,
	},
	{
		Service:     "UserVoice",
		CNames:      []string{".uservoice.com"},
		Fingerprint: []string{"This UserVoice subdomain is currently available"},
		NXDomain:    false,
	},
	{
		Service:     "Tilda",
		CNames:      []string{".tilda.ws"},
		Fingerprint: []string{"Please renew your subscription"},
		NXDomain:    false,
	},
	{
		Service:     "Readme.io",
		CNames:      []string{".readme.io"},
		Fingerprint: []string{"Project doesnt exist"},
		NXDomain:    false,
	},
}

// DetectTakeovers checks a list of subdomains for potential subdomain takeover
// vulnerabilities by resolving CNAMEs and fingerprinting responses.
// Concurrency is capped with a semaphore to avoid DNS flood.
func DetectTakeovers(subdomains []models.Subdomain, timeoutSecs int) []models.TakeoverResult {
	if len(subdomains) == 0 {
		return nil
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 15)
	var results []models.TakeoverResult

	client := &http.Client{
		Timeout: time.Duration(timeoutSecs) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	for _, sub := range subdomains {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := checkTakeover(client, host)
			if result == nil {
				return
			}
			mu.Lock()
			results = append(results, *result)
			mu.Unlock()
		}(sub.Name)
	}

	wg.Wait()
	return results
}

// checkTakeover resolves the CNAME chain for a host and checks against known
// vulnerable signatures.
func checkTakeover(client *http.Client, host string) *models.TakeoverResult {
	// Resolve CNAME records
	cname, err := net.LookupCNAME(host)
	if err != nil || cname == "" || cname == host+"." {
		return nil // No CNAME — not a takeover candidate
	}
	cname = strings.TrimSuffix(cname, ".")

	// Check against each signature
	for _, sig := range takeoverSignatures {
		if !matchesCNAME(cname, sig.CNames) {
			continue
		}

		// Matched a known vulnerable service CNAME pattern
		result := &models.TakeoverResult{
			Host:       host,
			CNAME:      cname,
			Service:    sig.Service,
			Vulnerable: false,
		}

		// Check 1: NXDOMAIN on the CNAME target (resource deleted/unclaimed)
		if sig.NXDomain {
			_, err := net.LookupHost(cname)
			if err != nil {
				if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
					result.Vulnerable = true
					result.Evidence = fmt.Sprintf("CNAME target %s returns NXDOMAIN — resource unclaimed", cname)
					return result
				}
			}
		}

		// Check 2: HTTP fingerprint — does the response body match unclaimed patterns?
		if len(sig.Fingerprint) > 0 {
			for _, scheme := range []string{"https", "http"} {
				body := fetchBody(client, fmt.Sprintf("%s://%s", scheme, host))
				if body == "" {
					continue
				}
				for _, fp := range sig.Fingerprint {
					if strings.Contains(body, fp) {
						result.Vulnerable = true
						result.Evidence = fmt.Sprintf("HTTP response contains '%s' (service: %s)", fp, sig.Service)
						return result
					}
				}
			}
		}

		// CNAME matches but resource seems claimed — not vulnerable but worth noting
		result.Evidence = fmt.Sprintf("CNAME points to %s but resource appears claimed", sig.Service)
		return result
	}

	return nil
}

// matchesCNAME checks if the CNAME record matches any of the given patterns (suffix match).
func matchesCNAME(cname string, patterns []string) bool {
	lower := strings.ToLower(cname)
	for _, p := range patterns {
		if strings.HasSuffix(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// fetchBody retrieves the response body (up to 4KB) from a URL for fingerprinting.
func fetchBody(client *http.Client, url string) string {
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}
