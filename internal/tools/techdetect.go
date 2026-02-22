package tools

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// techSignature is a single detection rule.
// Matching logic (in order of precedence):
//  1. Cookie: match if any Set-Cookie header name starts with Cookie.
//  2. Header + Body: match if the named header is present AND Body matches its value.
//  3. Header (no Body): match if the named header exists (any value).
//  4. Body only (Header & Cookie both empty): match if Body matches the response body.
type techSignature struct {
	Name     string
	Category string
	Header   string
	Cookie   string
	Body     *regexp.Regexp
}

var techSignatures = []techSignature{
	// ── CMS ──────────────────────────────────────────────────────────────────
	{Name: "WordPress", Category: "CMS", Header: "X-Powered-By", Body: regexp.MustCompile(`(?i)wordpress`)},
	{Name: "WordPress", Category: "CMS", Body: regexp.MustCompile(`(?i)/wp-content/|/wp-includes/|wp-login\.php`)},
	{Name: "WordPress", Category: "CMS", Cookie: "wp-settings"},
	{Name: "WordPress", Category: "CMS", Cookie: "wordpress_"},
	{Name: "Drupal", Category: "CMS", Header: "X-Generator", Body: regexp.MustCompile(`(?i)drupal`)},
	{Name: "Drupal", Category: "CMS", Header: "X-Drupal-Cache"},
	{Name: "Drupal", Category: "CMS", Body: regexp.MustCompile(`(?i)Drupal\.settings|sites/default/files`)},
	{Name: "Drupal", Category: "CMS", Cookie: "SESS"},
	{Name: "Joomla", Category: "CMS", Body: regexp.MustCompile(`(?i)joomla!|/components/com_`)},
	{Name: "Joomla", Category: "CMS", Cookie: "joomla_"},
	{Name: "Ghost", Category: "CMS", Header: "X-Ghost-Cache-Status"},
	{Name: "Ghost", Category: "CMS", Body: regexp.MustCompile(`(?i)ghost\.org`)},
	{Name: "TYPO3", Category: "CMS", Body: regexp.MustCompile(`(?i)typo3`)},
	{Name: "Symfony", Category: "CMS", Header: "X-Debug-Token"},

	// ── E-Commerce ───────────────────────────────────────────────────────────
	{Name: "Magento", Category: "E-Commerce", Header: "X-Magento"},
	{Name: "Magento", Category: "E-Commerce", Cookie: "frontend"},
	{Name: "Magento", Category: "E-Commerce", Body: regexp.MustCompile(`(?i)/skin/frontend/|mageConfig`)},
	{Name: "Shopify", Category: "E-Commerce", Header: "X-ShopId"},
	{Name: "Shopify", Category: "E-Commerce", Body: regexp.MustCompile(`(?i)cdn\.shopify\.com|myshopify\.com`)},
	{Name: "WooCommerce", Category: "E-Commerce", Body: regexp.MustCompile(`(?i)woocommerce`)},
	{Name: "OpenCart", Category: "E-Commerce", Cookie: "OCSESSID"},
	{Name: "PrestaShop", Category: "E-Commerce", Cookie: "PrestaShop"},
	{Name: "BigCommerce", Category: "E-Commerce", Body: regexp.MustCompile(`(?i)bigcommerce\.com`)},

	// ── Frameworks ───────────────────────────────────────────────────────────
	{Name: "Laravel", Category: "Framework", Cookie: "laravel_session"},
	{Name: "Laravel", Category: "Framework", Cookie: "XSRF-TOKEN"},
	{Name: "Django", Category: "Framework", Cookie: "csrftoken"},
	{Name: "Rails", Category: "Framework", Header: "X-Powered-By", Body: regexp.MustCompile(`(?i)phusion passenger`)},
	{Name: "Rails", Category: "Framework", Cookie: "_session_id"},
	{Name: "Spring Boot", Category: "Framework", Header: "X-Application-Context"},
	{Name: "ASP.NET", Category: "Framework", Header: "X-Powered-By", Body: regexp.MustCompile(`(?i)ASP\.NET`)},
	{Name: "ASP.NET", Category: "Framework", Header: "X-AspNet-Version"},
	{Name: "ASP.NET", Category: "Framework", Cookie: "ASP.NET_SessionId"},
	{Name: "PHP", Category: "Language", Header: "X-Powered-By", Body: regexp.MustCompile(`(?i)PHP/`)},
	{Name: "ColdFusion", Category: "Framework", Cookie: "CFID"},
	{Name: "ColdFusion", Category: "Framework", Cookie: "CFTOKEN"},

	// ── JavaScript Frameworks ────────────────────────────────────────────────
	{Name: "React", Category: "JavaScript", Body: regexp.MustCompile(`react\.production\.min\.js|__reactFiber|data-reactroot`)},
	{Name: "Angular", Category: "JavaScript", Body: regexp.MustCompile(`angular\.min\.js|ng-version=|ng-app`)},
	{Name: "Vue.js", Category: "JavaScript", Body: regexp.MustCompile(`vue\.min\.js|__vue__|data-v-[a-f0-9]+`)},
	{Name: "Next.js", Category: "JavaScript", Body: regexp.MustCompile(`_next/static|__NEXT_DATA__`)},
	{Name: "Nuxt.js", Category: "JavaScript", Body: regexp.MustCompile(`__nuxt|_nuxt/`)},
	{Name: "jQuery", Category: "JavaScript", Body: regexp.MustCompile(`jquery\.min\.js|jquery-\d+\.\d+`)},
	{Name: "Svelte", Category: "JavaScript", Body: regexp.MustCompile(`__svelte|svelte\.js`)},

	// ── Web Servers ──────────────────────────────────────────────────────────
	{Name: "Nginx", Category: "Web Server", Header: "Server", Body: regexp.MustCompile(`(?i)^nginx`)},
	{Name: "Apache", Category: "Web Server", Header: "Server", Body: regexp.MustCompile(`(?i)^Apache`)},
	{Name: "IIS", Category: "Web Server", Header: "Server", Body: regexp.MustCompile(`(?i)IIS/`)},
	{Name: "Caddy", Category: "Web Server", Header: "Server", Body: regexp.MustCompile(`(?i)^caddy`)},
	{Name: "LiteSpeed", Category: "Web Server", Header: "Server", Body: regexp.MustCompile(`(?i)litespeed`)},
	{Name: "Gunicorn", Category: "Web Server", Header: "Server", Body: regexp.MustCompile(`(?i)gunicorn`)},
	{Name: "Tomcat", Category: "Web Server", Header: "Server", Body: regexp.MustCompile(`(?i)Apache-Coyote|Tomcat`)},

	// ── CDN ──────────────────────────────────────────────────────────────────
	{Name: "Cloudflare", Category: "CDN", Header: "CF-Ray"},
	{Name: "Cloudflare", Category: "CDN", Header: "Server", Body: regexp.MustCompile(`(?i)cloudflare`)},
	{Name: "Akamai", Category: "CDN", Header: "X-Akamai-Transformed"},
	{Name: "Akamai", Category: "CDN", Header: "X-Check-Cacheable"},
	{Name: "Fastly", Category: "CDN", Header: "Fastly-Debug-Digest"},
	{Name: "AWS CloudFront", Category: "CDN", Header: "X-Amz-Cf-Id"},
	{Name: "Varnish", Category: "CDN", Header: "X-Varnish"},
	{Name: "Azure CDN", Category: "CDN", Header: "X-MSEdge-Ref"},

	// ── WAF / Security ───────────────────────────────────────────────────────
	{Name: "Sucuri", Category: "WAF", Header: "X-Sucuri-ID"},
	{Name: "Imperva", Category: "WAF", Header: "X-Iinfo"},
	{Name: "ModSecurity", Category: "WAF", Header: "X-Powered-By", Body: regexp.MustCompile(`(?i)mod_security`)},

	// ── Analytics ────────────────────────────────────────────────────────────
	{Name: "Google Analytics", Category: "Analytics", Body: regexp.MustCompile(`google-analytics\.com|gtag\(`)},
	{Name: "Hotjar", Category: "Analytics", Body: regexp.MustCompile(`static\.hotjar\.com|hjid`)},
	{Name: "Segment", Category: "Analytics", Body: regexp.MustCompile(`cdn\.segment\.com`)},
}

// DetectTechnologies probes live HTTP services for technology fingerprints.
// It limits itself to one representative URL per host to avoid redundant work.
func DetectTechnologies(httpServices []models.HTTPService, timeoutSec int) []models.Technology {
	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Deduplicate: one URL per host (prefer HTTPS).
	seen := make(map[string]string)
	for _, svc := range httpServices {
		if _, ok := seen[svc.Host]; !ok {
			seen[svc.Host] = svc.URL
		} else if strings.HasPrefix(svc.URL, "https://") {
			seen[svc.Host] = svc.URL // upgrade to HTTPS if found
		}
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 10)
		results []models.Technology
		added   = make(map[string]bool)
	)

	for host, u := range seen {
		wg.Add(1)
		go func(host, rawURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			detected := probeForTech(client, rawURL)

			mu.Lock()
			for _, t := range detected {
				key := host + ":" + t.Name
				if !added[key] {
					added[key] = true
					t.Host = host
					results = append(results, t)
				}
			}
			mu.Unlock()
		}(host, u)
	}

	wg.Wait()
	return results
}

// probeForTech makes a single GET request and applies all signatures.
func probeForTech(client *http.Client, rawURL string) []models.Technology {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Read up to 128 KB of body — enough for tech signatures.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	bodyStr := string(body)

	matched := make(map[string]bool)
	var detected []models.Technology

	for _, sig := range techSignatures {
		if matched[sig.Name] {
			continue
		}

		ok := false

		switch {
		case sig.Cookie != "":
			for _, c := range resp.Cookies() {
				if strings.HasPrefix(c.Name, sig.Cookie) {
					ok = true
					break
				}
			}

		case sig.Header != "" && sig.Body != nil:
			if val := resp.Header.Get(sig.Header); val != "" {
				ok = sig.Body.MatchString(val)
			}

		case sig.Header != "" && sig.Body == nil:
			ok = resp.Header.Get(sig.Header) != ""

		case sig.Body != nil:
			ok = sig.Body.MatchString(bodyStr)
		}

		if ok {
			matched[sig.Name] = true
			detected = append(detected, models.Technology{
				Name:     sig.Name,
				Category: sig.Category,
			})
		}
	}

	return detected
}
