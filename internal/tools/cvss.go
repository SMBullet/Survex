package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// ── NVD API types ─────────────────────────────────────────────────────────────

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			Metrics struct {
				CvssMetricV31 []nvdMetric `json:"cvssMetricV31"`
				CvssMetricV30 []nvdMetric `json:"cvssMetricV30"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdMetric struct {
	Type     string `json:"type"` // "Primary" | "Secondary"
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

// ── Cache & rate limiter ──────────────────────────────────────────────────────

type cvssEntry struct {
	Score  float64
	Vector string
}

var (
	cvssCache  sync.Map
	nvdMu      sync.Mutex
	nvdLast    time.Time
	nvdGap     = 7 * time.Second // 5 req/30s unauthenticated → ~6s; 7s for safety
	nvdAPIKey  string
	nvdClient  = &http.Client{Timeout: 12 * time.Second}
)

// SetNVDAPIKey configures an optional NVD API key.
// With a key, the rate limit increases from 5 req/30s to 50 req/30s.
func SetNVDAPIKey(key string) {
	nvdMu.Lock()
	defer nvdMu.Unlock()
	nvdAPIKey = key
	if key != "" {
		nvdGap = 700 * time.Millisecond // ~50 req/30s
	}
}

func nvdThrottle() {
	nvdMu.Lock()
	defer nvdMu.Unlock()
	if elapsed := time.Since(nvdLast); elapsed < nvdGap {
		time.Sleep(nvdGap - elapsed)
	}
	nvdLast = time.Now()
}

// LookupCVSS queries the NVD REST API v2 for the CVSS v3.1 base score and
// vector of a CVE ID (e.g. "CVE-2021-44228"). Results are cached in memory.
// Returns (0, "", nil) when the CVE has no CVSS v3 data.
func LookupCVSS(ctx context.Context, cveID string) (float64, string, error) {
	if cached, ok := cvssCache.Load(cveID); ok {
		e := cached.(cvssEntry)
		return e.Score, e.Vector, nil
	}

	nvdThrottle()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="+cveID,
		nil,
	)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "Survex-ASM/1.0")
	if nvdAPIKey != "" {
		req.Header.Set("apiKey", nvdAPIKey)
	}

	resp, err := nvdClient.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("NVD lookup %s: %w", cveID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("NVD returned HTTP %d for %s", resp.StatusCode, cveID)
	}

	var nvd nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvd); err != nil {
		return 0, "", fmt.Errorf("NVD decode error for %s: %w", cveID, err)
	}

	var score float64
	var vector string
	if len(nvd.Vulnerabilities) > 0 {
		m := nvd.Vulnerabilities[0].CVE.Metrics
		// Prefer CVSS 3.1 (Primary first), fallback to 3.0.
		for _, tier := range [][]nvdMetric{m.CvssMetricV31, m.CvssMetricV30} {
			if len(tier) == 0 {
				continue
			}
			chosen := tier[0]
			for _, x := range tier {
				if x.Type == "Primary" {
					chosen = x
					break
				}
			}
			score = chosen.CVSSData.BaseScore
			vector = chosen.CVSSData.VectorString
			break
		}
	}

	cvssCache.Store(cveID, cvssEntry{Score: score, Vector: vector})
	return score, vector, nil
}

// EnrichCVSS performs best-effort NVD lookups for a list of CVE IDs and returns
// a map of CVE ID → CVSSData. Lookups are sequential (to respect NVD rate limits).
// The context may be cancelled early, in which case already-cached results are still returned.
func EnrichCVSS(ctx context.Context, cveIDs []string) map[string]models.CVSSData {
	// Deduplicate.
	seen := make(map[string]struct{}, len(cveIDs))
	uniq := cveIDs[:0]
	for _, id := range cveIDs {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			uniq = append(uniq, id)
		}
	}

	out := make(map[string]models.CVSSData, len(uniq))
	for _, id := range uniq {
		if ctx.Err() != nil {
			break
		}
		score, vector, err := LookupCVSS(ctx, id)
		if err != nil {
			// Best-effort: skip failures.
			continue
		}
		out[id] = models.CVSSData{Score: score, Vector: vector}
	}
	return out
}

// ── CVSS v3.1 Base Score Calculator ──────────────────────────────────────────

// CalculateCVSSScore computes the CVSS v3.0/3.1 base score from a vector string.
// Returns 0 for an empty or malformed vector.
//
// Example: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" → 9.8
func CalculateCVSSScore(vector string) float64 {
	if vector == "" {
		return 0
	}

	// Strip version prefix: "CVSS:3.1/" etc.
	slash := strings.Index(vector, "/")
	if slash < 0 {
		return 0
	}
	body := vector[slash+1:]

	m := make(map[string]string, 8)
	for _, tok := range strings.Split(body, "/") {
		if kv := strings.SplitN(tok, ":", 2); len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}

	// Metric numeric tables (CVSS v3.1 spec §7.1).
	avMap  := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	acMap  := map[string]float64{"L": 0.77, "H": 0.44}
	prMapU := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27} // Scope Unchanged
	prMapC := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50} // Scope Changed
	uiMap  := map[string]float64{"N": 0.85, "R": 0.62}
	impMap := map[string]float64{"N": 0.00, "L": 0.22, "H": 0.56}

	av, ok1 := avMap[m["AV"]]
	ac, ok2 := acMap[m["AC"]]
	ui, ok3 := uiMap[m["UI"]]
	c, ok4  := impMap[m["C"]]
	i, ok5  := impMap[m["I"]]
	a, ok6  := impMap[m["A"]]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) {
		return 0
	}

	scope := m["S"]
	var pr float64
	var ok bool
	if scope == "C" {
		pr, ok = prMapC[m["PR"]]
	} else {
		pr, ok = prMapU[m["PR"]]
	}
	if !ok {
		return 0
	}

	// ISC (Impact Sub-Score)
	iscBase := 1.0 - (1.0-c)*(1.0-i)*(1.0-a)
	var isc float64
	if scope == "U" {
		isc = 6.42 * iscBase
	} else {
		isc = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	}
	if isc <= 0 {
		return 0
	}

	exploitability := 8.22 * av * ac * pr * ui

	var base float64
	if scope == "U" {
		base = math.Min(isc+exploitability, 10)
	} else {
		base = math.Min(1.08*(isc+exploitability), 10)
	}
	return cvssRoundup(base)
}

// cvssRoundup rounds up to the nearest 0.1 as required by the CVSS v3.1 spec.
func cvssRoundup(x float64) float64 {
	return math.Ceil(x*10) / 10
}

// CVSSSeverityLabel converts a CVSS v3.x base score to a qualitative severity label.
func CVSSSeverityLabel(score float64) string {
	switch {
	case score <= 0:
		return "info"
	case score < 4.0:
		return "low"
	case score < 7.0:
		return "medium"
	case score < 9.0:
		return "high"
	default:
		return "critical"
	}
}
