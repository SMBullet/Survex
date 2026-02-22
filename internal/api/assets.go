package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/SMBullet/Survex/internal/db"
)

// AssetEntry represents a discovered asset aggregated across all scans.
type AssetEntry struct {
	Asset     string    `json:"asset"`
	Type      string    `json:"type"`   // subdomain | url | ip
	Client    string    `json:"client"`
	ScanID    string    `json:"scan_id"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type subdomainRaw struct {
	Name string `json:"name"`
}

type httpRaw struct {
	URL  string `json:"url"`
	Host string `json:"host"`
}

// handleListAssets aggregates all discovered assets from completed scans.
//
//	GET /api/v1/assets
func handleListAssets(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)

		jobs, err := database.ListScanJobs(u.UserID, 500)
		if err != nil {
			return fiber.ErrInternalServerError
		}

		// Track first/last seen per asset (keyed by "type|asset").
		type assetMeta struct {
			entry     AssetEntry
			firstSeen time.Time
			lastSeen  time.Time
		}
		index := make(map[string]*assetMeta)

		for _, job := range jobs {
			if job.ReportPath == "" {
				continue
			}
			scanDir := filepath.Dir(job.ReportPath)
			scanTime := job.CreatedAt

			// Aggregate subdomains.json
			if data, err := os.ReadFile(filepath.Join(scanDir, "subdomains.json")); err == nil {
				var subs []subdomainRaw
				if json.Unmarshal(data, &subs) == nil {
					for _, s := range subs {
						if s.Name == "" {
							continue
						}
						key := "subdomain|" + strings.ToLower(s.Name)
						if m, ok := index[key]; ok {
							if scanTime.Before(m.firstSeen) {
								m.firstSeen = scanTime
								m.entry.ScanID = job.ID
							}
							if scanTime.After(m.lastSeen) {
								m.lastSeen = scanTime
							}
						} else {
							index[key] = &assetMeta{
								entry: AssetEntry{
									Asset:  s.Name,
									Type:   "subdomain",
									Client: job.Client,
									ScanID: job.ID,
								},
								firstSeen: scanTime,
								lastSeen:  scanTime,
							}
						}
					}
				}
			}

			// Aggregate http.json for live URLs.
			if data, err := os.ReadFile(filepath.Join(scanDir, "http.json")); err == nil {
				var httpsrvs []httpRaw
				if json.Unmarshal(data, &httpsrvs) == nil {
					for _, h := range httpsrvs {
						asset := h.URL
						if asset == "" {
							asset = h.Host
						}
						if asset == "" {
							continue
						}
						key := "url|" + strings.ToLower(asset)
						if m, ok := index[key]; ok {
							if scanTime.Before(m.firstSeen) {
								m.firstSeen = scanTime
								m.entry.ScanID = job.ID
							}
							if scanTime.After(m.lastSeen) {
								m.lastSeen = scanTime
							}
						} else {
							index[key] = &assetMeta{
								entry: AssetEntry{
									Asset:  asset,
									Type:   "url",
									Client: job.Client,
									ScanID: job.ID,
								},
								firstSeen: scanTime,
								lastSeen:  scanTime,
							}
						}
					}
				}
			}
		}

		// Build final list.
		assets := make([]AssetEntry, 0, len(index))
		for _, m := range index {
			e := m.entry
			e.FirstSeen = m.firstSeen
			e.LastSeen = m.lastSeen
			assets = append(assets, e)
		}

		// Sort: subdomains first, then by asset name.
		sort.Slice(assets, func(i, j int) bool {
			if assets[i].Type != assets[j].Type {
				return assets[i].Type < assets[j].Type
			}
			return assets[i].Asset < assets[j].Asset
		})

		return c.JSON(assets)
	}
}
