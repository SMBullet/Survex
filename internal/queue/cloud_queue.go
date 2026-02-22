package queue

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/SMBullet/Survex/internal/db"
	"github.com/SMBullet/Survex/internal/models"
	"github.com/SMBullet/Survex/internal/tools"
)

// CloudQueue manages async cloud/SCM configuration review scan jobs.
type CloudQueue struct {
	ch chan string // job IDs
	db *db.DB
}

// NewCloudQueue creates a new cloud scan queue with a buffer of 256 jobs.
func NewCloudQueue(database *db.DB) *CloudQueue {
	return &CloudQueue{
		ch: make(chan string, 256),
		db: database,
	}
}

// Enqueue adds a cloud scan job ID to the queue.
func (q *CloudQueue) Enqueue(id string) {
	q.ch <- id
}

// Start runs the cloud queue worker in a goroutine. It processes one job at a time.
func (q *CloudQueue) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case id := <-q.ch:
				q.process(ctx, id)
			}
		}
	}()
}

func (q *CloudQueue) process(ctx context.Context, id string) {
	row, err := q.db.GetCloudScanByID(id)
	if err != nil {
		log.Printf("[cloud-queue] failed to load job %s: %v", id, err)
		return
	}

	now := time.Now()
	if err := q.db.UpdateCloudScanStatus(id, "running", &now, nil); err != nil {
		log.Printf("[cloud-queue] failed to mark job %s running: %v", id, err)
		return
	}

	log.Printf("[cloud-queue] starting %s scan (job %s)", row.Provider, id)

	var opts map[string]interface{}
	if err := json.Unmarshal([]byte(row.OptionsJSON), &opts); err != nil {
		q.fail(id, "failed to parse scan options: "+err.Error())
		return
	}

	// Convert interface{} map to string map for tool functions.
	creds := make(map[string]string, len(opts))
	for k, v := range opts {
		if s, ok := v.(string); ok {
			creds[k] = s
		}
	}

	logFn := func(msg string) {
		log.Printf("[cloud-queue][%s] %s", id, msg)
	}

	var result *models.CloudScanResult
	var runErr error

	switch row.Provider {

	// ── Cloud providers: asset discovery (cloudlist) + security audit (prowler) ──
	case "aws", "azure", "gcp":
		provider := row.Provider
		mode := creds["mode"] // "discovery" | "audit" | "" / "both"

		var assets []models.CloudAsset
		var findings []models.CloudFinding
		var accountID string
		var clErr, prErr error

		// Asset discovery via cloudlist.
		if mode != "audit" {
			assets, clErr = tools.RunCloudlist(ctx, provider, creds, logFn)
			if clErr != nil {
				logFn("cloudlist unavailable: " + clErr.Error())
			}
		}

		// Security audit via prowler.
		if mode != "discovery" {
			findings, accountID, prErr = tools.RunProwler(ctx, provider, creds, logFn)
			if prErr != nil {
				logFn("prowler unavailable: " + prErr.Error())
			}
		}

		// Fail only if every requested tool failed.
		allFailed := (mode == "discovery" && clErr != nil) ||
			(mode == "audit" && prErr != nil) ||
			(mode != "discovery" && mode != "audit" && clErr != nil && prErr != nil)
		if allFailed {
			runErr = clErr
			if runErr == nil {
				runErr = prErr
			}
			break
		}

		result = buildCloudResult(id, provider, accountID, findings, assets)

	// ── SCM providers: custom Go implementations ────────────────────────────────
	case "github":
		crd := tools.GitHubReviewCreds{
			Token: creds["token"],
			Org:   creds["org"],
			Repos: creds["repos"],
		}
		findings, err := tools.RunGitHubReview(ctx, crd, logFn)
		runErr = err
		if err == nil {
			result = buildCloudResult(id, "github", crd.Org, findings, nil)
		}

	case "gitlab":
		crd := tools.GitLabReviewCreds{
			Token: creds["token"],
			URL:   creds["url"],
			Group: creds["group"],
		}
		findings, err := tools.RunGitLabReview(ctx, crd, logFn)
		runErr = err
		if err == nil {
			result = buildCloudResult(id, "gitlab", crd.Group, findings, nil)
		}

	default:
		q.fail(id, "unknown provider: "+row.Provider)
		return
	}

	if runErr != nil {
		q.fail(id, runErr.Error())
		return
	}

	b, err := json.Marshal(result)
	if err != nil {
		q.fail(id, "marshal result: "+err.Error())
		return
	}
	if err := q.db.UpdateCloudScanResult(id, string(b)); err != nil {
		log.Printf("[cloud-queue] failed to save result for job %s: %v", id, err)
	}
	log.Printf("[cloud-queue] job %s done — %d assets, %d findings", id, len(result.Assets), len(result.Findings))
}

func (q *CloudQueue) fail(id, msg string) {
	log.Printf("[cloud-queue] job %s failed: %s", id, msg)
	_ = q.db.UpdateCloudScanError(id, msg)
}

func buildCloudResult(scanID, provider, accountID string, findings []models.CloudFinding, assets []models.CloudAsset) *models.CloudScanResult {
	if findings == nil {
		findings = []models.CloudFinding{}
	}
	if assets == nil {
		assets = []models.CloudAsset{}
	}
	summary := map[string]int{
		"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
	}
	for _, f := range findings {
		summary[f.Severity]++
	}
	return &models.CloudScanResult{
		Provider:  provider,
		AccountID: accountID,
		ScanID:    scanID,
		Assets:    assets,
		Findings:  findings,
		Summary:   summary,
		ChecksRun: len(findings),
	}
}
