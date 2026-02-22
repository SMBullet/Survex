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

	// Mark as running
	now := time.Now()
	if err := q.db.UpdateCloudScanStatus(id, "running", &now, nil); err != nil {
		log.Printf("[cloud-queue] failed to mark job %s running: %v", id, err)
		return
	}

	log.Printf("[cloud-queue] starting %s scan (job %s)", row.Provider, id)

	// Parse options — contains credentials + scan config
	var opts map[string]interface{}
	if err := json.Unmarshal([]byte(row.OptionsJSON), &opts); err != nil {
		q.fail(id, "failed to parse scan options: "+err.Error())
		return
	}

	// Simple logger that writes to the server log (can be extended with WS streaming)
	logFn := func(msg string) {
		log.Printf("[cloud-queue][%s] %s", id, msg)
	}

	var result *models.CloudScanResult
	var runErr error

	switch row.Provider {
	case "aws":
		creds := tools.AWSCreds{
			AccessKeyID:     strField(opts, "access_key_id"),
			SecretAccessKey: strField(opts, "secret_access_key"),
			SessionToken:    strField(opts, "session_token"),
			RoleARN:         strField(opts, "role_arn"),
			Region:          strField(opts, "region"),
		}
		findings, accountID, err := tools.RunAWSReview(ctx, creds, logFn)
		runErr = err
		if err == nil {
			result = buildCloudResult(id, "aws", accountID, findings)
		}

	case "azure":
		creds := tools.AzureCreds{
			TenantID:       strField(opts, "tenant_id"),
			ClientID:       strField(opts, "client_id"),
			ClientSecret:   strField(opts, "client_secret"),
			SubscriptionID: strField(opts, "subscription_id"),
		}
		findings, err := tools.RunAzureReview(ctx, creds, logFn)
		runErr = err
		if err == nil {
			result = buildCloudResult(id, "azure", creds.SubscriptionID, findings)
		}

	case "gcp":
		creds := tools.GCPCreds{
			ServiceAccountJSON: strField(opts, "service_account_json"),
			ProjectID:          strField(opts, "project_id"),
		}
		findings, projectID, err := tools.RunGCPReview(ctx, creds, logFn)
		runErr = err
		if err == nil {
			result = buildCloudResult(id, "gcp", projectID, findings)
		}

	case "github":
		creds := tools.GitHubReviewCreds{
			Token: strField(opts, "token"),
			Org:   strField(opts, "org"),
			Repos: strField(opts, "repos"),
		}
		findings, err := tools.RunGitHubReview(ctx, creds, logFn)
		runErr = err
		if err == nil {
			result = buildCloudResult(id, "github", creds.Org, findings)
		}

	case "gitlab":
		creds := tools.GitLabReviewCreds{
			Token: strField(opts, "token"),
			URL:   strField(opts, "url"),
			Group: strField(opts, "group"),
		}
		findings, err := tools.RunGitLabReview(ctx, creds, logFn)
		runErr = err
		if err == nil {
			result = buildCloudResult(id, "gitlab", creds.Group, findings)
		}

	default:
		q.fail(id, "unknown provider: "+row.Provider)
		return
	}

	if runErr != nil {
		q.fail(id, runErr.Error())
		return
	}

	// Persist result
	b, err := json.Marshal(result)
	if err != nil {
		q.fail(id, "marshal result: "+err.Error())
		return
	}
	if err := q.db.UpdateCloudScanResult(id, string(b)); err != nil {
		log.Printf("[cloud-queue] failed to save result for job %s: %v", id, err)
	}
	log.Printf("[cloud-queue] job %s done — %d findings", id, len(result.Findings))
}

func (q *CloudQueue) fail(id, msg string) {
	log.Printf("[cloud-queue] job %s failed: %s", id, msg)
	_ = q.db.UpdateCloudScanError(id, msg)
}

func buildCloudResult(scanID, provider, accountID string, findings []models.CloudFinding) *models.CloudScanResult {
	if findings == nil {
		findings = []models.CloudFinding{}
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
		Findings:  findings,
		Summary:   summary,
		ChecksRun: len(findings), // approximate
	}
}

func strField(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
