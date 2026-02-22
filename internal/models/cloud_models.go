package models

import "time"

// CloudFinding represents a single security finding from a cloud/SCM config review.
type CloudFinding struct {
	Provider    string `json:"provider"`    // aws|azure|gcp|github|gitlab
	Service     string `json:"service"`     // S3|IAM|EC2|BlobStorage|NSG|etc
	Resource    string `json:"resource"`    // resource name/ID
	Check       string `json:"check"`       // human-readable check name
	Detail      string `json:"detail"`      // additional context
	Severity    string `json:"severity"`    // critical|high|medium|low|info
	Remediation string `json:"remediation"` // suggested fix
}

// CloudAsset is a cloud resource discovered by cloudlist (IP, hostname, instance, etc.).
type CloudAsset struct {
	Provider string `json:"provider"`          // aws|azure|gcp
	IP       string `json:"ip,omitempty"`       // IPv4 address
	Host     string `json:"host,omitempty"`     // hostname or DNS name
	Public   bool   `json:"public"`             // true if publicly reachable
}

// CloudScanResult is the aggregated result of a cloud/SCM config review scan.
type CloudScanResult struct {
	Provider  string         `json:"provider"`
	AccountID string         `json:"account_id,omitempty"` // AWS account / Azure subscription / GCP project
	ScanID    string         `json:"scan_id"`
	Assets    []CloudAsset   `json:"assets,omitempty"`   // discovered by cloudlist
	Findings  []CloudFinding `json:"findings"`
	Summary   map[string]int `json:"summary"`    // severity → count
	ChecksRun int            `json:"checks_run"` // total checks attempted
}

// CloudScanJob represents an async cloud scan job persisted in the database.
type CloudScanJob struct {
	ID         string           `json:"id"`
	UserID     int64            `json:"user_id"`
	Provider   string           `json:"provider"` // aws|azure|gcp|github|gitlab
	Status     string           `json:"status"`   // queued|running|done|failed
	CreatedAt  time.Time        `json:"created_at"`
	StartedAt  *time.Time       `json:"started_at,omitempty"`
	FinishedAt *time.Time       `json:"finished_at,omitempty"`
	Result     *CloudScanResult `json:"result,omitempty"`
	ErrorMsg   string           `json:"error,omitempty"`
}

// CloudCredentials holds per-provider saved credentials for a user.
type CloudCredentials struct {
	UserID    int64             `json:"user_id"`
	Provider  string            `json:"provider"`
	Data      map[string]string `json:"data"`      // field name → value
	UpdatedAt time.Time         `json:"updated_at"`
}
