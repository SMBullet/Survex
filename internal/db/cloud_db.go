package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// ── Cloud Credentials ─────────────────────────────────────────────────────────

// GetCloudCredentials returns the saved credentials for a provider, or nil if none.
func (d *DB) GetCloudCredentials(userID int64, provider string) (*models.CloudCredentials, error) {
	row := d.conn.QueryRow(
		`SELECT user_id, provider, data_json, updated_at
		 FROM cloud_credentials WHERE user_id = ? AND provider = ?`,
		userID, provider,
	)
	c := &models.CloudCredentials{}
	var dataJSON string
	err := row.Scan(&c.UserID, &c.Provider, &dataJSON, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get cloud credentials: %w", err)
	}
	if err := json.Unmarshal([]byte(dataJSON), &c.Data); err != nil {
		return nil, fmt.Errorf("parse cloud credentials: %w", err)
	}
	return c, nil
}

// GetAllCloudCredentials returns saved credentials for all providers for a user.
// Returns a map of provider → {field→value}.
func (d *DB) GetAllCloudCredentials(userID int64) (map[string]map[string]string, error) {
	rows, err := d.conn.Query(
		`SELECT provider, data_json FROM cloud_credentials WHERE user_id = ?`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]map[string]string)
	for rows.Next() {
		var provider, dataJSON string
		if err := rows.Scan(&provider, &dataJSON); err != nil {
			return nil, err
		}
		var data map[string]string
		if err := json.Unmarshal([]byte(dataJSON), &data); err != nil {
			continue
		}
		// Redact sensitive fields before returning to frontend
		redactCloudCreds(provider, data)
		result[provider] = data
	}
	return result, rows.Err()
}

// UpsertCloudCredentials saves or updates credentials for a provider.
func (d *DB) UpsertCloudCredentials(userID int64, provider string, data map[string]string) error {
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal cloud credentials: %w", err)
	}
	_, err = d.conn.Exec(
		`INSERT INTO cloud_credentials (user_id, provider, data_json, updated_at)
		 VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(user_id, provider) DO UPDATE SET
		   data_json  = excluded.data_json,
		   updated_at = CURRENT_TIMESTAMP`,
		userID, provider, string(b),
	)
	return err
}

// DeleteCloudCredentials removes saved credentials for a provider.
func (d *DB) DeleteCloudCredentials(userID int64, provider string) error {
	_, err := d.conn.Exec(
		`DELETE FROM cloud_credentials WHERE user_id = ? AND provider = ?`,
		userID, provider,
	)
	return err
}

// redactCloudCreds replaces sensitive field values with a redaction marker.
// This is used before sending credentials to the frontend.
func redactCloudCreds(provider string, data map[string]string) {
	sensitiveFields := map[string][]string{
		"aws":    {"secret_access_key", "session_token"},
		"azure":  {"client_secret"},
		"gcp":    {"service_account_json"},
		"github": {"token"},
		"gitlab": {"token"},
	}
	for _, field := range sensitiveFields[provider] {
		if v, ok := data[field]; ok && v != "" {
			data[field] = "••••••••"
		}
	}
}

// ── Cloud Scans ───────────────────────────────────────────────────────────────

// CloudScanRow is the DB representation of a cloud scan job.
type CloudScanRow struct {
	ID          string
	UserID      int64
	Provider    string
	Status      string
	OptionsJSON string
	ResultJSON  string
	CreatedAt   time.Time
	StartedAt   *time.Time
	FinishedAt  *time.Time
	ErrorMsg    string
}

// CreateCloudScan inserts a new cloud scan job with status "queued".
func (d *DB) CreateCloudScan(id string, userID int64, provider, optionsJSON string) error {
	_, err := d.conn.Exec(
		`INSERT INTO cloud_scans (id, user_id, provider, status, options_json, result_json, created_at)
		 VALUES (?, ?, ?, 'queued', ?, '{}', CURRENT_TIMESTAMP)`,
		id, userID, provider, optionsJSON,
	)
	return err
}

// GetCloudScan retrieves a cloud scan by ID for a specific user.
func (d *DB) GetCloudScan(id string, userID int64) (*CloudScanRow, error) {
	row := d.conn.QueryRow(
		`SELECT id, user_id, provider, status, options_json, result_json,
		        created_at, started_at, finished_at, error_msg
		 FROM cloud_scans WHERE id = ? AND user_id = ?`, id, userID,
	)
	return scanCloudRow(row)
}

// GetCloudScanByID retrieves a cloud scan by ID (no user filter — for internal use by worker).
func (d *DB) GetCloudScanByID(id string) (*CloudScanRow, error) {
	row := d.conn.QueryRow(
		`SELECT id, user_id, provider, status, options_json, result_json,
		        created_at, started_at, finished_at, error_msg
		 FROM cloud_scans WHERE id = ?`, id,
	)
	return scanCloudRow(row)
}

// ListCloudScans returns the most recent cloud scans for a user, optionally filtered by provider.
func (d *DB) ListCloudScans(userID int64, provider string, limit int) ([]*CloudScanRow, error) {
	var rows *sql.Rows
	var err error
	if provider != "" {
		rows, err = d.conn.Query(
			`SELECT id, user_id, provider, status, options_json, result_json,
			        created_at, started_at, finished_at, error_msg
			 FROM cloud_scans WHERE user_id = ? AND provider = ?
			 ORDER BY created_at DESC LIMIT ?`, userID, provider, limit,
		)
	} else {
		rows, err = d.conn.Query(
			`SELECT id, user_id, provider, status, options_json, result_json,
			        created_at, started_at, finished_at, error_msg
			 FROM cloud_scans WHERE user_id = ?
			 ORDER BY created_at DESC LIMIT ?`, userID, limit,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*CloudScanRow
	for rows.Next() {
		j, err := scanCloudRow(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

// UpdateCloudScanStatus updates status and timestamps.
func (d *DB) UpdateCloudScanStatus(id, status string, startedAt, finishedAt *time.Time) error {
	_, err := d.conn.Exec(
		`UPDATE cloud_scans SET status=?, started_at=?, finished_at=? WHERE id=?`,
		status, startedAt, finishedAt, id,
	)
	return err
}

// UpdateCloudScanResult stores the final result JSON and marks the scan done.
func (d *DB) UpdateCloudScanResult(id, resultJSON string) error {
	now := time.Now()
	_, err := d.conn.Exec(
		`UPDATE cloud_scans SET status='done', finished_at=?, result_json=? WHERE id=?`,
		now, resultJSON, id,
	)
	return err
}

// UpdateCloudScanError marks a cloud scan as failed with an error message.
func (d *DB) UpdateCloudScanError(id, errMsg string) error {
	now := time.Now()
	_, err := d.conn.Exec(
		`UPDATE cloud_scans SET status='failed', finished_at=?, error_msg=? WHERE id=?`,
		now, errMsg, id,
	)
	return err
}

type cloudRowScanner interface {
	Scan(dest ...any) error
}

func scanCloudRow(row cloudRowScanner) (*CloudScanRow, error) {
	j := &CloudScanRow{}
	err := row.Scan(
		&j.ID, &j.UserID, &j.Provider, &j.Status,
		&j.OptionsJSON, &j.ResultJSON,
		&j.CreatedAt, &j.StartedAt, &j.FinishedAt, &j.ErrorMsg,
	)
	if err != nil {
		return nil, err
	}
	return j, nil
}
