package db

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite connection for the web server.
type DB struct {
	conn *sql.DB
}

// User represents a registered user.
type User struct {
	ID           int64
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}

// ScanJob represents a scan request stored in the database.
type ScanJob struct {
	ID           string     `json:"id"`
	UserID       int64      `json:"user_id"`
	Client       string     `json:"client"`
	Targets      string     `json:"targets"`  // comma-separated
	Modules      string     `json:"modules"`  // comma-separated
	Options      string     `json:"options"`  // JSON blob of extra options
	Status       string     `json:"status"`   // queued | running | done | failed | cancelled
	CreatedAt    time.Time  `json:"created_at"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	FindingCount int        `json:"finding_count"`
	MaxSeverity  string     `json:"max_severity"`
	ReportPath   string     `json:"report_path,omitempty"`
	ErrorMsg     string     `json:"error,omitempty"`
}

// UserSettings holds per-user global configuration.
type UserSettings struct {
	UserID      int64     `json:"user_id"`
	ShodanKey   string    `json:"shodan_key"`
	GitHubToken string    `json:"github_token"`
	WebhookURLs string    `json:"webhook_urls"` // JSON array: [{name,url}]
	AIProvider  string    `json:"ai_provider"`  // "anthropic"|"openai"|"deepseek"|"gemini"|"ollama"
	AIAPIKey    string    `json:"ai_api_key"`
	AIModel     string    `json:"ai_model"`
	AIBaseURL   string    `json:"ai_base_url"`  // for Ollama custom endpoints
	UpdatedAt   time.Time `json:"updated_at"`
}

// FalsePositive represents a suppressed finding fingerprint.
type FalsePositive struct {
	ID          int64     `json:"id"`
	UserID      int64     `json:"user_id"`
	Fingerprint string    `json:"fingerprint"` // "asset|title"
	Asset       string    `json:"asset"`
	Title       string    `json:"title"`
	CreatedAt   time.Time `json:"created_at"`
}

// Schedule represents a recurring scan job.
type Schedule struct {
	ID        string     `json:"id"`
	UserID    int64      `json:"user_id"`
	Client    string     `json:"client"`
	Targets   string     `json:"targets"`  // comma-separated
	Modules   string     `json:"modules"`  // comma-separated
	Options   string     `json:"options"`  // JSON blob
	IntervalH int        `json:"interval_h"` // hours between runs
	Enabled   bool       `json:"enabled"`
	NextRun   time.Time  `json:"next_run"`
	LastRun   *time.Time `json:"last_run,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// Open initialises the SQLite database and runs migrations.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	conn.SetMaxOpenConns(1) // SQLite is single-writer
	d := &DB{conn: conn}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return d, nil
}

func (d *DB) Close() error { return d.conn.Close() }

// migrate creates all tables if they don't exist.
func (d *DB) migrate() error {
	stmts := []string{
		`PRAGMA journal_mode=WAL`,

		`CREATE TABLE IF NOT EXISTS users (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			email         TEXT    NOT NULL UNIQUE,
			password_hash TEXT    NOT NULL,
			created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS scan_jobs (
			id            TEXT PRIMARY KEY,
			user_id       INTEGER NOT NULL REFERENCES users(id),
			client        TEXT    NOT NULL,
			targets       TEXT    NOT NULL,
			modules       TEXT    NOT NULL,
			options       TEXT    NOT NULL DEFAULT '{}',
			status        TEXT    NOT NULL DEFAULT 'queued',
			created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
			started_at    DATETIME,
			finished_at   DATETIME,
			finding_count INTEGER DEFAULT 0,
			max_severity  TEXT    DEFAULT '',
			report_path   TEXT    DEFAULT '',
			error_msg     TEXT    DEFAULT ''
		)`,

		`CREATE INDEX IF NOT EXISTS scan_jobs_user_id ON scan_jobs(user_id)`,
		`CREATE INDEX IF NOT EXISTS scan_jobs_status   ON scan_jobs(status)`,

		`CREATE TABLE IF NOT EXISTS user_settings (
			user_id       INTEGER PRIMARY KEY REFERENCES users(id),
			shodan_key    TEXT    NOT NULL DEFAULT '',
			github_token  TEXT    NOT NULL DEFAULT '',
			webhook_urls  TEXT    NOT NULL DEFAULT '[]',
			updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS false_positives (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id       INTEGER NOT NULL REFERENCES users(id),
			fingerprint   TEXT    NOT NULL,
			asset         TEXT    NOT NULL,
			title         TEXT    NOT NULL,
			created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(user_id, fingerprint)
		)`,

		`CREATE INDEX IF NOT EXISTS fp_user_id ON false_positives(user_id)`,

		`CREATE TABLE IF NOT EXISTS schedules (
			id            TEXT    PRIMARY KEY,
			user_id       INTEGER NOT NULL REFERENCES users(id),
			client        TEXT    NOT NULL,
			targets       TEXT    NOT NULL,
			modules       TEXT    NOT NULL,
			options       TEXT    NOT NULL DEFAULT '{}',
			interval_h    INTEGER NOT NULL DEFAULT 24,
			enabled       INTEGER NOT NULL DEFAULT 1,
			next_run      DATETIME NOT NULL,
			last_run      DATETIME,
			created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE INDEX IF NOT EXISTS schedules_user_id  ON schedules(user_id)`,
		`CREATE INDEX IF NOT EXISTS schedules_next_run ON schedules(next_run)`,

		// Cloud credentials: per-user, per-provider saved credentials
		`CREATE TABLE IF NOT EXISTS cloud_credentials (
			user_id    INTEGER NOT NULL REFERENCES users(id),
			provider   TEXT    NOT NULL,
			data_json  TEXT    NOT NULL DEFAULT '{}',
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, provider)
		)`,

		// Cloud scan jobs: async cloud/SCM config review scans
		`CREATE TABLE IF NOT EXISTS cloud_scans (
			id           TEXT    PRIMARY KEY,
			user_id      INTEGER NOT NULL REFERENCES users(id),
			provider     TEXT    NOT NULL,
			status       TEXT    NOT NULL DEFAULT 'queued',
			options_json TEXT    NOT NULL DEFAULT '{}',
			result_json  TEXT    NOT NULL DEFAULT '{}',
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
			started_at   DATETIME,
			finished_at  DATETIME,
			error_msg    TEXT    NOT NULL DEFAULT ''
		)`,

		`CREATE INDEX IF NOT EXISTS cloud_scans_user_id  ON cloud_scans(user_id)`,
		`CREATE INDEX IF NOT EXISTS cloud_scans_provider ON cloud_scans(provider)`,
	}

	for _, stmt := range stmts {
		if _, err := d.conn.Exec(stmt); err != nil {
			return fmt.Errorf("migrate %q: %w", stmt[:min(40, len(stmt))], err)
		}
	}
	return d.migrateAddColumns()
}

// migrateAddColumns adds new columns to existing tables without failing if they already exist.
func (d *DB) migrateAddColumns() error {
	cols := []struct{ table, col, def string }{
		{"user_settings", "ai_provider", "TEXT NOT NULL DEFAULT ''"},
		{"user_settings", "ai_api_key",  "TEXT NOT NULL DEFAULT ''"},
		{"user_settings", "ai_model",    "TEXT NOT NULL DEFAULT ''"},
		{"user_settings", "ai_base_url", "TEXT NOT NULL DEFAULT ''"},
	}
	for _, c := range cols {
		_, err := d.conn.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, c.table, c.col, c.def))
		if err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("add column %s.%s: %w", c.table, c.col, err)
		}
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── Users ──────────────────────────────────────────────────────────────────────

func (d *DB) CreateUser(email, passwordHash string) (int64, error) {
	res, err := d.conn.Exec(
		`INSERT INTO users (email, password_hash) VALUES (?, ?)`,
		email, passwordHash,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) GetUserByEmail(email string) (*User, error) {
	row := d.conn.QueryRow(
		`SELECT id, email, password_hash, created_at FROM users WHERE email = ?`, email,
	)
	u := &User{}
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt); err != nil {
		return nil, err
	}
	return u, nil
}

func (d *DB) GetUserByID(id int64) (*User, error) {
	row := d.conn.QueryRow(
		`SELECT id, email, password_hash, created_at FROM users WHERE id = ?`, id,
	)
	u := &User{}
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt); err != nil {
		return nil, err
	}
	return u, nil
}

// ── Scan Jobs ─────────────────────────────────────────────────────────────────

func (d *DB) CreateScanJob(job *ScanJob) error {
	_, err := d.conn.Exec(
		`INSERT INTO scan_jobs (id, user_id, client, targets, modules, options, status)
		 VALUES (?, ?, ?, ?, ?, ?, 'queued')`,
		job.ID, job.UserID, job.Client, job.Targets, job.Modules, job.Options,
	)
	return err
}

func (d *DB) GetScanJob(id string, userID int64) (*ScanJob, error) {
	row := d.conn.QueryRow(
		`SELECT id, user_id, client, targets, modules, options, status,
		        created_at, started_at, finished_at, finding_count, max_severity, report_path, error_msg
		 FROM scan_jobs WHERE id = ? AND user_id = ?`, id, userID,
	)
	return scanJobFromRow(row)
}

func (d *DB) ListScanJobs(userID int64, limit int) ([]*ScanJob, error) {
	rows, err := d.conn.Query(
		`SELECT id, user_id, client, targets, modules, options, status,
		        created_at, started_at, finished_at, finding_count, max_severity, report_path, error_msg
		 FROM scan_jobs WHERE user_id = ?
		 ORDER BY created_at DESC LIMIT ?`, userID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*ScanJob
	for rows.Next() {
		j, err := scanJobFromRow(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

func (d *DB) UpdateScanStatus(id, status string, startedAt, finishedAt *time.Time) error {
	_, err := d.conn.Exec(
		`UPDATE scan_jobs SET status=?, started_at=?, finished_at=? WHERE id=?`,
		status, startedAt, finishedAt, id,
	)
	return err
}

func (d *DB) UpdateScanResult(id string, findingCount int, maxSeverity, reportPath string) error {
	_, err := d.conn.Exec(
		`UPDATE scan_jobs SET finding_count=?, max_severity=?, report_path=? WHERE id=?`,
		findingCount, maxSeverity, reportPath, id,
	)
	return err
}

func (d *DB) UpdateScanError(id, errMsg string) error {
	now := time.Now()
	_, err := d.conn.Exec(
		`UPDATE scan_jobs SET status='failed', finished_at=?, error_msg=? WHERE id=?`,
		now, errMsg, id,
	)
	return err
}

// scanJobFromRow scans a ScanJob from a *sql.Row or *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanJobFromRow(row rowScanner) (*ScanJob, error) {
	j := &ScanJob{}
	err := row.Scan(
		&j.ID, &j.UserID, &j.Client, &j.Targets, &j.Modules, &j.Options,
		&j.Status, &j.CreatedAt, &j.StartedAt, &j.FinishedAt,
		&j.FindingCount, &j.MaxSeverity, &j.ReportPath, &j.ErrorMsg,
	)
	if err != nil {
		return nil, err
	}
	return j, nil
}

// ── User Settings ──────────────────────────────────────────────────────────────

func (d *DB) GetUserSettings(userID int64) (*UserSettings, error) {
	row := d.conn.QueryRow(
		`SELECT user_id, shodan_key, github_token, webhook_urls,
		        ai_provider, ai_api_key, ai_model, ai_base_url, updated_at
		 FROM user_settings WHERE user_id = ?`, userID,
	)
	s := &UserSettings{}
	err := row.Scan(&s.UserID, &s.ShodanKey, &s.GitHubToken, &s.WebhookURLs,
		&s.AIProvider, &s.AIAPIKey, &s.AIModel, &s.AIBaseURL, &s.UpdatedAt)
	if err == sql.ErrNoRows {
		return &UserSettings{UserID: userID, WebhookURLs: "[]"}, nil
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (d *DB) UpsertUserSettings(s *UserSettings) error {
	_, err := d.conn.Exec(
		`INSERT INTO user_settings
		   (user_id, shodan_key, github_token, webhook_urls, ai_provider, ai_api_key, ai_model, ai_base_url, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(user_id) DO UPDATE SET
		   shodan_key   = excluded.shodan_key,
		   github_token = excluded.github_token,
		   webhook_urls = excluded.webhook_urls,
		   ai_provider  = excluded.ai_provider,
		   ai_api_key   = excluded.ai_api_key,
		   ai_model     = excluded.ai_model,
		   ai_base_url  = excluded.ai_base_url,
		   updated_at   = CURRENT_TIMESTAMP`,
		s.UserID, s.ShodanKey, s.GitHubToken, s.WebhookURLs,
		s.AIProvider, s.AIAPIKey, s.AIModel, s.AIBaseURL,
	)
	return err
}

// ── False Positives ────────────────────────────────────────────────────────────

// MakeFPFingerprint creates a stable fingerprint for an asset+title pair.
func MakeFPFingerprint(asset, title string) string {
	return strings.ToLower(asset) + "|" + strings.ToLower(title)
}

func (d *DB) ListFalsePositives(userID int64) ([]*FalsePositive, error) {
	rows, err := d.conn.Query(
		`SELECT id, user_id, fingerprint, asset, title, created_at
		 FROM false_positives WHERE user_id = ? ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var fps []*FalsePositive
	for rows.Next() {
		fp := &FalsePositive{}
		if err := rows.Scan(&fp.ID, &fp.UserID, &fp.Fingerprint, &fp.Asset, &fp.Title, &fp.CreatedAt); err != nil {
			return nil, err
		}
		fps = append(fps, fp)
	}
	return fps, rows.Err()
}

func (d *DB) AddFalsePositive(userID int64, asset, title string) (*FalsePositive, error) {
	fp := &FalsePositive{
		UserID:      userID,
		Fingerprint: MakeFPFingerprint(asset, title),
		Asset:       asset,
		Title:       title,
	}
	res, err := d.conn.Exec(
		`INSERT OR IGNORE INTO false_positives (user_id, fingerprint, asset, title)
		 VALUES (?, ?, ?, ?)`,
		fp.UserID, fp.Fingerprint, fp.Asset, fp.Title,
	)
	if err != nil {
		return nil, err
	}
	fp.ID, _ = res.LastInsertId()
	fp.CreatedAt = time.Now()
	return fp, nil
}

func (d *DB) RemoveFalsePositive(userID int64, fingerprint string) error {
	_, err := d.conn.Exec(
		`DELETE FROM false_positives WHERE user_id = ? AND fingerprint = ?`,
		userID, fingerprint,
	)
	return err
}

// GetFalsePositiveSet returns a set of fingerprints for the given user (for fast lookup).
func (d *DB) GetFalsePositiveSet(userID int64) (map[string]struct{}, error) {
	rows, err := d.conn.Query(
		`SELECT fingerprint FROM false_positives WHERE user_id = ?`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	set := make(map[string]struct{})
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		set[fp] = struct{}{}
	}
	return set, rows.Err()
}

// ── Schedules ──────────────────────────────────────────────────────────────────

func (d *DB) CreateSchedule(s *Schedule) error {
	_, err := d.conn.Exec(
		`INSERT INTO schedules (id, user_id, client, targets, modules, options, interval_h, enabled, next_run)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.UserID, s.Client, s.Targets, s.Modules, s.Options, s.IntervalH, boolToInt(s.Enabled), s.NextRun,
	)
	return err
}

func (d *DB) ListSchedules(userID int64) ([]*Schedule, error) {
	rows, err := d.conn.Query(
		`SELECT id, user_id, client, targets, modules, options, interval_h, enabled, next_run, last_run, created_at
		 FROM schedules WHERE user_id = ? ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var schedules []*Schedule
	for rows.Next() {
		s, err := scheduleFromRow(rows)
		if err != nil {
			return nil, err
		}
		schedules = append(schedules, s)
	}
	return schedules, rows.Err()
}

func (d *DB) GetSchedule(id string, userID int64) (*Schedule, error) {
	row := d.conn.QueryRow(
		`SELECT id, user_id, client, targets, modules, options, interval_h, enabled, next_run, last_run, created_at
		 FROM schedules WHERE id = ? AND user_id = ?`, id, userID,
	)
	return scheduleFromRow(row)
}

func (d *DB) UpdateScheduleEnabled(id string, userID int64, enabled bool) error {
	_, err := d.conn.Exec(
		`UPDATE schedules SET enabled = ? WHERE id = ? AND user_id = ?`,
		boolToInt(enabled), id, userID,
	)
	return err
}

func (d *DB) UpdateScheduleNextRun(id string, nextRun time.Time, lastRun time.Time) error {
	_, err := d.conn.Exec(
		`UPDATE schedules SET next_run = ?, last_run = ? WHERE id = ?`,
		nextRun, lastRun, id,
	)
	return err
}

func (d *DB) DeleteSchedule(id string, userID int64) error {
	_, err := d.conn.Exec(
		`DELETE FROM schedules WHERE id = ? AND user_id = ?`, id, userID,
	)
	return err
}

// GetDueSchedules returns enabled schedules whose next_run is in the past.
func (d *DB) GetDueSchedules() ([]*Schedule, error) {
	rows, err := d.conn.Query(
		`SELECT id, user_id, client, targets, modules, options, interval_h, enabled, next_run, last_run, created_at
		 FROM schedules WHERE enabled = 1 AND next_run <= ?`, time.Now(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var schedules []*Schedule
	for rows.Next() {
		s, err := scheduleFromRow(rows)
		if err != nil {
			return nil, err
		}
		schedules = append(schedules, s)
	}
	return schedules, rows.Err()
}

type scheduleRowScanner interface {
	Scan(dest ...any) error
}

func scheduleFromRow(row scheduleRowScanner) (*Schedule, error) {
	s := &Schedule{}
	var enabled int
	err := row.Scan(
		&s.ID, &s.UserID, &s.Client, &s.Targets, &s.Modules, &s.Options,
		&s.IntervalH, &enabled, &s.NextRun, &s.LastRun, &s.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	s.Enabled = enabled == 1
	return s, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
