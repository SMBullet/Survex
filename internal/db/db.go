package db

import (
	"database/sql"
	"fmt"
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
	ID        string    `json:"id"`
	UserID    int64     `json:"user_id"`
	Client    string    `json:"client"`
	Targets   string    `json:"targets"`   // comma-separated
	Modules   string    `json:"modules"`   // comma-separated
	Options   string    `json:"options"`   // JSON blob of extra options
	Status    string    `json:"status"`    // queued | running | done | failed | cancelled
	CreatedAt time.Time `json:"created_at"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	FindingCount int    `json:"finding_count"`
	MaxSeverity  string `json:"max_severity"`
	ReportPath   string `json:"report_path,omitempty"`
	ErrorMsg     string `json:"error,omitempty"`
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
	_, err := d.conn.Exec(`
		PRAGMA journal_mode=WAL;

		CREATE TABLE IF NOT EXISTS users (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			email         TEXT    NOT NULL UNIQUE,
			password_hash TEXT    NOT NULL,
			created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS scan_jobs (
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
		);

		CREATE INDEX IF NOT EXISTS scan_jobs_user_id ON scan_jobs(user_id);
		CREATE INDEX IF NOT EXISTS scan_jobs_status   ON scan_jobs(status);
	`)
	return err
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
