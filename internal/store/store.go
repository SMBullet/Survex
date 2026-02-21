package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/SMBullet/Survex/internal/models"
	_ "modernc.org/sqlite"
)

// Store wraps a SQLite database for persisting scan results.
// Use Open() to create a Store, and Close() when done.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at the given path and runs migrations.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS scans (
			id          TEXT PRIMARY KEY,
			client      TEXT NOT NULL,
			target      TEXT NOT NULL,
			started_at  DATETIME NOT NULL,
			finished_at DATETIME,
			status      TEXT NOT NULL,
			result_json TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_scans_client ON scans(client, started_at DESC);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Save stores a complete scan result in the database.
func (s *Store) Save(client string, result *models.ScanResult) error {
	b, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshalling result: %w", err)
	}

	finishedAt := (*time.Time)(nil)
	if result.Scan.FinishedAt != nil {
		finishedAt = result.Scan.FinishedAt
	}

	_, err = s.db.Exec(`
		INSERT OR REPLACE INTO scans (id, client, target, started_at, finished_at, status, result_json)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		result.Scan.ID,
		client,
		result.Scan.Target,
		result.Scan.StartedAt,
		finishedAt,
		result.Scan.Status,
		string(b),
	)
	return err
}

// LoadLast retrieves the most recent completed scan for a client.
// Returns nil, nil if no previous scan exists.
func (s *Store) LoadLast(client string) (*models.ScanResult, error) {
	row := s.db.QueryRow(`
		SELECT result_json FROM scans
		WHERE client = ? AND status = 'done'
		ORDER BY started_at DESC
		LIMIT 1`, client)

	var raw string
	if err := row.Scan(&raw); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("querying last scan: %w", err)
	}

	var result models.ScanResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parsing stored result: %w", err)
	}

	return &result, nil
}

// ListScans returns scan metadata (no full result) for a client, newest first.
func (s *Store) ListScans(client string, limit int) ([]models.Scan, error) {
	rows, err := s.db.Query(`
		SELECT id, client, target, started_at, finished_at, status
		FROM scans WHERE client = ?
		ORDER BY started_at DESC LIMIT ?`, client, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []models.Scan
	for rows.Next() {
		var sc models.Scan
		var finishedAt sql.NullTime
		if err := rows.Scan(&sc.ID, &sc.Client, &sc.Target, &sc.StartedAt, &finishedAt, &sc.Status); err != nil {
			return nil, err
		}
		if finishedAt.Valid {
			sc.FinishedAt = &finishedAt.Time
		}
		scans = append(scans, sc)
	}
	return scans, rows.Err()
}

// ────────────────────────────────────────────────────────────────────────────────
// Package-level convenience functions (backward compatible).
// These exist so callers can use a default global store without changing every
// call site immediately.
// ────────────────────────────────────────────────────────────────────────────────

var defaultStore *Store

// Init opens the database at the given path and sets the default store.
func Init(path string) error {
	s, err := Open(path)
	if err != nil {
		return err
	}
	defaultStore = s
	return nil
}

// Save stores a result using the default store.
func Save(client string, result *models.ScanResult) error {
	if defaultStore == nil {
		return fmt.Errorf("store not initialized")
	}
	return defaultStore.Save(client, result)
}

// LoadLast retrieves the last scan using the default store.
func LoadLast(client string) (*models.ScanResult, error) {
	if defaultStore == nil {
		return nil, fmt.Errorf("store not initialized")
	}
	return defaultStore.LoadLast(client)
}

// ListScans lists scans using the default store.
func ListScans(client string, limit int) ([]models.Scan, error) {
	if defaultStore == nil {
		return nil, fmt.Errorf("store not initialized")
	}
	return defaultStore.ListScans(client, limit)
}
