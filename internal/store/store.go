package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/SMBullet/Survex/internal/models"
	_ "modernc.org/sqlite"
)

var db *sql.DB

// Init opens (or creates) the SQLite database and runs migrations.
func Init(path string) error {
	var err error
	db, err = sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
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
	return err
}

// Save stores a complete scan result in the database.
func Save(client string, result *models.ScanResult) error {
	if db == nil {
		return fmt.Errorf("store not initialized")
	}

	b, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshalling result: %w", err)
	}

	finishedAt := (*time.Time)(nil)
	if result.Scan.FinishedAt != nil {
		finishedAt = result.Scan.FinishedAt
	}

	_, err = db.Exec(`
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
func LoadLast(client string) (*models.ScanResult, error) {
	if db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	row := db.QueryRow(`
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
func ListScans(client string, limit int) ([]models.Scan, error) {
	if db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	rows, err := db.Query(`
		SELECT id, client, target, started_at, finished_at, status
		FROM scans WHERE client = ?
		ORDER BY started_at DESC LIMIT ?`, client, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []models.Scan
	for rows.Next() {
		var s models.Scan
		var finishedAt sql.NullTime
		if err := rows.Scan(&s.ID, &s.Client, &s.Target, &s.StartedAt, &finishedAt, &s.Status); err != nil {
			return nil, err
		}
		if finishedAt.Valid {
			s.FinishedAt = &finishedAt.Time
		}
		scans = append(scans, s)
	}
	return scans, rows.Err()
}
