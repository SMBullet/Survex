package queue

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/SMBullet/Survex/internal/config"
	"github.com/SMBullet/Survex/internal/db"
	"github.com/SMBullet/Survex/internal/models"
	"github.com/SMBullet/Survex/internal/risk"
	"github.com/SMBullet/Survex/internal/scan"
)

// Job represents a scan task in the queue.
type Job struct {
	ID     string
	UserID int64
	Config *config.Config

	mu          sync.RWMutex
	cancelled   bool // set by Cancel(); checked before the scan starts
	logLines    []string
	subscribers []chan string
	cancel      context.CancelFunc
}

// Subscribe returns a channel that receives log lines for this job.
// All lines emitted before Subscribe was called are sent first.
// The channel is closed when the job finishes.
func (j *Job) Subscribe() chan string {
	ch := make(chan string, 512)
	j.mu.Lock()
	for _, l := range j.logLines {
		select {
		case ch <- l:
		default:
		}
	}
	j.subscribers = append(j.subscribers, ch)
	j.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber channel.
func (j *Job) Unsubscribe(ch chan string) {
	j.mu.Lock()
	for i, s := range j.subscribers {
		if s == ch {
			j.subscribers = append(j.subscribers[:i], j.subscribers[i+1:]...)
			break
		}
	}
	j.mu.Unlock()
}

// Cancel marks the job as cancelled.
// If the scan is already running the context is cancelled immediately.
// If it hasn't started yet the flag is checked before the scan begins.
func (j *Job) Cancel() {
	j.mu.Lock()
	j.cancelled = true
	cancel := j.cancel
	j.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// IsCancelled returns true if Cancel has been called.
func (j *Job) IsCancelled() bool {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.cancelled
}

// LogLines returns a copy of all log lines emitted so far.
func (j *Job) LogLines() []string {
	j.mu.RLock()
	defer j.mu.RUnlock()
	cp := make([]string, len(j.logLines))
	copy(cp, j.logLines)
	return cp
}

func (j *Job) appendLog(line string) {
	j.mu.Lock()
	j.logLines = append(j.logLines, line)
	for _, ch := range j.subscribers {
		select {
		case ch <- line:
		default:
		}
	}
	j.mu.Unlock()
}

func (j *Job) closeSubscribers() {
	j.mu.Lock()
	for _, ch := range j.subscribers {
		close(ch)
	}
	j.subscribers = nil
	j.mu.Unlock()
}

// Queue serialises scan jobs so log output is never interleaved.
type Queue struct {
	database *db.DB

	mu      sync.RWMutex
	jobs    map[string]*Job

	pending chan *Job
	done    chan struct{}
}

// New creates a Queue and starts the background worker goroutine.
func New(database *db.DB) *Queue {
	q := &Queue{
		database: database,
		jobs:     make(map[string]*Job),
		pending:  make(chan *Job, 128),
		done:     make(chan struct{}),
	}
	go q.worker()
	return q
}

// Enqueue adds a job to the run queue and stores it for later lookup.
func (q *Queue) Enqueue(job *Job) {
	q.mu.Lock()
	q.jobs[job.ID] = job
	q.mu.Unlock()
	q.pending <- job
}

// Get returns a known job by ID, or nil if unknown.
func (q *Queue) Get(id string) *Job {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.jobs[id]
}

// Stop shuts the queue worker down gracefully (waits for current job).
func (q *Queue) Stop() {
	close(q.pending)
	<-q.done
}

func (q *Queue) worker() {
	defer close(q.done)
	origOut := log.Writer()
	for job := range q.pending {
		q.runJob(job, origOut)
	}
}

func (q *Queue) runJob(job *Job, origLog io.Writer) {
	// Check if the job was cancelled before it even reached the worker.
	if job.IsCancelled() {
		now := time.Now()
		_ = q.database.UpdateScanStatus(job.ID, "cancelled", &now, &now)
		job.appendLog("[queue] scan was cancelled before it started")
		job.closeSubscribers()
		return
	}

	startedAt := time.Now()
	_ = q.database.UpdateScanStatus(job.ID, "running", &startedAt, nil)

	// Redirect the global logger through a pipe so we can fan out lines.
	pr, pw := io.Pipe()
	log.SetOutput(io.MultiWriter(origLog, pw))

	pipeDone := make(chan struct{})
	go func() {
		defer close(pipeDone)
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			job.appendLog(scanner.Text())
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	job.mu.Lock()
	job.cancel = cancel
	job.mu.Unlock()

	// If Cancel() was called between the IsCancelled check above and now,
	// make sure the context is also cancelled.
	if job.IsCancelled() {
		cancel()
	}

	result, err := scan.Run(ctx, job.Config)
	cancel()

	_ = pw.Close()
	<-pipeDone
	log.SetOutput(origLog)

	finishedAt := time.Now()

	switch {
	case err == nil && !job.IsCancelled():
		findCount, maxSev, reportPath := extractMeta(job.Config, result)
		_ = q.database.UpdateScanStatus(job.ID, "done", &startedAt, &finishedAt)
		_ = q.database.UpdateScanResult(job.ID, findCount, maxSev, reportPath)
		job.appendLog(fmt.Sprintf("[queue] scan complete — %d findings (max severity: %s)", findCount, maxSev))

	case job.IsCancelled() || err == context.Canceled:
		_ = q.database.UpdateScanStatus(job.ID, "cancelled", &startedAt, &finishedAt)
		job.appendLog("[queue] scan was cancelled")

	default:
		_ = q.database.UpdateScanError(job.ID, err.Error())
		job.appendLog(fmt.Sprintf("[queue] scan failed: %v", err))
	}

	job.closeSubscribers()
}

func extractMeta(cfg *config.Config, result *models.ScanResult) (int, string, string) {
	if result == nil {
		return 0, "", ""
	}
	findCount := len(result.Findings)
	maxSev := risk.MaxSeverity(result.Findings)

	outDir := cfg.Output.Dir
	if outDir == "" {
		outDir = filepath.Join("reports", cfg.Client)
	}
	reportPath := filepath.Join(outDir, result.Scan.ID, "report.html")
	return findCount, maxSev, reportPath
}
