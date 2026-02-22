// Package scheduler runs a background goroutine that fires recurring scan jobs.
package scheduler

import (
	"log"
	"time"

	"github.com/SMBullet/Survex/internal/db"
	"github.com/SMBullet/Survex/internal/queue"
)

// Runner checks the schedules table every minute and enqueues due jobs.
type Runner struct {
	database *db.DB
	q        *queue.Queue
	stop     chan struct{}

	// runJob is injected so the API package can provide the create-and-enqueue logic
	// without creating an import cycle.
	runJob func(database *db.DB, q *queue.Queue, s *db.Schedule) error
}

// New creates a new scheduler Runner.
// runJob must create+enqueue a scan job for the given schedule and return an error on failure.
func New(database *db.DB, q *queue.Queue, runJob func(*db.DB, *queue.Queue, *db.Schedule) error) *Runner {
	return &Runner{
		database: database,
		q:        q,
		stop:     make(chan struct{}),
		runJob:   runJob,
	}
}

// Start launches the background goroutine. Call Stop to shut it down.
func (r *Runner) Start() {
	go r.loop()
}

// Stop signals the loop to exit.
func (r *Runner) Stop() {
	close(r.stop)
}

func (r *Runner) loop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	// Run once immediately at startup so we don't miss jobs after a restart.
	r.tick()

	for {
		select {
		case <-ticker.C:
			r.tick()
		case <-r.stop:
			return
		}
	}
}

func (r *Runner) tick() {
	schedules, err := r.database.GetDueSchedules()
	if err != nil {
		log.Printf("[scheduler] error fetching due schedules: %v", err)
		return
	}

	for _, s := range schedules {
		if err := r.runJob(r.database, r.q, s); err != nil {
			log.Printf("[scheduler] error firing schedule %s: %v", s.ID, err)
			continue
		}

		next := time.Now().Add(time.Duration(s.IntervalH) * time.Hour)
		if err := r.database.UpdateScheduleNextRun(s.ID, next, time.Now()); err != nil {
			log.Printf("[scheduler] error updating next_run for schedule %s: %v", s.ID, err)
		}

		log.Printf("[scheduler] fired schedule %s (%s), next run at %s",
			s.ID, s.Client, next.Format(time.RFC3339))
	}
}
