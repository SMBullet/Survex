package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/SMBullet/Survex/internal/api"
	"github.com/SMBullet/Survex/internal/db"
	"github.com/SMBullet/Survex/internal/queue"
)

func main() {
	addr        := flag.String("addr", ":8080", "address to listen on")
	dbPath      := flag.String("db", "survex.db", "path to SQLite database")
	frontendDir := flag.String("frontend", "web/out", "path to built Next.js export (set empty to disable)")
	flag.Parse()

	// ── Database ─────────────────────────────────────────────────────────────
	database, err := db.Open(*dbPath)
	if err != nil {
		log.Fatalf("survex-server: open db: %v", err)
	}
	defer database.Close()
	log.Printf("survex-server: database opened at %s", *dbPath)

	// ── Queue ─────────────────────────────────────────────────────────────────
	q := queue.New(database)
	defer q.Stop()
	log.Printf("survex-server: scan queue started")

	// ── API server ─────────────────────────────────────────────────────────────
	frontend := *frontendDir
	if _, err := os.Stat(frontend); err != nil {
		frontend = "" // don't serve static files if the directory doesn't exist
	}
	app := api.New(database, q, frontend)

	// ── Graceful shutdown ──────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		log.Println("survex-server: shutting down...")
		_ = app.Shutdown()
	}()

	log.Printf("survex-server: listening on %s", *addr)
	if err := app.Listen(*addr); err != nil {
		log.Fatalf("survex-server: %v", err)
	}
}
