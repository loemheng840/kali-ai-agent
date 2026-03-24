// cmd/main.go
// =============================================================================
// Kali Agent — Go REST + SSE Server
//
// Responsibilities:
//   - Expose HTTP endpoints that FastAPI gateway calls.
//   - Execute Kali binaries safely via handlers/executor.go.
//   - Stream stdout/stderr back to clients via Server-Sent Events.
//   - Enforce input sanitisation and a hard tool-allowlist.
//
// Concurrency model:
//   Each scan runs in its own goroutine. Results are pushed through a
//   channel to the SSE handler, so the HTTP layer never blocks.
// =============================================================================

package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/loemheng840/kali-ai-agent/handlers"
	"github.com/loemheng840/kali-ai-agent/middleware"
)

func main() {
	port := getEnv("GO_SERVER_PORT", "8080")
	logger := log.New(os.Stdout, "[kali-go] ", log.LstdFlags|log.Lshortfile)

	mux := http.NewServeMux()

	// ── Health ──────────────────────────────────────────────────────────────
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"kali-go-server"}`))
	})

	// ── Tool endpoints ───────────────────────────────────────────────────────
	// POST /tool/nmap       — Nmap port/service scan
	// POST /tool/nikto      — Nikto web vulnerability scan
	// POST /tool/ffuf       — FFUF directory/parameter fuzzing
	// POST /tool/sqlmap     — SQLMap injection test  (requires HITL token)
	// POST /tool/metasploit — Metasploit module run  (requires HITL token)
	//
	// GET  /stream/{job_id} — SSE stream for a running job

	h := handlers.NewToolHandler(logger)

	mux.Handle("/tool/nmap",       middleware.Chain(http.HandlerFunc(h.Nmap),       middleware.Logger(logger), middleware.RateLimit(10)))
	mux.Handle("/tool/nikto",      middleware.Chain(http.HandlerFunc(h.Nikto),      middleware.Logger(logger), middleware.RateLimit(5)))
	mux.Handle("/tool/ffuf",       middleware.Chain(http.HandlerFunc(h.Ffuf),       middleware.Logger(logger), middleware.RateLimit(5)))
	mux.Handle("/tool/sqlmap",     middleware.Chain(http.HandlerFunc(h.Sqlmap),     middleware.Logger(logger), middleware.RateLimit(2), middleware.RequireHITL()))
	// mux.Handle("/tool/metasploit", middleware.Chain(http.HandlerFunc(h.Metasploit), middleware.Logger(logger), middleware.RateLimit(1), middleware.RequireHITL()))

	mux.Handle("/stream/", middleware.Chain(http.HandlerFunc(h.Stream), middleware.Logger(logger)))

	// ── Server ───────────────────────────────────────────────────────────────
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // SSE streams need no write deadline
		IdleTimeout:  60 * time.Second,
	}

	logger.Printf("Listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil {
		logger.Fatalf("Server error: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}