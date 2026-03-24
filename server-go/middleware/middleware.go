// middleware/middleware.go
// =============================================================================
// Middleware chain for the Go API server.
//
//   Chain(handler, mw1, mw2, ...)  — wraps handler outermost-first so request
//   flows mw1 → mw2 → handler and response flows handler → mw2 → mw1.
//
// Included middleware:
//   Logger       — structured request/response logging
//   RateLimit    — simple per-IP token-bucket limiter
//   RequireHITL  — validates the Human-in-the-Loop confirmation token for
//                  destructive tools (sqlmap, metasploit)
// =============================================================================

package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ── Chain ─────────────────────────────────────────────────────────────────────

// Chain applies middleware in order: first middleware wraps outermost.
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// ── Logger ────────────────────────────────────────────────────────────────────

// Logger logs method, path, status code, and duration for every request.
func Logger(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(rw, r)
			logger.Printf("%-6s %-40s %d %s",
				r.Method, r.URL.Path, rw.statusCode, time.Since(start))
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// ── Rate Limiter ──────────────────────────────────────────────────────────────

type ipBucket struct {
	tokens   float64
	lastSeen time.Time
}

type rateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*ipBucket
	maxTPS   float64 // requests per second
}

var globalLimiter = &rateLimiter{buckets: make(map[string]*ipBucket)}

// RateLimit enforces a per-IP rate of maxPerMinute requests/minute.
func RateLimit(maxPerMinute int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			if !globalLimiter.allow(ip, float64(maxPerMinute)/60.0) {
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (rl *rateLimiter) allow(ip string, ratePerSec float64) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, exists := rl.buckets[ip]
	if !exists {
		b = &ipBucket{tokens: 1, lastSeen: now}
		rl.buckets[ip] = b
		return true
	}

	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * ratePerSec
	if b.tokens > 5 {
		b.tokens = 5 // cap burst at 5 requests
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ── Human-in-the-Loop (HITL) Token ────────────────────────────────────────────

// RequireHITL validates the X-HITL-Token header before allowing destructive
// tools (sqlmap, metasploit) to execute.
//
// The Next.js UI generates a time-limited HMAC token when the operator clicks
// "Approve" on the confirmation dialog. The token format is:
//
//	hex( HMAC-SHA256( secret, "hitl:{job_id}:{unix_timestamp}" ) )
//
// This prevents replaying approvals across different jobs or after expiry.
func RequireHITL() func(http.Handler) http.Handler {
	secret := []byte(getEnvOrFatal("HITL_SECRET"))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("X-HITL-Token")
			payload := r.Header.Get("X-HITL-Payload") // "job_id:unix_timestamp"

			if token == "" || payload == "" {
				jsonForbidden(w, "Human-in-the-loop confirmation required")
				return
			}

			parts := strings.SplitN(payload, ":", 2)
			if len(parts) != 2 {
				jsonForbidden(w, "Malformed HITL payload")
				return
			}

			// Verify timestamp freshness (5-minute window)
			var ts int64
			fmt.Sscan(parts[1], &ts)
			if time.Since(time.Unix(ts, 0)) > 5*time.Minute {
				jsonForbidden(w, "HITL token expired")
				return
			}

			// Verify HMAC
			message := fmt.Sprintf("hitl:%s:%d", parts[0], ts)
			mac := hmac.New(sha256.New, secret)
			mac.Write([]byte(message))
			expected := hex.EncodeToString(mac.Sum(nil))

			if !hmac.Equal([]byte(token), []byte(expected)) {
				jsonForbidden(w, "Invalid HITL token signature")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func jsonForbidden(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}

func getEnvOrFatal(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic(fmt.Sprintf("required env var %q is not set", key))
	}
	return v
}