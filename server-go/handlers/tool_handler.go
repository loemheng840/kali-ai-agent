// handlers/tool_handler.go
// =============================================================================
// ToolHandler — Safe execution of Kali Linux tools
//
// Security layers (in order of evaluation):
//   1. Input validation  — reject anything that doesn't match a strict schema.
//   2. Allowlist check   — only pre-approved binaries may be called.
//   3. Argument sanitiser— each arg is checked against per-tool regex rules.
//   4. No shell          — exec.Command() is called directly; never via /bin/sh.
//   5. Timeout context   — every job is killed after MaxJobDuration.
//   6. HITL token        — destructive tools require a signed confirmation token
//                          injected by the middleware layer.
// =============================================================================

package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ── Constants ─────────────────────────────────────────────────────────────────

const (
	MaxJobDuration = 10 * time.Minute
	MaxTargetLen   = 253 // max valid hostname length
)

// ── Allowlisted binaries ──────────────────────────────────────────────────────
// Only these absolute paths may be executed. Any other binary is rejected.

var allowedBinaries = map[string]string{
	"nmap":       "/usr/bin/nmap",
	"nikto":      "/usr/bin/nikto",
	"ffuf":       "/usr/bin/ffuf",
	"sqlmap":     "/usr/bin/sqlmap",
	"msfconsole": "/usr/bin/msfconsole",
}

// ── Per-tool argument allowlists ──────────────────────────────────────────────
// Each entry is a compiled regex that an individual argument MUST match.
// Arguments are validated one-by-one; any mismatch aborts the job.

var argAllowlists = map[string][]*regexp.Regexp{
	"nmap": {
		// Flags:  -sV, -sC, -sS, -A, -p, --open, -oN, -oX, --script=*
		regexp.MustCompile(`^-[sACTpPnoO]{1,4}$`),
		regexp.MustCompile(`^--open$`),
		regexp.MustCompile(`^--script=[a-zA-Z0-9_,\-]+$`),
		regexp.MustCompile(`^-p\d[\d,\-]*$`),          // inline port e.g. -p80,443
		regexp.MustCompile(`^\d{1,5}$`),                // plain port number
		regexp.MustCompile(`^` + targetPattern + `$`),  // host/CIDR
		regexp.MustCompile(`^-oN$`), regexp.MustCompile(`^/tmp/[a-zA-Z0-9_\-\.]+$`),
		regexp.MustCompile(`^-T[0-5]$`),
		regexp.MustCompile(`^-v+$`),
	},
	"nikto": {
		regexp.MustCompile(`^-h$`),
		regexp.MustCompile(`^` + targetPattern + `$`),              // plain hostname/IP
		regexp.MustCompile(`^https?://` + targetPattern + `/?$`),   // URL with http://
		regexp.MustCompile(`^-p$`), regexp.MustCompile(`^\d{1,5}$`),
		regexp.MustCompile(`^-ssl$`),
		regexp.MustCompile(`^-o$`), regexp.MustCompile(`^/tmp/[a-zA-Z0-9_\-\.]+$`),
	},
	"ffuf": {
		regexp.MustCompile(`^-u$`), regexp.MustCompile(`^https?://` + targetPattern + `/[a-zA-Z0-9_/\.FUZZ]*$`),
		regexp.MustCompile(`^-w$`), regexp.MustCompile(`^/usr/share/[a-zA-Z0-9_/\-\.]+$`),
		regexp.MustCompile(`^-mc$`), regexp.MustCompile(`^\d{3}(,\d{3})*$`),
		regexp.MustCompile(`^-t$`), regexp.MustCompile(`^\d{1,3}$`),
		regexp.MustCompile(`^-o$`), regexp.MustCompile(`^/tmp/[a-zA-Z0-9_\-\.]+\.json$`),
		regexp.MustCompile(`^-of$`), regexp.MustCompile(`^json$`),
	},
	"sqlmap": {
		regexp.MustCompile(`^-u$`), regexp.MustCompile(`^https?://` + targetPattern + `/[a-zA-Z0-9_/\.\?\=\&]*$`),
		regexp.MustCompile(`^--batch$`),
		regexp.MustCompile(`^--level=[1-5]$`),
		regexp.MustCompile(`^--risk=[1-3]$`),
		regexp.MustCompile(`^--dbs$`),
		regexp.MustCompile(`^--output-dir=/tmp/[a-zA-Z0-9_\-]+$`),
	},
	"msfconsole": {
		regexp.MustCompile(`^-x$`),
		// Only allow "use module; set RHOSTS x; run; exit" style one-liners
		regexp.MustCompile(`^use [a-zA-Z0-9_/]+; set RHOSTS ` + targetPattern + `; (run|exploit); exit$`),
	},
}

// targetPattern validates IPs, hostnames, and CIDR ranges
const targetPattern = `[a-zA-Z0-9\.\-\_]{1,253}(/\d{1,2})?`

// ── Data structures ───────────────────────────────────────────────────────────

// ToolRequest is the JSON body expected by every /tool/* endpoint.
type ToolRequest struct {
	Target string   `json:"target"`   // IP, hostname, URL, or CIDR
	Args   []string `json:"args"`     // Additional arguments (validated)
	JobID  string   `json:"job_id"`   // Optional; generated if empty
}

// ToolResponse is the immediate JSON reply (before streaming starts).
type ToolResponse struct {
	JobID   string `json:"job_id"`
	Status  string `json:"status"`
	Message string `json:"message"`
	StreamURL string `json:"stream_url"`
}

// JobEvent is one line emitted over the SSE stream.
type JobEvent struct {
	JobID   string `json:"job_id"`
	Type    string `json:"type"`    // "stdout" | "stderr" | "exit" | "error"
	Data    string `json:"data"`
	ExitCode int   `json:"exit_code,omitempty"`
}

// Job holds the live state of a running scan.
type Job struct {
	ID       string
	Tool     string
	Events   chan JobEvent
	Done     chan struct{}
	Created  time.Time
}

// ── ToolHandler ───────────────────────────────────────────────────────────────

type ToolHandler struct {
	logger *log.Logger
	mu     sync.RWMutex
	jobs   map[string]*Job
}

func NewToolHandler(logger *log.Logger) *ToolHandler {
	h := &ToolHandler{
		logger: logger,
		jobs:   make(map[string]*Job),
	}
	go h.reapOldJobs()
	return h
}

// ── Public HTTP handlers ──────────────────────────────────────────────────────

func (h *ToolHandler) Nmap(w http.ResponseWriter, r *http.Request) {
	h.runTool(w, r, "nmap")
}

func (h *ToolHandler) Nikto(w http.ResponseWriter, r *http.Request) {
	h.runTool(w, r, "nikto")
}

func (h *ToolHandler) Ffuf(w http.ResponseWriter, r *http.Request) {
	h.runTool(w, r, "ffuf")
}

func (h *ToolHandler) Sqlmap(w http.ResponseWriter, r *http.Request) {
	h.runTool(w, r, "sqlmap")
}

func (h *ToolHandler) Metasploit(w http.ResponseWriter, r *http.Request) {
	h.runTool(w, r, "msfconsole")
}

// ── Core execution logic ──────────────────────────────────────────────────────

func (h *ToolHandler) runTool(w http.ResponseWriter, r *http.Request, toolName string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Decode request body
	var req ToolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// 2. Validate target
	if err := validateTarget(req.Target); err != nil {
		h.jsonError(w, fmt.Sprintf("Target validation failed: %v", err), http.StatusBadRequest)
		return
	}

	// 3. Resolve binary path from allowlist
	binaryPath, ok := allowedBinaries[toolName]
	if !ok {
		h.jsonError(w, "Tool not in allowlist", http.StatusForbidden)
		return
	}

	// 4. Validate each argument against the per-tool allowlist
	allArgs := append(req.Args, req.Target)
	if err := validateArgs(toolName, allArgs); err != nil {
		h.jsonError(w, fmt.Sprintf("Argument validation failed: %v", err), http.StatusBadRequest)
		return
	}

	// 5. Build the final arg list (target appended by the handler, not user)
	cmdArgs := buildArgs(toolName, req.Target, req.Args)

	// 6. Create a Job
	jobID := req.JobID
	if jobID == "" {
		jobID = uuid.New().String()
	}
	job := &Job{
		ID:      jobID,
		Tool:    toolName,
		Events:  make(chan JobEvent, 512),
		Done:    make(chan struct{}),
		Created: time.Now(),
	}
	h.storeJob(job)

	// 7. Launch scan in goroutine — does NOT block this handler
	go h.executeCommand(job, binaryPath, cmdArgs)

	// 8. Return immediately with the job ID and stream URL
	h.logger.Printf("Job %s started: %s %v", jobID, toolName, cmdArgs)
	resp := ToolResponse{
		JobID:     jobID,
		Status:    "started",
		Message:   fmt.Sprintf("%s job queued", toolName),
		StreamURL: fmt.Sprintf("/stream/%s", jobID),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(resp)
}

// executeCommand runs the binary, pipes output into the job's event channel.
// This is the ONLY place where a process is actually spawned.
func (h *ToolHandler) executeCommand(job *Job, binary string, args []string) {
	defer func() {
		close(job.Done)
		// Drain the channel after a grace period so SSE clients finish reading
		go func() {
			time.Sleep(30 * time.Second)
			h.deleteJob(job.ID)
		}()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), MaxJobDuration)
	defer cancel()

	// ✅ SECURITY: exec.CommandContext — never exec.Command("/bin/sh", "-c", ...)
	// Arguments are passed as a slice, so the OS kernel treats each element as
	// a separate argument. Shell metacharacters (;, |, &&, $()) have no effect.
	cmd := exec.CommandContext(ctx, binary, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		job.Events <- JobEvent{JobID: job.ID, Type: "error", Data: err.Error()}
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		job.Events <- JobEvent{JobID: job.ID, Type: "error", Data: err.Error()}
		return
	}

	if err := cmd.Start(); err != nil {
		job.Events <- JobEvent{JobID: job.ID, Type: "error", Data: fmt.Sprintf("Failed to start: %v", err)}
		return
	}

	var wg sync.WaitGroup

	// Pipe stdout
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			job.Events <- JobEvent{JobID: job.ID, Type: "stdout", Data: scanner.Text()}
		}
	}()

	// Pipe stderr
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			job.Events <- JobEvent{JobID: job.ID, Type: "stderr", Data: scanner.Text()}
		}
	}()

	wg.Wait()
	exitCode := 0
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}
	job.Events <- JobEvent{JobID: job.ID, Type: "exit", ExitCode: exitCode,
		Data: fmt.Sprintf("Process exited with code %d", exitCode)}
}

// ── SSE Streaming ─────────────────────────────────────────────────────────────

// Stream handles GET /stream/{job_id}
func (h *ToolHandler) Stream(w http.ResponseWriter, r *http.Request) {
	jobID := strings.TrimPrefix(r.URL.Path, "/stream/")
	if jobID == "" {
		http.Error(w, "Missing job_id", http.StatusBadRequest)
		return
	}

	// Wait up to 5 seconds for the job to appear (race between POST and GET)
	var job *Job
	for i := 0; i < 50; i++ {
		job = h.getJob(jobID)
		if job != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if job == nil {
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}

	// SSE headers — must be set before WriteHeader
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Use rc (ResponseController) for flushing — works with all middleware wrappers
	rc := http.NewResponseController(w)

	flush := func() {
		_ = rc.Flush()
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event, open := <-job.Events:
			if !open {
				fmt.Fprintf(w, "event: close\ndata: {}\n\n")
				flush()
				return
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, string(data))
			flush()

			if event.Type == "exit" || event.Type == "error" {
				return
			}

		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flush()

		case <-r.Context().Done():
			return

		case <-job.Done:
			for {
				select {
				case event := <-job.Events:
					data, _ := json.Marshal(event)
					fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, string(data))
					flush()
				default:
					fmt.Fprintf(w, "event: close\ndata: {}\n\n")
					flush()
					return
				}
			}
		}
	}
}

// ── Validation helpers ────────────────────────────────────────────────────────

var targetRegex = regexp.MustCompile(`^[a-zA-Z0-9\.\-\_\/\:]{1,253}$`)

func validateTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("target is empty")
	}
	if len(target) > MaxTargetLen {
		return fmt.Errorf("target exceeds max length")
	}
	if !targetRegex.MatchString(target) {
		return fmt.Errorf("target contains illegal characters")
	}
	return nil
}

func validateArgs(toolName string, args []string) error {
	rules, ok := argAllowlists[toolName]
	if !ok {
		return fmt.Errorf("no allowlist defined for tool %q", toolName)
	}

	for _, arg := range args {
		matched := false
		for _, rule := range rules {
			if rule.MatchString(arg) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("argument %q is not permitted for %s", arg, toolName)
		}
	}
	return nil
}

// buildArgs constructs the final argument list with safe, tool-specific defaults.
func buildArgs(toolName, target string, userArgs []string) []string {
	defaults := map[string][]string{
		"nmap":       {"-sV", "--open", "-T4"},
		"nikto":      {"-h"},
		"ffuf":       {"-u", target + "/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-mc", "200,204,301,302,307,401,403"},
		"sqlmap":     {"-u", target, "--batch", "--level=1", "--risk=1"},
		"msfconsole": {"-x"},
	}

	base := defaults[toolName]
	switch toolName {
	case "nmap":
		return append(append(base, userArgs...), target)
	case "nikto":
		return append(append(base, target), userArgs...)
	case "ffuf":
		// URL and wordlist already in defaults for ffuf
		return append(base, userArgs...)
	default:
		return append(base, userArgs...)
	}
}

// ── Job store ─────────────────────────────────────────────────────────────────

func (h *ToolHandler) storeJob(job *Job) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.jobs[job.ID] = job
}

func (h *ToolHandler) getJob(id string) *Job {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.jobs[id]
}

func (h *ToolHandler) deleteJob(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.jobs, id)
}

// reapOldJobs periodically removes completed jobs older than 1 hour.
func (h *ToolHandler) reapOldJobs() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		h.mu.Lock()
		for id, job := range h.jobs {
			select {
			case <-job.Done:
				if time.Since(job.Created) > time.Hour {
					delete(h.jobs, id)
				}
			default:
			}
		}
		h.mu.Unlock()
	}
}

// ── Utility ───────────────────────────────────────────────────────────────────

func (h *ToolHandler) jsonError(w http.ResponseWriter, msg string, code int) {
	h.logger.Printf("ERROR %d: %s", code, msg)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}