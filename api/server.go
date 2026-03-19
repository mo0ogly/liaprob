// Package api provides the HTTP server for LiaProbe API mode.
// Used when LiaProbe is integrated into LIA-SEC (--serve flag).
// The API exposes scan control, results, and journal endpoints.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mo0ogly/liaprob/pkg/agent"
	"github.com/mo0ogly/liaprob/pkg/config"
	"github.com/mo0ogly/liaprob/pkg/log"
	"github.com/mo0ogly/liaprob/pkg/scanner"
	"github.com/mo0ogly/liaprob/pkg/store"
)

// Server is the LiaProbe HTTP API server.
type Server struct {
	cfg     *config.Config
	store   store.Store
	tools   *agent.ToolKit
	mux     *http.ServeMux
	httpSrv *http.Server

	// Active scans
	mu          sync.RWMutex
	activeScans map[string]*activeScan

	// Live journal streaming
	broadcaster *JournalBroadcaster
}

// activeScan tracks a running scan.
type activeScan struct {
	Agent   *agent.Agent
	Journal *agent.Journal
	Cancel  context.CancelFunc
	Started time.Time
	Goal    agent.ScanGoal
	Done    chan *agent.RunResult
}

// NewServer creates a new API server.
func NewServer(cfg *config.Config, dataStore store.Store, tools *agent.ToolKit) *Server {
	s := &Server{
		cfg:         cfg,
		store:       dataStore,
		tools:       tools,
		mux:         http.NewServeMux(),
		activeScans: make(map[string]*activeScan),
		broadcaster: NewJournalBroadcaster(),
	}
	s.registerRoutes()
	return s
}

// registerRoutes sets up all API endpoints.
func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/scan", s.handleScan)
	s.mux.HandleFunc("/api/scan/status", s.handleScanStatus)
	s.mux.HandleFunc("/api/scan/stop", s.handleScanStop)
	s.mux.HandleFunc("/api/scan/results", s.handleScanResults)
	s.mux.HandleFunc("/api/scan/journal", s.handleScanJournal)
	s.mux.HandleFunc("/api/scan/stream", s.handleScanStream)
	s.mux.HandleFunc("/api/version", s.handleVersion)
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	addr := ":" + log.Sprintf("%d", s.cfg.APIPort)
	s.httpSrv = &http.Server{
		Addr:         addr,
		Handler:      s.mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 300 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return s.httpSrv.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	// Cancel all active scans
	s.mu.Lock()
	for _, scan := range s.activeScans {
		scan.Cancel()
	}
	s.mu.Unlock()

	return s.httpSrv.Shutdown(ctx)
}

// --- Handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, 200, map[string]interface{}{
		"status":  "ok",
		"version": "0.1.0",
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, 200, map[string]interface{}{
		"version": "0.1.0",
		"mode":    "api",
	})
}

// ScanRequest is the JSON body for POST /api/scan.
type ScanRequest struct {
	Targets []string `json:"targets"`
	Mode    string   `json:"mode"`
	Ports   []int    `json:"ports,omitempty"`
	Service string   `json:"service,omitempty"`
	Banner  string   `json:"banner,omitempty"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]string{"error": "invalid request body"})
		return
	}

	if len(req.Targets) == 0 {
		s.writeJSON(w, 400, map[string]string{"error": "at least one target is required"})
		return
	}

	if req.Mode == "" {
		req.Mode = "smart"
	}

	scanID := log.Sprintf("scan-%d", time.Now().UnixMilli())
	goal := agent.ScanGoal{
		Description: "API scan: " + strings.Join(req.Targets, ", "),
		Targets:     req.Targets,
		Mode:        req.Mode,
		Ports:       req.Ports,
		Service:     req.Service,
		Banner:      req.Banner,
	}

	journal := agent.NewJournal()
	// Wire SSE broadcaster for live streaming
	journal.AddWriter(NewJournalWriter(scanID, s.broadcaster))
	scanAgent := agent.NewAgent(s.cfg, s.tools, journal)

	ctx, cancel := context.WithCancel(r.Context())
	done := make(chan *agent.RunResult, 1)

	scan := &activeScan{
		Agent:   scanAgent,
		Journal: journal,
		Cancel:  cancel,
		Started: time.Now(),
		Goal:    goal,
		Done:    done,
	}

	s.mu.Lock()
	s.activeScans[scanID] = scan
	s.mu.Unlock()

	// Run scan in background
	go func() {
		result := scanAgent.Run(ctx, goal)
		done <- result

		// Save results
		if result.ScanResult != nil {
			result.ScanResult.ID = scanID
			s.store.SaveScanResult(result.ScanResult)
			s.store.SaveJournal(scanID, journal.Entries())
		}
	}()

	s.writeJSON(w, 202, map[string]interface{}{
		"scan_id": scanID,
		"status":  "started",
		"targets": req.Targets,
		"mode":    req.Mode,
	})
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := r.URL.Query().Get("id")
	if scanID == "" {
		s.writeJSON(w, 400, map[string]string{"error": "id parameter required"})
		return
	}

	s.mu.RLock()
	scan, exists := s.activeScans[scanID]
	s.mu.RUnlock()

	if !exists {
		s.writeJSON(w, 404, map[string]string{"error": "scan not found"})
		return
	}

	// Check if done
	select {
	case result := <-scan.Done:
		// Put it back for results endpoint
		scan.Done <- result
		s.writeJSON(w, 200, map[string]interface{}{
			"scan_id":  scanID,
			"status":   "complete",
			"duration": time.Since(scan.Started).String(),
			"stats":    result.ScanResult.Stats,
		})
	default:
		entries := scan.Journal.Entries()
		s.writeJSON(w, 200, map[string]interface{}{
			"scan_id":       scanID,
			"status":        "running",
			"duration":      time.Since(scan.Started).String(),
			"journal_count": len(entries),
		})
	}
}

func (s *Server) handleScanStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}

	scanID := r.URL.Query().Get("id")
	if scanID == "" {
		s.writeJSON(w, 400, map[string]string{"error": "id parameter required"})
		return
	}

	s.mu.RLock()
	scan, exists := s.activeScans[scanID]
	s.mu.RUnlock()

	if !exists {
		s.writeJSON(w, 404, map[string]string{"error": "scan not found"})
		return
	}

	scan.Cancel()
	s.writeJSON(w, 200, map[string]interface{}{
		"scan_id": scanID,
		"status":  "stopping",
	})
}

func (s *Server) handleScanResults(w http.ResponseWriter, r *http.Request) {
	scanID := r.URL.Query().Get("id")
	if scanID == "" {
		// List all results
		results, err := s.store.ListScans()
		if err != nil {
			s.writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		s.writeJSON(w, 200, results)
		return
	}

	result, err := s.store.GetScanResult(scanID)
	if err != nil {
		s.writeJSON(w, 404, map[string]string{"error": "scan result not found"})
		return
	}
	s.writeJSON(w, 200, result)
}

func (s *Server) handleScanJournal(w http.ResponseWriter, r *http.Request) {
	scanID := r.URL.Query().Get("id")
	if scanID == "" {
		s.writeJSON(w, 400, map[string]string{"error": "id parameter required"})
		return
	}

	// Check active scan first
	s.mu.RLock()
	scan, exists := s.activeScans[scanID]
	s.mu.RUnlock()

	if exists {
		s.writeJSON(w, 200, scan.Journal.Entries())
		return
	}

	// Try store
	entries, err := s.store.GetJournal(scanID)
	if err != nil {
		s.writeJSON(w, 404, map[string]string{"error": "journal not found"})
		return
	}
	s.writeJSON(w, 200, entries)
}

// writeJSON writes a JSON response.
func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// BuildScanResult converts a RunResult to a ScanResult for storage.
// Exposed for use by the CLI when saving results.
func BuildScanResult(result *agent.RunResult) *scanner.ScanResult {
	return result.ScanResult
}
