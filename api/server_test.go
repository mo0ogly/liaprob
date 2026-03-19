package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/mo0ogly/liaprob/pkg/agent"
	"github.com/mo0ogly/liaprob/pkg/ai"
	"github.com/mo0ogly/liaprob/pkg/config"
	"github.com/mo0ogly/liaprob/pkg/scanner"
	"github.com/mo0ogly/liaprob/pkg/store"
)

func newTestServer() *Server {
	cfg := config.Default()
	dataStore := store.NewMemoryStore()
	tools := &agent.ToolKit{
		TCPScanner:   scanner.NewTCPScanner(cfg.PortConnectTimeout, cfg.PortWorkers),
		AliveChecker: scanner.NewAliveChecker(cfg.AliveConnectTimeout, cfg.AliveWorkers),
		AI:           &ai.NoopProvider{},
		Config:       cfg,
	}
	return NewServer(cfg, dataStore, tools)
}

func TestHealthEndpoint(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %v", resp["status"])
	}
}

func TestVersionEndpoint(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest("GET", "/api/version", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["mode"] != "api" {
		t.Errorf("expected mode api, got %v", resp["mode"])
	}
}

func TestScanEndpoint_NoTargets(t *testing.T) {
	srv := newTestServer()
	body, _ := json.Marshal(ScanRequest{})
	req := httptest.NewRequest("POST", "/api/scan", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestScanEndpoint_WrongMethod(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest("GET", "/api/scan", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestScanStatusEndpoint_NoID(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest("GET", "/api/scan/status", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestScanStatusEndpoint_NotFound(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest("GET", "/api/scan/status?id=nonexistent", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestScanResultsEndpoint_EmptyList(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest("GET", "/api/scan/results", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestScanJournalEndpoint_NoID(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest("GET", "/api/scan/journal", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
