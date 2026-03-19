package api

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/mo0ogly/liaprob/pkg/agent"
)

// JournalBroadcaster fans out journal entries to connected WebSocket clients.
// Uses SSE (Server-Sent Events) instead of WebSocket to avoid external dependencies.
// SSE is native HTTP, works through proxies, and needs zero JS library on the client.
type JournalBroadcaster struct {
	mu      sync.RWMutex
	clients map[string][]chan agent.JournalEntry
}

// NewJournalBroadcaster creates a broadcaster.
func NewJournalBroadcaster() *JournalBroadcaster {
	return &JournalBroadcaster{
		clients: make(map[string][]chan agent.JournalEntry),
	}
}

// Subscribe registers a client for a scan's live journal.
func (b *JournalBroadcaster) Subscribe(scanID string) chan agent.JournalEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan agent.JournalEntry, 64)
	b.clients[scanID] = append(b.clients[scanID], ch)
	return ch
}

// Unsubscribe removes a client.
func (b *JournalBroadcaster) Unsubscribe(scanID string, ch chan agent.JournalEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	clients := b.clients[scanID]
	for i, c := range clients {
		if c == ch {
			b.clients[scanID] = append(clients[:i], clients[i+1:]...)
			close(ch)
			return
		}
	}
}

// Broadcast sends a journal entry to all clients watching a scan.
func (b *JournalBroadcaster) Broadcast(scanID string, entry agent.JournalEntry) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.clients[scanID] {
		select {
		case ch <- entry:
		default:
			// Client too slow, drop entry
		}
	}
}

// JournalWriter is an io.Writer that broadcasts journal entries via SSE.
// Implements io.Writer so it can be added to Journal.AddWriter().
type JournalWriter struct {
	scanID      string
	broadcaster *JournalBroadcaster
}

// NewJournalWriter creates a writer that broadcasts to SSE clients.
func NewJournalWriter(scanID string, broadcaster *JournalBroadcaster) *JournalWriter {
	return &JournalWriter{scanID: scanID, broadcaster: broadcaster}
}

// Write implements io.Writer. Parses JSONL and broadcasts each entry.
func (jw *JournalWriter) Write(p []byte) (n int, err error) {
	var entry agent.JournalEntry
	if err := json.Unmarshal(p, &entry); err == nil {
		jw.broadcaster.Broadcast(jw.scanID, entry)
	}
	return len(p), nil
}

// sseWrite writes an SSE event to the writer.
func sseWrite(w io.Writer, data string) {
	io.WriteString(w, "data: ")
	io.WriteString(w, data)
	io.WriteString(w, "\n\n")
}

// sseEvent writes a named SSE event to the writer.
func sseEvent(w io.Writer, event, data string) {
	io.WriteString(w, "event: ")
	io.WriteString(w, event)
	io.WriteString(w, "\n")
	io.WriteString(w, "data: ")
	io.WriteString(w, data)
	io.WriteString(w, "\n\n")
}

// handleScanStream handles GET /api/scan/stream?id=X using SSE.
// Client connects with: new EventSource('/api/scan/stream?id=scan-123')
func (s *Server) handleScanStream(w http.ResponseWriter, r *http.Request) {
	scanID := r.URL.Query().Get("id")
	if scanID == "" {
		s.writeJSON(w, 400, map[string]string{"error": "id parameter required"})
		return
	}

	// Check scan exists
	s.mu.RLock()
	_, exists := s.activeScans[scanID]
	s.mu.RUnlock()
	if !exists {
		s.writeJSON(w, 404, map[string]string{"error": "active scan not found"})
		return
	}

	// Check if client supports SSE
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeJSON(w, 500, map[string]string{"error": "streaming not supported"})
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(200)
	flusher.Flush()

	// Subscribe to journal events
	ch := s.broadcaster.Subscribe(scanID)
	defer s.broadcaster.Unsubscribe(scanID, ch)

	// Send existing entries first (replay)
	s.mu.RLock()
	scan := s.activeScans[scanID]
	s.mu.RUnlock()
	if scan != nil {
		for _, entry := range scan.Journal.Entries() {
			data, _ := json.Marshal(entry)
			sseWrite(w, string(data))
		}
		flusher.Flush()
	}

	// Stream new entries
	ctx := r.Context()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-ch:
			if !ok {
				// Scan finished
				sseEvent(w, "done", "{\"status\":\"complete\"}")
				flusher.Flush()
				return
			}
			data, _ := json.Marshal(entry)
			sseWrite(w, string(data))
			flusher.Flush()
		case <-ticker.C:
			// SSE keepalive
			io.WriteString(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// Ensure JournalWriter implements io.Writer at compile time.
var _ io.Writer = (*JournalWriter)(nil)
