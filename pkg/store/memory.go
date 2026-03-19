package store

import (
	"fmt"
	"sort"
	"sync"

	"github.com/mo0ogly/liaprob/pkg/agent"
	"github.com/mo0ogly/liaprob/pkg/scanner"
)

// MemoryStore is an in-memory store for tests and API mode.
// Data is lost when the process stops.
type MemoryStore struct {
	mu       sync.RWMutex
	scans    map[string]*scanner.ScanResult
	journals map[string][]agent.JournalEntry
}

// NewMemoryStore cree un store en memoire.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		scans:    make(map[string]*scanner.ScanResult),
		journals: make(map[string][]agent.JournalEntry),
	}
}

func (ms *MemoryStore) SaveScanResult(result *scanner.ScanResult) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.scans[result.ID] = result
	return nil
}

func (ms *MemoryStore) GetScanResult(id string) (*scanner.ScanResult, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	result, ok := ms.scans[id]
	if !ok {
		return nil, fmt.Errorf("scan %s not found", id)
	}
	return result, nil
}

func (ms *MemoryStore) ListScans() ([]ScanSummary, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	var summaries []ScanSummary
	for _, result := range ms.scans {
		status := "complete"
		if result.CompletedAt.IsZero() {
			status = "running"
		}
		summaries = append(summaries, ScanSummary{
			ID:          result.ID,
			StartedAt:   result.StartedAt.Format("2006-01-02T15:04:05Z"),
			CompletedAt: result.CompletedAt.Format("2006-01-02T15:04:05Z"),
			HostsAlive:  result.Stats.HostsAlive,
			PortsOpen:   result.Stats.PortsOpen,
			Status:      status,
		})
	}

	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].StartedAt > summaries[j].StartedAt
	})

	return summaries, nil
}

func (ms *MemoryStore) SaveJournal(scanID string, entries []agent.JournalEntry) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.journals[scanID] = entries
	return nil
}

func (ms *MemoryStore) GetJournal(scanID string) ([]agent.JournalEntry, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	entries, ok := ms.journals[scanID]
	if !ok {
		return nil, fmt.Errorf("journal for scan %s not found", scanID)
	}
	cp := make([]agent.JournalEntry, len(entries))
	copy(cp, entries)
	return cp, nil
}

func (ms *MemoryStore) Close() error {
	return nil
}
