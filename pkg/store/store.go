// Package store defines the abstract storage interface for LiaProbe.
// Implementations: file (JSON, CLI default), memory, sqlite, postgres (LIA-SEC).
package store

import (
	"github.com/mo0ogly/liaprobe/pkg/agent"
	"github.com/mo0ogly/liaprobe/pkg/scanner"
)

// Store is the storage interface for LiaProbe.
// All implementations must be thread-safe.
type Store interface {
	// SaveScanResult persists a scan result.
	SaveScanResult(result *scanner.ScanResult) error

	// GetScanResult recupere un resultat par ID.
	GetScanResult(id string) (*scanner.ScanResult, error)

	// ListScans liste les scans enregistres.
	ListScans() ([]ScanSummary, error)

	// SaveJournal persiste le journal agentique d'un scan.
	SaveJournal(scanID string, entries []agent.JournalEntry) error

	// GetJournal recupere le journal d'un scan.
	GetJournal(scanID string) ([]agent.JournalEntry, error)

	// Close ferme la connexion au store.
	Close() error
}

// ScanSummary est un resume de scan pour les listings.
type ScanSummary struct {
	ID          string `json:"id"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
	HostsAlive  int    `json:"hosts_alive"`
	PortsOpen   int    `json:"ports_open"`
	Status      string `json:"status"`
}
