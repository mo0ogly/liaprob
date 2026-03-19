package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/mo0ogly/liaprob/pkg/agent"
	"github.com/mo0ogly/liaprob/pkg/scanner"
)

// FileStore persists results in JSON files.
// Defaut CLI : un fichier par scan, un fichier par journal.
// Structure :
//
//	{dir}/
//	  scans/
//	    {scan_id}.json
//	  journals/
//	    {scan_id}.jsonl
type FileStore struct {
	dir string
	mu  sync.RWMutex
}

// NewFileStore cree un store fichier dans le repertoire donne.
// Cree les sous-repertoires scans/ et journals/ si necessaire.
func NewFileStore(dir string) (*FileStore, error) {
	for _, sub := range []string{"scans", "journals"} {
		path := filepath.Join(dir, sub)
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", path, err)
		}
	}
	return &FileStore{dir: dir}, nil
}

func (fs *FileStore) scanPath(id string) string {
	return filepath.Join(fs.dir, "scans", id+".json")
}

func (fs *FileStore) journalPath(id string) string {
	return filepath.Join(fs.dir, "journals", id+".jsonl")
}

// SaveScanResult persiste le resultat d'un scan en JSON.
func (fs *FileStore) SaveScanResult(result *scanner.ScanResult) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal scan result: %w", err)
	}

	path := fs.scanPath(result.ID)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write scan result: %w", err)
	}
	return nil
}

// GetScanResult recupere un resultat par ID.
func (fs *FileStore) GetScanResult(id string) (*scanner.ScanResult, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	path := fs.scanPath(id)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("scan %s not found", id)
		}
		return nil, fmt.Errorf("failed to read scan result: %w", err)
	}

	var result scanner.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse scan result: %w", err)
	}
	return &result, nil
}

// ListScans liste les scans enregistres en lisant le repertoire scans/.
func (fs *FileStore) ListScans() ([]ScanSummary, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	scansDir := filepath.Join(fs.dir, "scans")
	entries, err := os.ReadDir(scansDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read scans directory: %w", err)
	}

	var summaries []ScanSummary
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		path := filepath.Join(scansDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var result scanner.ScanResult
		if err := json.Unmarshal(data, &result); err != nil {
			continue
		}

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

	// Trier par date decroissante
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].StartedAt > summaries[j].StartedAt
	})

	return summaries, nil
}

// SaveJournal persiste le journal agentique en JSONL.
func (fs *FileStore) SaveJournal(scanID string, entries []agent.JournalEntry) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	path := fs.journalPath(scanID)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create journal file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, entry := range entries {
		if err := enc.Encode(entry); err != nil {
			return fmt.Errorf("failed to write journal entry: %w", err)
		}
	}
	return nil
}

// GetJournal recupere le journal d'un scan depuis le fichier JSONL.
func (fs *FileStore) GetJournal(scanID string) ([]agent.JournalEntry, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	path := fs.journalPath(scanID)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("journal for scan %s not found", scanID)
		}
		return nil, fmt.Errorf("failed to open journal: %w", err)
	}
	defer f.Close()

	var entries []agent.JournalEntry
	dec := json.NewDecoder(f)
	for dec.More() {
		var entry agent.JournalEntry
		if err := dec.Decode(&entry); err != nil {
			break
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// Close est un no-op pour le store fichier.
func (fs *FileStore) Close() error {
	return nil
}
