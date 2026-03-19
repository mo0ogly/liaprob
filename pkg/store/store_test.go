package store

import (
	"os"
	"testing"
	"time"

	"github.com/mo0ogly/liaprob/pkg/agent"
	"github.com/mo0ogly/liaprob/pkg/scanner"
)

func testScanResult() *scanner.ScanResult {
	return &scanner.ScanResult{
		ID:          "test-scan-001",
		StartedAt:   time.Now(),
		CompletedAt: time.Now(),
		Hosts: []scanner.HostResult{
			{
				Target: scanner.Target{IP: "10.0.0.1", Hostname: "server1"},
				Alive:  true,
				OpenPorts: []scanner.OpenPort{
					{IP: "10.0.0.1", Port: 22, Protocol: "tcp", Banner: "OpenSSH_8.9"},
					{IP: "10.0.0.1", Port: 80, Protocol: "tcp", Banner: "nginx/1.24"},
				},
			},
		},
		Stats: scanner.ScanStats{
			TotalTargets: 1,
			HostsAlive:   1,
			PortsOpen:    2,
			DurationMs:   1500,
		},
	}
}

func testJournalEntries() []agent.JournalEntry {
	return []agent.JournalEntry{
		{
			Timestamp: time.Now().UTC(),
			Level:     agent.LevelPlan,
			Action:    "SCAN_START",
			Details:   map[string]interface{}{"scan_id": "test-scan-001"},
		},
		{
			Timestamp: time.Now().UTC(),
			Level:     agent.LevelTask,
			Action:    "HOST_SCANNED",
			Target:    "10.0.0.1",
		},
	}
}

// --- MemoryStore tests ---

func TestMemoryStore_SaveAndGet(t *testing.T) {
	ms := NewMemoryStore()
	result := testScanResult()

	if err := ms.SaveScanResult(result); err != nil {
		t.Fatalf("SaveScanResult failed: %v", err)
	}

	got, err := ms.GetScanResult("test-scan-001")
	if err != nil {
		t.Fatalf("GetScanResult failed: %v", err)
	}
	if got.ID != result.ID {
		t.Errorf("expected ID %s, got %s", result.ID, got.ID)
	}
	if got.Stats.PortsOpen != 2 {
		t.Errorf("expected 2 open ports, got %d", got.Stats.PortsOpen)
	}
}

func TestMemoryStore_GetNotFound(t *testing.T) {
	ms := NewMemoryStore()
	_, err := ms.GetScanResult("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent scan")
	}
}

func TestMemoryStore_ListScans(t *testing.T) {
	ms := NewMemoryStore()
	ms.SaveScanResult(testScanResult())

	summaries, err := ms.ListScans()
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	if summaries[0].ID != "test-scan-001" {
		t.Errorf("expected ID test-scan-001, got %s", summaries[0].ID)
	}
}

func TestMemoryStore_Journal(t *testing.T) {
	ms := NewMemoryStore()
	entries := testJournalEntries()

	if err := ms.SaveJournal("test-scan-001", entries); err != nil {
		t.Fatalf("SaveJournal failed: %v", err)
	}

	got, err := ms.GetJournal("test-scan-001")
	if err != nil {
		t.Fatalf("GetJournal failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
}

// --- FileStore tests ---

func TestFileStore_SaveAndGet(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	result := testScanResult()
	if err := fs.SaveScanResult(result); err != nil {
		t.Fatalf("SaveScanResult failed: %v", err)
	}

	got, err := fs.GetScanResult("test-scan-001")
	if err != nil {
		t.Fatalf("GetScanResult failed: %v", err)
	}
	if got.ID != result.ID {
		t.Errorf("expected ID %s, got %s", result.ID, got.ID)
	}

	// Verify file exists on disk
	if _, err := os.Stat(fs.scanPath("test-scan-001")); os.IsNotExist(err) {
		t.Error("scan file should exist on disk")
	}
}

func TestFileStore_ListScans(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	fs.SaveScanResult(testScanResult())

	summaries, err := fs.ListScans()
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
}

func TestFileStore_Journal(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	entries := testJournalEntries()

	if err := fs.SaveJournal("test-scan-001", entries); err != nil {
		t.Fatalf("SaveJournal failed: %v", err)
	}

	got, err := fs.GetJournal("test-scan-001")
	if err != nil {
		t.Fatalf("GetJournal failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].Action != "SCAN_START" {
		t.Errorf("expected action SCAN_START, got %s", got[0].Action)
	}
}
