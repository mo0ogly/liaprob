package agent

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// JournalLevel categorizes journal entries.
type JournalLevel string

const (
	LevelPlan    JournalLevel = "PLAN"
	LevelTask    JournalLevel = "TASK"
	LevelObserve JournalLevel = "OBSERVE"
	LevelReplan  JournalLevel = "REPLAN"
	LevelAI      JournalLevel = "AI"
	LevelError   JournalLevel = "ERROR"
)

// JournalEntry is an agentic journal entry.
// The journal traces EVERY action, decision, replanning, AI interaction.
// It is NON-DISABLEABLE. Traceability is not optional.
type JournalEntry struct {
	Timestamp  time.Time              `json:"ts"`
	Level      JournalLevel           `json:"level"`
	Action     string                 `json:"action"`
	Target     string                 `json:"target,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
	DurationMs int64                  `json:"duration_ms"`
	PlanRev    int                    `json:"plan_rev"`
}

// Journal is the agentic journal of LiaProbe.
// Thread-safe. Writes in JSONL format (one JSON entry per line).
type Journal struct {
	mu      sync.Mutex
	entries []JournalEntry
	writers []io.Writer // stdout, fichier, ou les deux
	planRev int
}

// NewJournal creates a new journal.
// By default, writes to stdout. Add more writers with AddWriter().
func NewJournal() *Journal {
	return &Journal{
		entries: make([]JournalEntry, 0, 256),
		writers: []io.Writer{os.Stdout},
	}
}

// AddWriter adds an additional writer (file, websocket, etc.).
func (j *Journal) AddWriter(w io.Writer) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.writers = append(j.writers, w)
}

// SetPlanRevision updates the plan revision number.
func (j *Journal) SetPlanRevision(rev int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.planRev = rev
}

// Log records an entry in the journal.
func (j *Journal) Log(level JournalLevel, action string, target string, details map[string]interface{}, durationMs int64) {
	j.mu.Lock()
	defer j.mu.Unlock()

	entry := JournalEntry{
		Timestamp:  time.Now().UTC(),
		Level:      level,
		Action:     action,
		Target:     target,
		Details:    details,
		DurationMs: durationMs,
		PlanRev:    j.planRev,
	}

	j.entries = append(j.entries, entry)

	// Write in JSONL format to all writers
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	line = append(line, '\n')
	for _, w := range j.writers {
		w.Write(line)
	}
}

// LogPlan logs a plan event.
func (j *Journal) LogPlan(action string, details map[string]interface{}) {
	j.Log(LevelPlan, action, "", details, 0)
}

// LogTask logs a task event.
func (j *Journal) LogTask(action string, target string, details map[string]interface{}, durationMs int64) {
	j.Log(LevelTask, action, target, details, durationMs)
}

// LogReplan logs a replanning event.
func (j *Journal) LogReplan(action string, target string, details map[string]interface{}) {
	j.Log(LevelReplan, action, target, details, 0)
}

// LogAI logs an AI provider interaction.
func (j *Journal) LogAI(action string, target string, details map[string]interface{}, durationMs int64) {
	j.Log(LevelAI, action, target, details, durationMs)
}

// Entries returns a copy of all entries.
func (j *Journal) Entries() []JournalEntry {
	j.mu.Lock()
	defer j.mu.Unlock()
	cp := make([]JournalEntry, len(j.entries))
	copy(cp, j.entries)
	return cp
}

// EntriesByLevel returns entries filtered by level.
func (j *Journal) EntriesByLevel(level JournalLevel) []JournalEntry {
	j.mu.Lock()
	defer j.mu.Unlock()
	var filtered []JournalEntry
	for _, e := range j.entries {
		if e.Level == level {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// EntriesByTarget returns entries filtered by target.
func (j *Journal) EntriesByTarget(target string) []JournalEntry {
	j.mu.Lock()
	defer j.mu.Unlock()
	var filtered []JournalEntry
	for _, e := range j.entries {
		if e.Target == target {
			filtered = append(filtered, e)
		}
	}
	return filtered
}
