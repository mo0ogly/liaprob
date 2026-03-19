// Package agent implements the OODA agentic loop of LiaProbe.
// Goal decomposition, planning, execution, observation, replanning.
package agent

import "time"

// --- Goal ---

// ScanGoal is the high-level objective given by the user.
type ScanGoal struct {
	Description string            `json:"description"`           // "Scan 192.168.1.0/24 and find all web servers"
	Targets     []string          `json:"targets"`               // Raw targets
	Mode        string            `json:"mode"`                  // "smart", "full", "specific", "hunt"
	Ports       []int             `json:"ports,omitempty"`       // Specific ports (specific mode)
	Service     string            `json:"service,omitempty"`     // Service to find (hunt mode)
	Banner      string            `json:"banner,omitempty"`      // Banner to find (hunt mode)
	Params      map[string]string `json:"params,omitempty"`      // Additional parameters
}

// --- Plan ---

// PlanStatus is the plan state.
type PlanStatus string

const (
	PlanPlanning    PlanStatus = "PLANNING"
	PlanExecuting   PlanStatus = "EXECUTING"
	PlanReplanning  PlanStatus = "REPLANNING"
	PlanComplete    PlanStatus = "COMPLETE"
	PlanFailed      PlanStatus = "FAILED"
)

// ScanPlan is the decomposed execution plan.
type ScanPlan struct {
	ID           string     `json:"id"`
	Goal         ScanGoal   `json:"goal"`
	Tasks        []ScanTask `json:"tasks"`
	Status       PlanStatus `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	Revisions    int        `json:"revisions"`
	MaxRevisions int        `json:"max_revisions"`
	Concurrency  int        `json:"concurrency"`
	Delay        time.Duration `json:"delay"`
}

// HasPendingTasks returns true if the plan has pending tasks.
func (p *ScanPlan) HasPendingTasks() bool {
	for _, t := range p.Tasks {
		if t.Status == TaskPending || t.Status == TaskRunning {
			return true
		}
	}
	return false
}

// --- Task ---

// TaskType is the type of an atomic task.
type TaskType string

const (
	TaskExpandTargets   TaskType = "EXPAND_TARGETS"
	TaskAliveCheck      TaskType = "ALIVE_CHECK"
	TaskPortScan        TaskType = "PORT_SCAN"
	TaskBannerGrab      TaskType = "BANNER_GRAB"
	TaskFingerprint     TaskType = "FINGERPRINT"
	TaskContextExpand   TaskType = "CONTEXT_EXPAND"   // Contextual port expansion
	TaskAIAnalyze       TaskType = "AI_ANALYZE"
	TaskAIIdentify      TaskType = "AI_IDENTIFY_BANNER"
	TaskSampleSelection TaskType = "SAMPLE_SELECTION"
	TaskReport          TaskType = "REPORT"
)

// TaskStatus is the state of a task.
type TaskStatus string

const (
	TaskPending  TaskStatus = "PENDING"
	TaskRunning  TaskStatus = "RUNNING"
	TaskComplete TaskStatus = "COMPLETE"
	TaskFailed   TaskStatus = "FAILED"
	TaskSkipped  TaskStatus = "SKIPPED"
)

// ScanTask is an atomic task in the plan.
type ScanTask struct {
	ID           string                 `json:"id"`
	Type         TaskType               `json:"type"`
	Targets      []string               `json:"targets,omitempty"`
	Ports        []int                  `json:"ports,omitempty"`
	Tools        []string               `json:"tools,omitempty"`
	Dependencies []string               `json:"dependencies,omitempty"`
	Status       TaskStatus             `json:"status"`
	Result       interface{}            `json:"result,omitempty"`
	Error        string                 `json:"error,omitempty"`
	Duration     time.Duration          `json:"duration"`
	RetryCount   int                    `json:"retry_count"`
	Params       map[string]interface{} `json:"params,omitempty"`
}

// --- Observation ---

// ReplanTrigger is the trigger for replanning.
type ReplanTrigger string

const (
	TriggerHostTimeout        ReplanTrigger = "HOST_TIMEOUT"
	TriggerTooManyHosts       ReplanTrigger = "TOO_MANY_HOSTS"
	TriggerUnknownBanner      ReplanTrigger = "UNKNOWN_BANNER"
	TriggerRateLimited        ReplanTrigger = "RATE_LIMITED"
	TriggerUnexpectedService  ReplanTrigger = "UNEXPECTED_SERVICE"
	TriggerPortFiltered       ReplanTrigger = "PORT_FILTERED"
)

// Observation is the result of observing the current state.
type Observation struct {
	Trigger       ReplanTrigger `json:"trigger,omitempty"`
	Host          string        `json:"host,omitempty"`
	Port          int           `json:"port,omitempty"`
	Service       string        `json:"service,omitempty"`
	Banner        string        `json:"banner,omitempty"`
	NeedsReplan   bool          `json:"needs_replan"`
	NeedsAI       bool          `json:"needs_ai"`
	Details       string        `json:"details,omitempty"`
}
