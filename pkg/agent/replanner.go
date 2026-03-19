package agent

import (
	"fmt"
	"time"

	"github.com/mo0ogly/liaprob/pkg/portdb"
)

// Replanner adjusts a plan during execution when an observation justifies it.
type Replanner struct {
	journal *Journal
	memory  *WorkingMemory
}

// NewReplanner creates a replanner.
func NewReplanner(journal *Journal, memory *WorkingMemory) *Replanner {
	return &Replanner{journal: journal, memory: memory}
}

// Replan modifies the plan based on an observation.
// Returns true if the plan was modified.
func (r *Replanner) Replan(plan *ScanPlan, obs Observation, failedTask *ScanTask) bool {
	if plan.Revisions >= plan.MaxRevisions {
		r.journal.LogReplan("MAX_REVISIONS_REACHED", "", map[string]interface{}{
			"max": plan.MaxRevisions,
		})
		return false
	}

	plan.Revisions++
	plan.Status = PlanReplanning
	plan.UpdatedAt = time.Now()
	r.journal.SetPlanRevision(plan.Revisions)

	var modified bool

	switch obs.Trigger {
	case TriggerTooManyHosts:
		modified = r.handleTooManyHosts(plan)

	case TriggerHostTimeout:
		modified = r.handleHostTimeout(plan, failedTask)

	case TriggerUnknownBanner:
		modified = r.handleUnknownBanner(plan, obs)

	case TriggerRateLimited:
		modified = r.handleRateLimited(plan)

	case TriggerUnexpectedService:
		modified = r.handleUnexpectedService(plan, obs)

	default:
		r.journal.LogReplan("UNKNOWN_TRIGGER", "", map[string]interface{}{
			"trigger": string(obs.Trigger),
		})
	}

	if modified {
		plan.Status = PlanExecuting
		r.journal.LogReplan("PLAN_MODIFIED", "", map[string]interface{}{
			"revision":   plan.Revisions,
			"task_count": len(plan.Tasks),
		})

		r.memory.mu.Lock()
		r.memory.Stats.Replans++
		r.memory.mu.Unlock()
	} else {
		plan.Status = PlanExecuting
	}

	return modified
}

// handleTooManyHosts adds a sampling task.
func (r *Replanner) handleTooManyHosts(plan *ScanPlan) bool {
	// Inserer une tache sample_selection avant le portscan
	sampleTask := ScanTask{
		ID:     fmt.Sprintf("t-sample-r%d", plan.Revisions),
		Type:   TaskSampleSelection,
		Status: TaskPending,
		Params: map[string]interface{}{
			"max_hosts": 256,
			"strategy":  "representative", // representative sample by subnet
		},
	}

	// Find port scan position and insert before
	for i, t := range plan.Tasks {
		if t.Type == TaskPortScan && t.Status == TaskPending {
			sampleTask.Dependencies = []string{plan.Tasks[i-1].ID}
			plan.Tasks[i].Dependencies = []string{sampleTask.ID}

			// Insert
			plan.Tasks = append(plan.Tasks[:i], append([]ScanTask{sampleTask}, plan.Tasks[i:]...)...)

			r.journal.LogReplan("ADD_SAMPLING", "", map[string]interface{}{
				"max_hosts": 256,
			})
			return true
		}
	}

	return false
}

// handleHostTimeout retries with longer timeout or skips.
func (r *Replanner) handleHostTimeout(plan *ScanPlan, failedTask *ScanTask) bool {
	if failedTask == nil {
		return false
	}

	failedTask.RetryCount++
	if failedTask.RetryCount > 3 {
		failedTask.Status = TaskSkipped
		r.journal.LogReplan("TASK_SKIPPED_MAX_RETRY", failedTask.ID, nil)
		return true
	}

	// Retry with pending status
	failedTask.Status = TaskPending
	failedTask.Error = ""
	r.journal.LogReplan("TASK_RETRY", failedTask.ID, map[string]interface{}{
		"retry": failedTask.RetryCount,
	})
	return true
}

// handleUnknownBanner adds an AI banner identification task.
func (r *Replanner) handleUnknownBanner(plan *ScanPlan, obs Observation) bool {
	aiTask := ScanTask{
		ID:     fmt.Sprintf("t-ai-banner-r%d", plan.Revisions),
		Type:   TaskAIIdentify,
		Status: TaskPending,
		Params: map[string]interface{}{
			"host":   obs.Host,
			"port":   obs.Port,
			"banner": obs.Banner,
		},
	}

	// Add before report task
	for i := len(plan.Tasks) - 1; i >= 0; i-- {
		if plan.Tasks[i].Type == TaskReport {
			aiTask.Dependencies = []string{plan.Tasks[i-1].ID}
			plan.Tasks[i].Dependencies = []string{aiTask.ID}
			plan.Tasks = append(plan.Tasks[:i], append([]ScanTask{aiTask}, plan.Tasks[i:]...)...)

			r.journal.LogReplan("ADD_AI_BANNER_ID", obs.Host, map[string]interface{}{
				"port":   obs.Port,
				"banner": obs.Banner,
			})
			return true
		}
	}

	return false
}

// handleRateLimited slows down concurrency.
func (r *Replanner) handleRateLimited(plan *ScanPlan) bool {
	if plan.Concurrency > 1 {
		plan.Concurrency = plan.Concurrency / 2
		plan.Delay = 100 * time.Millisecond
		r.journal.LogReplan("REDUCE_CONCURRENCY", "", map[string]interface{}{
			"new_concurrency": plan.Concurrency,
			"delay_ms":        100,
		})
		return true
	}
	return false
}

// handleUnexpectedService adds contextual ports for the unexpected service.
func (r *Replanner) handleUnexpectedService(plan *ScanPlan, obs Observation) bool {
	if obs.Service == "" {
		return false
	}

	extraPorts := portdb.ContextPortsForService(obs.Service)
	if len(extraPorts) == 0 {
		return false
	}

	contextTask := ScanTask{
		ID:     fmt.Sprintf("t-ctx-%s-r%d", obs.Service, plan.Revisions),
		Type:   TaskContextExpand,
		Status: TaskPending,
		Ports:  extraPorts,
		Params: map[string]interface{}{
			"service": obs.Service,
			"host":    obs.Host,
		},
	}

	// Add before report
	for i := len(plan.Tasks) - 1; i >= 0; i-- {
		if plan.Tasks[i].Type == TaskReport {
			contextTask.Dependencies = []string{plan.Tasks[i-1].ID}
			plan.Tasks[i].Dependencies = []string{contextTask.ID}
			plan.Tasks = append(plan.Tasks[:i], append([]ScanTask{contextTask}, plan.Tasks[i:]...)...)

			r.journal.LogReplan("ADD_CONTEXT_EXPAND", obs.Service, map[string]interface{}{
				"extra_ports": extraPorts,
			})
			return true
		}
	}

	return false
}
