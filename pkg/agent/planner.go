package agent

import (
	"fmt"
	"time"

	"github.com/mo0ogly/liaprob/pkg/config"
	"github.com/mo0ogly/liaprob/pkg/portdb"
)

// Planner decomposes a ScanGoal into ScanPlan (ordered list of tasks).
type Planner struct {
	cfg *config.Config
}

// NewPlanner creates a planner.
func NewPlanner(cfg *config.Config) *Planner {
	return &Planner{cfg: cfg}
}

// CreatePlan decomposes an objective into an execution plan.
// The plan respects dependencies: expand -> alive -> portscan -> banner -> fingerprint -> [AI] -> report.
func (p *Planner) CreatePlan(goal ScanGoal) *ScanPlan {
	now := time.Now()
	plan := &ScanPlan{
		ID:           fmt.Sprintf("plan-%d", now.UnixMilli()),
		Goal:         goal,
		Status:       PlanPlanning,
		CreatedAt:    now,
		UpdatedAt:    now,
		MaxRevisions: p.cfg.MaxReplans,
		Concurrency:  p.cfg.PortWorkers,
	}

	// T1: Expand targets (CIDR, hostname -> IP)
	t1 := ScanTask{
		ID:      "t1-expand",
		Type:    TaskExpandTargets,
		Targets: goal.Targets,
		Status:  TaskPending,
	}
	plan.Tasks = append(plan.Tasks, t1)

	// T2: Alive check
	t2 := ScanTask{
		ID:           "t2-alive",
		Type:         TaskAliveCheck,
		Status:       TaskPending,
		Dependencies: []string{"t1-expand"},
	}
	plan.Tasks = append(plan.Tasks, t2)

	// T3: Port scan
	ports := p.selectPorts(goal)
	t3 := ScanTask{
		ID:           "t3-portscan",
		Type:         TaskPortScan,
		Ports:        ports,
		Status:       TaskPending,
		Dependencies: []string{"t2-alive"},
	}
	plan.Tasks = append(plan.Tasks, t3)

	// T4: Banner grab
	t4 := ScanTask{
		ID:           "t4-banner",
		Type:         TaskBannerGrab,
		Status:       TaskPending,
		Dependencies: []string{"t3-portscan"},
	}
	plan.Tasks = append(plan.Tasks, t4)

	// T5: Fingerprint
	if p.cfg.Fingerprint.ProbesEnabled {
		t5 := ScanTask{
			ID:           "t5-fingerprint",
			Type:         TaskFingerprint,
			Status:       TaskPending,
			Dependencies: []string{"t4-banner"},
		}
		plan.Tasks = append(plan.Tasks, t5)
	}

	// T6: Context expansion (smart mode only)
	if goal.Mode == string(config.ModeSmart) {
		dep := "t4-banner"
		if p.cfg.Fingerprint.ProbesEnabled {
			dep = "t5-fingerprint"
		}
		t6 := ScanTask{
			ID:           "t6-context-expand",
			Type:         TaskContextExpand,
			Status:       TaskPending,
			Dependencies: []string{dep},
		}
		plan.Tasks = append(plan.Tasks, t6)
	}

	// T7: AI analysis (if AI enabled) -- depends on latest data task
	if p.cfg.AI.Enabled {
		dep := p.lastTaskID(plan)
		t7 := ScanTask{
			ID:           "t7-ai-analyze",
			Type:         TaskAIAnalyze,
			Status:       TaskPending,
			Dependencies: []string{dep},
		}
		plan.Tasks = append(plan.Tasks, t7)
	}

	// T8: Report (final task)
	lastDep := p.lastTaskID(plan)
	t8 := ScanTask{
		ID:           "t8-report",
		Type:         TaskReport,
		Status:       TaskPending,
		Dependencies: []string{lastDep},
	}
	plan.Tasks = append(plan.Tasks, t8)

	plan.Status = PlanExecuting
	plan.UpdatedAt = time.Now()
	return plan
}

// selectPorts selects ports based on mode and config.
func (p *Planner) selectPorts(goal ScanGoal) []int {
	switch config.ScanMode(goal.Mode) {
	case config.ModeSpecific:
		if len(goal.Ports) > 0 {
			return goal.Ports
		}
		return portdb.CommonPorts
	case config.ModeFull:
		ports := make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
		return ports
	case config.ModeHunt:
		return portdb.CommonPorts
	default:
		return portdb.CommonPorts
	}
}

// lastTaskID returns the ID of the last task in the plan.
func (p *Planner) lastTaskID(plan *ScanPlan) string {
	if len(plan.Tasks) == 0 {
		return ""
	}
	return plan.Tasks[len(plan.Tasks)-1].ID
}
