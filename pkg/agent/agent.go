// Package agent implements the OODA agentic loop of LiaProbe.
// Goal decomposition, planning, execution, observation, replanning.
//
// OODA Loop:
//
//	Goal -> Plan -> [Execute -> Observe -> Replan?] -> Report
//
// The agent decomposes a scan objective into a plan, executes each task,
// observes the result, and replans if necessary (max N revisions).
// Everything is traced in the journal (non-disableable).
package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/mo0ogly/liaprob/pkg/config"
	"github.com/mo0ogly/liaprob/pkg/scanner"
)

// Agent is the agentic coordinator of LiaProbe.
// It orchestrates the OODA loop: Plan -> Execute -> Observe -> Replan.
type Agent struct {
	cfg       *config.Config
	planner   *Planner
	executor  *Executor
	observer  *Observer
	replanner *Replanner
	memory    *WorkingMemory
	journal   *Journal
}

// NewAgent creates a complete agent.
func NewAgent(cfg *config.Config, tools *ToolKit, journal *Journal) *Agent {
	memory := NewWorkingMemory()
	return &Agent{
		cfg:       cfg,
		planner:   NewPlanner(cfg),
		executor:  NewExecutor(tools, memory, journal),
		observer:  NewObserver(journal, memory),
		replanner: NewReplanner(journal, memory),
		memory:    memory,
		journal:   journal,
	}
}

// RunResult is the complete result of an agentic scan.
type RunResult struct {
	ScanResult *scanner.ScanResult
	Plan       *ScanPlan
	Memory     *WorkingMemory
	Journal    []JournalEntry
}

// Run executes a complete scan in agentic mode.
func (a *Agent) Run(ctx context.Context, goal ScanGoal) *RunResult {
	start := time.Now()
	scanID := fmt.Sprintf("scan-%d", start.UnixMilli())

	a.journal.LogPlan("AGENT_START", map[string]interface{}{
		"scan_id": scanID,
		"mode":    goal.Mode,
		"targets": goal.Targets,
	})

	// Phase 1: Planning
	plan := a.planner.CreatePlan(goal)
	a.journal.LogPlan("PLAN_CREATED", map[string]interface{}{
		"plan_id":    plan.ID,
		"task_count": len(plan.Tasks),
	})

	// Phase 2: Dry run check
	if a.cfg.DryRun {
		a.journal.LogPlan("DRY_RUN", map[string]interface{}{
			"plan_id": plan.ID,
			"tasks":   taskSummary(plan.Tasks),
		})
		return &RunResult{
			ScanResult: &scanner.ScanResult{
				ID:          scanID,
				StartedAt:   start,
				CompletedAt: time.Now(),
			},
			Plan:    plan,
			Memory:  a.memory,
			Journal: a.journal.Entries(),
		}
	}

	// Phase 3: OODA Loop
	for {
		select {
		case <-ctx.Done():
			a.journal.Log(LevelError, "CANCELLED", "", nil, 0)
			plan.Status = PlanFailed
			break
		default:
		}

		if !plan.HasPendingTasks() {
			plan.Status = PlanComplete
			break
		}

		// Find next executable task
		task := a.nextExecutableTask(plan)
		if task == nil {
			// Deadlock: tasks pending but none executable
			a.journal.Log(LevelError, "DEADLOCK", "", map[string]interface{}{
				"pending": countByStatus(plan.Tasks, TaskPending),
				"running": countByStatus(plan.Tasks, TaskRunning),
			}, 0)
			plan.Status = PlanFailed
			break
		}

		// Execute
		obs := a.executor.ExecuteTask(ctx, task)

		// Observe
		needsReplan := a.observer.Analyze(obs, task)

		// Replan if necessary
		if needsReplan && plan.Revisions < plan.MaxRevisions {
			a.replanner.Replan(plan, obs, task)
		}

		// Inter-task delay if rate limited
		if plan.Delay > 0 {
			time.Sleep(plan.Delay)
		}
	}

	// Phase 4: Build result
	result := a.buildScanResult(scanID, start)

	a.journal.LogPlan("AGENT_COMPLETE", map[string]interface{}{
		"scan_id":     scanID,
		"hosts_alive": result.Stats.HostsAlive,
		"ports_open":  result.Stats.PortsOpen,
		"techs_found": result.Stats.TechnologiesFound,
		"replans":     plan.Revisions,
		"duration_ms": result.Stats.DurationMs,
	})

	return &RunResult{
		ScanResult: result,
		Plan:       plan,
		Memory:     a.memory,
		Journal:    a.journal.Entries(),
	}
}

// nextExecutableTask returns the next task whose dependencies are all complete.
func (a *Agent) nextExecutableTask(plan *ScanPlan) *ScanTask {
	completed := make(map[string]bool)
	for i := range plan.Tasks {
		switch plan.Tasks[i].Status {
		case TaskComplete, TaskSkipped, TaskFailed:
			// Failed tasks unblock dependents (graceful degradation)
			completed[plan.Tasks[i].ID] = true
		}
	}

	for i := range plan.Tasks {
		if plan.Tasks[i].Status != TaskPending {
			continue
		}

		// Check that all dependencies are satisfied
		allDeps := true
		for _, dep := range plan.Tasks[i].Dependencies {
			if !completed[dep] {
				allDeps = false
				break
			}
		}

		if allDeps {
			return &plan.Tasks[i]
		}
	}

	return nil
}

// buildScanResult converts working memory into ScanResult.
func (a *Agent) buildScanResult(scanID string, start time.Time) *scanner.ScanResult {
	a.memory.mu.RLock()
	defer a.memory.mu.RUnlock()

	var hosts []scanner.HostResult
	totalOpen := 0
	totalTechs := 0

	for _, h := range a.memory.Hosts {
		if !h.Alive {
			continue
		}

		var openPorts []scanner.OpenPort
		for _, p := range h.OpenPorts {
			openPorts = append(openPorts, scanner.OpenPort{
				IP:       h.IP,
				Hostname: h.Hostname,
				Port:     p.Port,
				Protocol: p.Protocol,
				Banner:   p.Banner,
			})
		}
		totalOpen += len(openPorts)
		totalTechs += len(h.Services)

		var services []scanner.ServiceInfo
		for _, svc := range h.Services {
			services = append(services, scanner.ServiceInfo{
				Port:       svc.Port,
				Name:       svc.Name,
				Product:    svc.Product,
				Version:    svc.Version,
				CPE:        svc.CPE,
				Confidence: svc.Confidence,
				PatternID:  svc.PatternID,
			})
		}

		hosts = append(hosts, scanner.HostResult{
			Target: scanner.Target{
				IP:       h.IP,
				Hostname: h.Hostname,
			},
			Alive:     true,
			OpenPorts: openPorts,
			Services:  services,
		})
	}

	return &scanner.ScanResult{
		ID:          scanID,
		StartedAt:   start,
		CompletedAt: time.Now(),
		Hosts:       hosts,
		AIAnalysis:  a.memory.AIAnalysis,
		Stats: scanner.ScanStats{
			TotalTargets:      a.memory.Stats.TargetsTotal,
			HostsAlive:        a.memory.Stats.HostsAlive,
			PortsOpen:         totalOpen,
			TechnologiesFound: totalTechs,
			DurationMs:        time.Since(start).Milliseconds(),
			Replans:           a.memory.Stats.Replans,
			AIQueries:         a.memory.Stats.AIQueries,
		},
	}
}

// taskSummary returns a summary of tasks for dry run.
func taskSummary(tasks []ScanTask) []map[string]interface{} {
	summary := make([]map[string]interface{}, len(tasks))
	for i, t := range tasks {
		summary[i] = map[string]interface{}{
			"id":           t.ID,
			"type":         string(t.Type),
			"dependencies": t.Dependencies,
		}
	}
	return summary
}

// countByStatus counts tasks by status.
func countByStatus(tasks []ScanTask, status TaskStatus) int {
	n := 0
	for _, t := range tasks {
		if t.Status == status {
			n++
		}
	}
	return n
}
