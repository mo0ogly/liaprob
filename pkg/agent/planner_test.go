package agent

import (
	"testing"

	"github.com/mo0ogly/liaprob/pkg/config"
)

func TestCreatePlan_SmartMode(t *testing.T) {
	cfg := config.Default()
	cfg.Mode = config.ModeSmart
	cfg.AI.Enabled = false
	cfg.Fingerprint.ProbesEnabled = false

	planner := NewPlanner(cfg)
	goal := ScanGoal{
		Targets: []string{"10.0.0.1"},
		Mode:    "smart",
	}

	plan := planner.CreatePlan(goal)

	if plan.Status != PlanExecuting {
		t.Errorf("expected status EXECUTING, got %s", plan.Status)
	}
	if len(plan.Tasks) == 0 {
		t.Fatal("plan has no tasks")
	}

	// Verify task order: expand -> alive -> portscan -> banner -> report
	expectedTypes := []TaskType{
		TaskExpandTargets,
		TaskAliveCheck,
		TaskPortScan,
		TaskBannerGrab,
		TaskContextExpand, // smart mode adds context expansion
		TaskReport,
	}

	if len(plan.Tasks) != len(expectedTypes) {
		t.Fatalf("expected %d tasks, got %d", len(expectedTypes), len(plan.Tasks))
	}

	for i, expected := range expectedTypes {
		if plan.Tasks[i].Type != expected {
			t.Errorf("task %d: expected type %s, got %s", i, expected, plan.Tasks[i].Type)
		}
	}
}

func TestCreatePlan_WithAI(t *testing.T) {
	cfg := config.Default()
	cfg.Mode = config.ModeSmart
	cfg.AI.Enabled = true
	cfg.Fingerprint.ProbesEnabled = false

	planner := NewPlanner(cfg)
	goal := ScanGoal{
		Targets: []string{"10.0.0.1"},
		Mode:    "smart",
	}

	plan := planner.CreatePlan(goal)

	// Should have AI analyze task
	hasAI := false
	for _, t := range plan.Tasks {
		if t.Type == TaskAIAnalyze {
			hasAI = true
			break
		}
	}
	if !hasAI {
		t.Error("plan should include AI analyze task when AI is enabled")
	}
}

func TestCreatePlan_WithFingerprint(t *testing.T) {
	cfg := config.Default()
	cfg.Mode = config.ModeSmart
	cfg.AI.Enabled = false
	cfg.Fingerprint.ProbesEnabled = true

	planner := NewPlanner(cfg)
	goal := ScanGoal{
		Targets: []string{"10.0.0.1"},
		Mode:    "smart",
	}

	plan := planner.CreatePlan(goal)

	hasFP := false
	for _, t := range plan.Tasks {
		if t.Type == TaskFingerprint {
			hasFP = true
			break
		}
	}
	if !hasFP {
		t.Error("plan should include fingerprint task when probes are enabled")
	}
}

func TestCreatePlan_FullMode(t *testing.T) {
	cfg := config.Default()
	cfg.Mode = config.ModeFull
	cfg.AI.Enabled = false
	cfg.Fingerprint.ProbesEnabled = false

	planner := NewPlanner(cfg)
	goal := ScanGoal{
		Targets: []string{"10.0.0.1"},
		Mode:    "full",
	}

	plan := planner.CreatePlan(goal)

	// Full mode should scan all 65535 ports
	for _, task := range plan.Tasks {
		if task.Type == TaskPortScan {
			if len(task.Ports) != 65535 {
				t.Errorf("full mode should scan 65535 ports, got %d", len(task.Ports))
			}
			return
		}
	}
	t.Error("no port scan task found")
}

func TestCreatePlan_SpecificPorts(t *testing.T) {
	cfg := config.Default()
	cfg.Mode = config.ModeSpecific
	cfg.AI.Enabled = false
	cfg.Fingerprint.ProbesEnabled = false

	planner := NewPlanner(cfg)
	goal := ScanGoal{
		Targets: []string{"10.0.0.1"},
		Mode:    "specific",
		Ports:   []int{22, 80, 443},
	}

	plan := planner.CreatePlan(goal)

	for _, task := range plan.Tasks {
		if task.Type == TaskPortScan {
			if len(task.Ports) != 3 {
				t.Errorf("specific mode should scan 3 ports, got %d", len(task.Ports))
			}
			return
		}
	}
	t.Error("no port scan task found")
}

func TestHasPendingTasks(t *testing.T) {
	plan := &ScanPlan{
		Tasks: []ScanTask{
			{Status: TaskComplete},
			{Status: TaskPending},
		},
	}
	if !plan.HasPendingTasks() {
		t.Error("should have pending tasks")
	}

	plan.Tasks[1].Status = TaskComplete
	if plan.HasPendingTasks() {
		t.Error("should not have pending tasks")
	}
}
