package scanner

import (
	"testing"
)

func TestExpandTargets_SingleIP(t *testing.T) {
	targets, err := ExpandTargets([]string{"192.168.1.1"}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].IP != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %s", targets[0].IP)
	}
}

func TestExpandTargets_CIDR(t *testing.T) {
	targets, err := ExpandTargets([]string{"10.0.0.0/30"}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /30 = 4 IPs (2 usable + network + broadcast), but expandCIDR returns all
	if len(targets) < 2 {
		t.Fatalf("expected at least 2 targets for /30, got %d", len(targets))
	}
}

func TestExpandTargets_InvalidTarget(t *testing.T) {
	_, err := ExpandTargets([]string{"not-a-valid-target-!!!@#$"}, 0)
	if err == nil {
		t.Fatal("expected error for invalid target, got nil")
	}
}

func TestExpandTargets_MultipleTargets(t *testing.T) {
	targets, err := ExpandTargets([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(targets))
	}
}

func TestExpandTargets_EmptyList(t *testing.T) {
	_, err := ExpandTargets([]string{}, 0)
	if err == nil {
		t.Fatal("expected error for empty target list")
	}
}

func TestExpandTargets_CommandInjection(t *testing.T) {
	// OWASP: ensure no command injection via target strings
	dangerous := []string{
		"; rm -rf /",
		"$(whoami)",
		"`id`",
		"192.168.1.1; cat /etc/passwd",
		"10.0.0.1 | ls",
		"../../../etc/passwd",
	}
	for _, d := range dangerous {
		_, err := ExpandTargets([]string{d}, 0)
		if err == nil {
			t.Errorf("expected error for dangerous target %q, got nil", d)
		}
	}
}
