package agent

import (
	"testing"
)

func TestWorkingMemory_AddHost(t *testing.T) {
	wm := NewWorkingMemory()
	wm.AddHost("10.0.0.1", "server1", true)

	host := wm.GetHost("10.0.0.1")
	if host == nil {
		t.Fatal("host not found")
	}
	if host.IP != "10.0.0.1" {
		t.Errorf("expected IP 10.0.0.1, got %s", host.IP)
	}
	if host.Hostname != "server1" {
		t.Errorf("expected hostname server1, got %s", host.Hostname)
	}
	if !host.Alive {
		t.Error("expected host to be alive")
	}

	stats := wm.GetStats()
	if stats.HostsAlive != 1 {
		t.Errorf("expected 1 alive host, got %d", stats.HostsAlive)
	}
}

func TestWorkingMemory_AddOpenPort(t *testing.T) {
	wm := NewWorkingMemory()
	wm.AddHost("10.0.0.1", "", true)
	wm.AddOpenPort("10.0.0.1", 80, "tcp", "HTTP/1.1 200 OK")
	wm.AddOpenPort("10.0.0.1", 443, "tcp", "")

	ports := wm.OpenPortsForHost("10.0.0.1")
	if len(ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(ports))
	}

	stats := wm.GetStats()
	if stats.PortsOpen != 2 {
		t.Errorf("expected 2 open ports, got %d", stats.PortsOpen)
	}
	if stats.BannersGrabbed != 1 {
		t.Errorf("expected 1 banner grabbed, got %d", stats.BannersGrabbed)
	}
}

func TestWorkingMemory_AddService(t *testing.T) {
	wm := NewWorkingMemory()
	wm.AddHost("10.0.0.1", "", true)
	wm.AddService("10.0.0.1", ServiceState{
		Port:       80,
		Name:       "nginx",
		Version:    "1.24.0",
		Confidence: 0.95,
	})

	host := wm.GetHost("10.0.0.1")
	if len(host.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(host.Services))
	}
	if host.Services[0].Name != "nginx" {
		t.Errorf("expected nginx, got %s", host.Services[0].Name)
	}

	stats := wm.GetStats()
	if stats.ServicesIdentified != 1 {
		t.Errorf("expected 1 service identified, got %d", stats.ServicesIdentified)
	}
}

func TestWorkingMemory_AddOpenPort_AutoCreateHost(t *testing.T) {
	wm := NewWorkingMemory()
	// Adding port without prior AddHost should auto-create
	wm.AddOpenPort("10.0.0.5", 22, "tcp", "OpenSSH_8.9")

	host := wm.GetHost("10.0.0.5")
	if host == nil {
		t.Fatal("host should be auto-created")
	}
	if len(host.OpenPorts) != 1 {
		t.Errorf("expected 1 port, got %d", len(host.OpenPorts))
	}
}

func TestWorkingMemory_GetHost_Unknown(t *testing.T) {
	wm := NewWorkingMemory()
	host := wm.GetHost("1.2.3.4")
	if host != nil {
		t.Error("expected nil for unknown host")
	}
}

func TestWorkingMemory_AddService_UnknownHost(t *testing.T) {
	wm := NewWorkingMemory()
	// Should not panic on unknown host
	wm.AddService("1.2.3.4", ServiceState{Port: 80, Name: "test"})
	stats := wm.GetStats()
	if stats.ServicesIdentified != 0 {
		t.Error("should not add service for unknown host")
	}
}
