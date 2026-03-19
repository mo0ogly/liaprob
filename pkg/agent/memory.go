package agent

import (
	"sync"
)

// HostState is the complete state of a host in working memory.
type HostState struct {
	IP        string     `json:"ip"`
	Hostname  string     `json:"hostname,omitempty"`
	Alive     bool       `json:"alive"`
	OpenPorts []PortState `json:"open_ports"`
	Services  []ServiceState `json:"services"`
}

// PortState is the state of a port in working memory.
type PortState struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Banner   string `json:"banner,omitempty"`
	State    string `json:"state"` // "open", "closed", "filtered"
}

// ServiceState is the state of an identified service in working memory.
type ServiceState struct {
	Port       int     `json:"port"`
	Name       string  `json:"name"`
	Product    string  `json:"product,omitempty"`
	Version    string  `json:"version,omitempty"`
	CPE        string  `json:"cpe,omitempty"`
	Confidence float64 `json:"confidence"`
	PatternID  string  `json:"pattern_id,omitempty"`
}

// Hypothesis is an AI hypothesis pending validation.
type Hypothesis struct {
	Target     string  `json:"target"`
	Port       int     `json:"port,omitempty"`
	Content    string  `json:"content"`
	Confidence float64 `json:"confidence"`
	Provider   string  `json:"provider"`
	Validated  bool    `json:"validated"`
}

// WorkingMemory is the agent's working memory during a scan.
// Thread-safe. Contains real-time discovered state.
type WorkingMemory struct {
	mu          sync.RWMutex
	Hosts       map[string]*HostState  `json:"hosts"`       // IP -> state
	Hypotheses  []Hypothesis           `json:"hypotheses"`
	Stats       MemoryStats            `json:"stats"`
	AIAnalysis  string                 `json:"ai_analysis,omitempty"`
}

// MemoryStats are real-time counters.
type MemoryStats struct {
	TargetsTotal      int `json:"targets_total"`
	HostsAlive        int `json:"hosts_alive"`
	PortsScanned      int `json:"ports_scanned"`
	PortsOpen         int `json:"ports_open"`
	ServicesIdentified int `json:"services_identified"`
	BannersGrabbed    int `json:"banners_grabbed"`
	AIQueries         int `json:"ai_queries"`
	Replans           int `json:"replans"`
}

// NewWorkingMemory creates an empty working memory.
func NewWorkingMemory() *WorkingMemory {
	return &WorkingMemory{
		Hosts: make(map[string]*HostState),
	}
}

// AddHost records a host in memory.
func (wm *WorkingMemory) AddHost(ip, hostname string, alive bool) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.Hosts[ip] = &HostState{
		IP:       ip,
		Hostname: hostname,
		Alive:    alive,
	}
	if alive {
		wm.Stats.HostsAlive++
	}
}

// AddOpenPort records an open port for a host. Deduplicates by port number.
func (wm *WorkingMemory) AddOpenPort(ip string, port int, protocol, banner string) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	host, ok := wm.Hosts[ip]
	if !ok {
		host = &HostState{IP: ip, Alive: true}
		wm.Hosts[ip] = host
	}
	// Deduplicate: if port already exists, update banner if new one is non-empty
	for i, p := range host.OpenPorts {
		if p.Port == port {
			if banner != "" && p.Banner == "" {
				host.OpenPorts[i].Banner = banner
				wm.Stats.BannersGrabbed++
			}
			return
		}
	}
	host.OpenPorts = append(host.OpenPorts, PortState{
		Port:     port,
		Protocol: protocol,
		Banner:   banner,
		State:    "open",
	})
	wm.Stats.PortsOpen++
	if banner != "" {
		wm.Stats.BannersGrabbed++
	}
}

// AddService records an identified service.
func (wm *WorkingMemory) AddService(ip string, svc ServiceState) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	host, ok := wm.Hosts[ip]
	if !ok {
		return
	}
	host.Services = append(host.Services, svc)
	wm.Stats.ServicesIdentified++
}

// AddHypothesis records an AI hypothesis.
func (wm *WorkingMemory) AddHypothesis(h Hypothesis) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.Hypotheses = append(wm.Hypotheses, h)
}

// GetHost returns the state of a host (nil if unknown).
func (wm *WorkingMemory) GetHost(ip string) *HostState {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	return wm.Hosts[ip]
}

// GetStats returns a copy of the stats.
func (wm *WorkingMemory) GetStats() MemoryStats {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	return wm.Stats
}

// OpenPortsForHost returns the open ports of a host.
func (wm *WorkingMemory) OpenPortsForHost(ip string) []PortState {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	host, ok := wm.Hosts[ip]
	if !ok {
		return nil
	}
	cp := make([]PortState, len(host.OpenPorts))
	copy(cp, host.OpenPorts)
	return cp
}
