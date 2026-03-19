// Package scanner provides the TCP/UDP network scanning engine for LiaProbe.
// Pure Go scanner: zero nmap dependency, zero CGO, zero shell.
package scanner

import "time"

// Target represents a resolved target (IP + optional hostname).
type Target struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
}

// OpenPort represents an open port discovered by TCP connect.
type OpenPort struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "tcp" or "udp"
	Banner   string `json:"banner,omitempty"`
}

// HostResult represents the complete result of a scanned host.
type HostResult struct {
	Target    Target        `json:"target"`
	Alive     bool          `json:"alive"`
	OpenPorts []OpenPort    `json:"open_ports"`
	Services  []ServiceInfo `json:"services,omitempty"`
	Duration  time.Duration `json:"duration"`
}

// ServiceInfo represents an identified technology on a host.
type ServiceInfo struct {
	Port       int     `json:"port"`
	Name       string  `json:"name"`
	Product    string  `json:"product,omitempty"`
	Version    string  `json:"version,omitempty"`
	CPE        string  `json:"cpe,omitempty"`
	Confidence float64 `json:"confidence"`
	PatternID  string  `json:"pattern_id,omitempty"`
}

// ScanResult represents the overall result of a scan.
type ScanResult struct {
	ID          string        `json:"id"`
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt time.Time     `json:"completed_at"`
	Hosts       []HostResult  `json:"hosts"`
	Stats       ScanStats     `json:"stats"`
	AIAnalysis  string        `json:"ai_analysis,omitempty"`
}

// HostResult represents the complete result of a scanned host.
// (extended with services)

// ScanStats summarizes scan metrics.
type ScanStats struct {
	TotalTargets      int   `json:"total_targets"`
	HostsAlive        int   `json:"hosts_alive"`
	PortsOpen         int   `json:"ports_open"`
	TechnologiesFound int   `json:"technologies_found"`
	DurationMs        int64 `json:"duration_ms"`
	Replans           int   `json:"replans,omitempty"`
	AIQueries         int   `json:"ai_queries,omitempty"`
}
