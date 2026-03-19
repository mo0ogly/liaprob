// Package config manages LiaProbe configuration.
// Configuration can be loaded from YAML, CLI flags, environment variables, or Go code.
package config

import "time"

// ScanMode defines the scanning strategy.
type ScanMode string

const (
	// ModeSmart is the default mode: adaptive scanning with decision tree.
	// Top 100 ports -> contextual expansion -> targeted fingerprinting.
	ModeSmart ScanMode = "smart"

	// ModeFull scans all ports (1-65535) and runs all probes.
	ModeFull ScanMode = "full"

	// ModeSpecific scans only user-specified ports.
	ModeSpecific ScanMode = "specific"

	// ModeHunt searches for a specific service or banner over a wide range.
	ModeHunt ScanMode = "hunt"
)

// ScanProfile defines a pre-configured scan profile.
type ScanProfile string

const (
	ProfileFast     ScanProfile = "fast"     // Top 100 ports, passive fingerprinting only
	ProfileStandard ScanProfile = "standard" // Top 1000 + adaptive fingerprinting
	ProfileThorough ScanProfile = "thorough" // All ports + all probes
	ProfileStealth  ScanProfile = "stealth"  // Slow, randomized, low network footprint
)

// Config est la configuration complete de LiaProbe.
type Config struct {
	// Scan
	Mode    ScanMode    `yaml:"mode" json:"mode"`
	Profile ScanProfile `yaml:"profile" json:"profile"`
	Targets []string    `yaml:"targets" json:"targets"`
	Ports   []int       `yaml:"ports,omitempty" json:"ports,omitempty"`

	// Hunt mode
	HuntService string `yaml:"hunt_service,omitempty" json:"hunt_service,omitempty"`
	HuntBanner  string `yaml:"hunt_banner,omitempty" json:"hunt_banner,omitempty"`

	// Performance
	PortWorkers    int `yaml:"port_workers" json:"port_workers"`
	AliveWorkers   int `yaml:"alive_workers" json:"alive_workers"`
	TargetWorkers  int `yaml:"target_workers" json:"target_workers"`
	MaxSubdomains  int `yaml:"max_subdomains" json:"max_subdomains"`

	// Timeouts
	PortConnectTimeout  time.Duration `yaml:"port_connect_timeout" json:"port_connect_timeout"`
	AliveConnectTimeout time.Duration `yaml:"alive_connect_timeout" json:"alive_connect_timeout"`
	SubdomainTimeout    time.Duration `yaml:"subdomain_timeout" json:"subdomain_timeout"`

	// Fingerprint
	Fingerprint FingerprintConfig `yaml:"fingerprint" json:"fingerprint"`

	// AI
	AI AIConfig `yaml:"ai" json:"ai"`

	// Output
	OutputFormat string `yaml:"output_format" json:"output_format"` // "json", "table"
	OutputFile   string `yaml:"output_file,omitempty" json:"output_file,omitempty"`
	Stream       bool   `yaml:"stream" json:"stream"`

	// Store
	Store StoreConfig `yaml:"store" json:"store"`

	// Agent
	Journal      bool `yaml:"journal" json:"journal"`
	DryRun       bool `yaml:"dry_run" json:"dry_run"`
	MaxReplans   int  `yaml:"max_replans" json:"max_replans"`

	// API server mode
	APIPort int  `yaml:"api_port,omitempty" json:"api_port,omitempty"`
	Serve   bool `yaml:"serve" json:"serve"`

	// Security
	Insecure bool `yaml:"insecure" json:"insecure"` // TLS InsecureSkipVerify
}

// FingerprintConfig configure le moteur de fingerprinting.
type FingerprintConfig struct {
	PatternDirs           []PatternDirConfig `yaml:"pattern_dirs" json:"pattern_dirs"`
	HTTPTimeoutMs         int                `yaml:"http_timeout_ms" json:"http_timeout_ms"`
	TCPTimeoutMs          int                `yaml:"tcp_timeout_ms" json:"tcp_timeout_ms"`
	TLSTimeoutMs          int                `yaml:"tls_timeout_ms" json:"tls_timeout_ms"`
	SSDPTimeoutMs         int                `yaml:"ssdp_timeout_ms" json:"ssdp_timeout_ms"`
	MaxProbesPerService   int                `yaml:"max_probes_per_service" json:"max_probes_per_service"`
	MaxBodySize           int                `yaml:"max_body_size" json:"max_body_size"`
	MaxBannerSize         int                `yaml:"max_banner_size" json:"max_banner_size"`
	ConfidenceThreshold   float64            `yaml:"confidence_threshold" json:"confidence_threshold"`
	ProbesEnabled         bool               `yaml:"probes_enabled" json:"probes_enabled"`
	Parallelism           int                `yaml:"parallelism" json:"parallelism"`
}

// PatternDirConfig configure un repertoire de patterns fingerprint.
type PatternDirConfig struct {
	Path     string `yaml:"path" json:"path"`
	Source   string `yaml:"source" json:"source"`     // "lia", "nmap", "nuclei", "recog", "wappalyzer"
	Priority int    `yaml:"priority" json:"priority"` // 100=lia, 80=nmap, 60=recog, 50=nuclei, 40=wappalyzer
	Enabled  bool   `yaml:"enabled" json:"enabled"`
}

// AIConfig configure le provider IA.
type AIConfig struct {
	Enabled  bool              `yaml:"enabled" json:"enabled"`
	Provider string            `yaml:"provider" json:"provider"` // "ollama", "liasec", "openai", "anthropic", "custom", "noop"
	Endpoint string            `yaml:"endpoint" json:"endpoint"`
	Model    string            `yaml:"model" json:"model"`
	APIKey   string            `yaml:"api_key,omitempty" json:"api_key,omitempty"`
	Timeout  time.Duration     `yaml:"timeout" json:"timeout"`
	Temp     float64           `yaml:"temperature" json:"temperature"`
	MaxTok   int               `yaml:"max_tokens" json:"max_tokens"`
	Fallback []AIProviderEntry `yaml:"fallback,omitempty" json:"fallback,omitempty"`
}

// AIProviderEntry est une entree dans la fallback chain IA.
type AIProviderEntry struct {
	Provider string `yaml:"provider" json:"provider"`
	Endpoint string `yaml:"endpoint" json:"endpoint"`
	Model    string `yaml:"model" json:"model"`
	APIKey   string `yaml:"api_key,omitempty" json:"api_key,omitempty"`
}

// StoreConfig configure le backend de stockage.
type StoreConfig struct {
	Type string `yaml:"type" json:"type"` // "memory", "file", "sqlite", "postgres"
	DSN  string `yaml:"dsn,omitempty" json:"dsn,omitempty"`
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
}
