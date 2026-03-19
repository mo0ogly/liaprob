package config

import "time"

// ApplyProfile overlays a named profile onto the configuration.
// Profiles provide tuned settings for common use cases.
func ApplyProfile(cfg *Config, profile ScanProfile) {
	switch profile {
	case ProfileFast:
		applyFast(cfg)
	case ProfileStandard:
		// Default values are already standard
	case ProfileThorough:
		applyThorough(cfg)
	case ProfileStealth:
		applyStealth(cfg)
	}
	cfg.Profile = profile
}

// applyFast configures for speed: top 100 ports, high concurrency, short timeouts.
func applyFast(cfg *Config) {
	cfg.PortWorkers = 500
	cfg.AliveWorkers = 100
	cfg.TargetWorkers = 50
	cfg.PortConnectTimeout = 300 * time.Millisecond
	cfg.AliveConnectTimeout = 200 * time.Millisecond
	cfg.Fingerprint.HTTPTimeoutMs = 3000
	cfg.Fingerprint.TCPTimeoutMs = 2000
	cfg.Fingerprint.TLSTimeoutMs = 3000
	cfg.Fingerprint.MaxProbesPerService = 3
	cfg.MaxReplans = 2
}

// applyThorough configures for completeness: all ports, all probes, relaxed timeouts.
func applyThorough(cfg *Config) {
	cfg.Mode = ModeFull
	cfg.PortWorkers = 100
	cfg.AliveWorkers = 30
	cfg.TargetWorkers = 10
	cfg.PortConnectTimeout = 1000 * time.Millisecond
	cfg.AliveConnectTimeout = 500 * time.Millisecond
	cfg.Fingerprint.HTTPTimeoutMs = 10000
	cfg.Fingerprint.TCPTimeoutMs = 5000
	cfg.Fingerprint.TLSTimeoutMs = 10000
	cfg.Fingerprint.SSDPTimeoutMs = 5000
	cfg.Fingerprint.MaxProbesPerService = 20
	cfg.Fingerprint.ConfidenceThreshold = 0.30
	cfg.MaxReplans = 10
}

// applyStealth configures for low network footprint: slow, randomized, minimal probes.
func applyStealth(cfg *Config) {
	cfg.PortWorkers = 5
	cfg.AliveWorkers = 3
	cfg.TargetWorkers = 2
	cfg.PortConnectTimeout = 2000 * time.Millisecond
	cfg.AliveConnectTimeout = 1000 * time.Millisecond
	cfg.Fingerprint.HTTPTimeoutMs = 10000
	cfg.Fingerprint.TCPTimeoutMs = 5000
	cfg.Fingerprint.MaxProbesPerService = 2
	cfg.Fingerprint.Parallelism = 1
	cfg.MaxReplans = 3
}
