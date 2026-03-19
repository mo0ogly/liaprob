package config

import (
	"fmt"
	"strings"
)

// Validate checks the configuration for errors.
// Returns nil if valid, or an error describing the first issue found.
func Validate(cfg *Config) error {
	// Mode
	validModes := map[ScanMode]bool{
		ModeSmart: true, ModeFull: true, ModeSpecific: true, ModeHunt: true,
	}
	if !validModes[cfg.Mode] {
		return fmt.Errorf("invalid mode: %q (valid: smart, full, specific, hunt)", cfg.Mode)
	}

	// Hunt mode requires service or banner
	if cfg.Mode == ModeHunt {
		if cfg.HuntService == "" && cfg.HuntBanner == "" {
			return fmt.Errorf("hunt mode requires --hunt-service or --hunt-banner")
		}
	}

	// Specific mode requires ports
	if cfg.Mode == ModeSpecific && len(cfg.Ports) == 0 {
		return fmt.Errorf("specific mode requires --ports")
	}

	// Workers
	if cfg.PortWorkers < 1 || cfg.PortWorkers > 10000 {
		return fmt.Errorf("port_workers must be between 1 and 10000, got %d", cfg.PortWorkers)
	}
	if cfg.AliveWorkers < 1 || cfg.AliveWorkers > 1000 {
		return fmt.Errorf("alive_workers must be between 1 and 1000, got %d", cfg.AliveWorkers)
	}

	// Timeouts
	if cfg.PortConnectTimeout <= 0 {
		return fmt.Errorf("port_connect_timeout must be positive")
	}

	// Ports range
	for _, p := range cfg.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("invalid port: %d (must be 1-65535)", p)
		}
	}

	// API port
	if cfg.Serve && (cfg.APIPort < 1 || cfg.APIPort > 65535) {
		return fmt.Errorf("api_port must be between 1 and 65535, got %d", cfg.APIPort)
	}

	// Fingerprint
	if cfg.Fingerprint.ConfidenceThreshold < 0 || cfg.Fingerprint.ConfidenceThreshold > 1.0 {
		return fmt.Errorf("confidence_threshold must be between 0 and 1.0")
	}

	// AI
	if cfg.AI.Enabled {
		validProviders := []string{"ollama", "openai", "groq", "custom", "liasec", "anthropic", "noop"}
		found := false
		for _, vp := range validProviders {
			if cfg.AI.Provider == vp {
				found = true
				break
			}
		}
		if !found && cfg.AI.Provider != "" {
			return fmt.Errorf("invalid AI provider: %q (valid: %s)", cfg.AI.Provider, strings.Join(validProviders, ", "))
		}
	}

	// Store
	validStores := map[string]bool{"memory": true, "file": true, "sqlite": true, "postgres": true}
	if !validStores[cfg.Store.Type] {
		return fmt.Errorf("invalid store type: %q (valid: memory, file, sqlite, postgres)", cfg.Store.Type)
	}

	return nil
}
