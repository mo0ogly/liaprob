// Package config - YAML configuration file loader.
//
// Configuration priority (highest wins):
//
//	CLI flags > Environment variables > YAML file > Defaults
//
// The loader searches for liaprobe.yaml in:
//  1. Explicit --config path
//  2. Current directory
//  3. $HOME/.config/liaprobe/
//  4. /etc/liaprobe/
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// searchPaths are the default locations for the config file.
var searchPaths = []string{
	"liaprobe.yaml",
	"liaprobe.yml",
}

// LoadFromFile loads configuration from a YAML file.
// Returns the config and nil error, or default config if file not found.
func LoadFromFile(path string) (*Config, error) {
	if path == "" {
		path = findConfigFile()
	}

	if path == "" {
		return Default(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	return cfg, nil
}

// findConfigFile searches for a config file in standard locations.
func findConfigFile() string {
	// Current directory
	for _, name := range searchPaths {
		if _, err := os.Stat(name); err == nil {
			return name
		}
	}

	// Home config directory
	home, err := os.UserHomeDir()
	if err == nil {
		for _, name := range searchPaths {
			p := filepath.Join(home, ".config", "liaprobe", name)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}

	// System config directory
	for _, name := range searchPaths {
		p := filepath.Join("/etc", "liaprobe", name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

// LoadFromEnv overlays environment variables onto a config.
func LoadFromEnv(cfg *Config) {
	if v := os.Getenv("LIAPROBE_MODE"); v != "" {
		cfg.Mode = ScanMode(v)
	}
	if v := os.Getenv("LIAPROBE_AI_PROVIDER"); v != "" {
		cfg.AI.Provider = v
		cfg.AI.Enabled = true
	}
	if v := os.Getenv("LIAPROBE_AI_ENDPOINT"); v != "" {
		cfg.AI.Endpoint = v
	}
	if v := os.Getenv("LIAPROBE_AI_MODEL"); v != "" {
		cfg.AI.Model = v
	}
	if v := os.Getenv("LIAPROBE_AI_KEY"); v != "" {
		cfg.AI.APIKey = v
	}
	if v := os.Getenv("LIAPROBE_STORE_TYPE"); v != "" {
		cfg.Store.Type = v
	}
	if v := os.Getenv("LIAPROBE_STORE_DSN"); v != "" {
		cfg.Store.DSN = v
	}
}
