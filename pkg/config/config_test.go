package config

import (
	"os"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.Mode != ModeSmart {
		t.Errorf("expected mode smart, got %s", cfg.Mode)
	}
	if cfg.PortWorkers != DefaultPortWorkers {
		t.Errorf("expected %d workers, got %d", DefaultPortWorkers, cfg.PortWorkers)
	}
	if cfg.Fingerprint.ProbesEnabled != true {
		t.Error("expected probes enabled by default")
	}
	if cfg.AI.Enabled != false {
		t.Error("expected AI disabled by default")
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := Default()
	if err := Validate(cfg); err != nil {
		t.Errorf("default config should be valid: %v", err)
	}
}

func TestValidate_InvalidMode(t *testing.T) {
	cfg := Default()
	cfg.Mode = "invalid"
	if err := Validate(cfg); err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestValidate_HuntMode(t *testing.T) {
	cfg := Default()
	cfg.Mode = ModeHunt
	if err := Validate(cfg); err == nil {
		t.Error("expected error for hunt mode without service/banner")
	}
	cfg.HuntService = "jenkins"
	if err := Validate(cfg); err != nil {
		t.Errorf("hunt mode with service should be valid: %v", err)
	}
}

func TestValidate_SpecificMode(t *testing.T) {
	cfg := Default()
	cfg.Mode = ModeSpecific
	if err := Validate(cfg); err == nil {
		t.Error("expected error for specific mode without ports")
	}
	cfg.Ports = []int{80, 443}
	if err := Validate(cfg); err != nil {
		t.Errorf("specific mode with ports should be valid: %v", err)
	}
}

func TestValidate_InvalidPort(t *testing.T) {
	cfg := Default()
	cfg.Ports = []int{80, 99999}
	if err := Validate(cfg); err == nil {
		t.Error("expected error for port 99999")
	}
}

func TestApplyProfile_Fast(t *testing.T) {
	cfg := Default()
	ApplyProfile(cfg, ProfileFast)
	if cfg.PortWorkers != 500 {
		t.Errorf("expected 500 workers for fast, got %d", cfg.PortWorkers)
	}
	if cfg.MaxReplans != 2 {
		t.Errorf("expected 2 replans for fast, got %d", cfg.MaxReplans)
	}
}

func TestApplyProfile_Stealth(t *testing.T) {
	cfg := Default()
	ApplyProfile(cfg, ProfileStealth)
	if cfg.PortWorkers != 5 {
		t.Errorf("expected 5 workers for stealth, got %d", cfg.PortWorkers)
	}
	if cfg.Fingerprint.Parallelism != 1 {
		t.Errorf("expected 1 parallelism for stealth, got %d", cfg.Fingerprint.Parallelism)
	}
}

func TestApplyProfile_Thorough(t *testing.T) {
	cfg := Default()
	ApplyProfile(cfg, ProfileThorough)
	if cfg.Mode != ModeFull {
		t.Errorf("expected full mode for thorough, got %s", cfg.Mode)
	}
	if cfg.Fingerprint.ConfidenceThreshold != 0.30 {
		t.Errorf("expected 0.30 threshold, got %f", cfg.Fingerprint.ConfidenceThreshold)
	}
}

func TestLoadFromEnv(t *testing.T) {
	cfg := Default()
	os.Setenv("LIAPROBE_MODE", "full")
	os.Setenv("LIAPROBE_AI_PROVIDER", "ollama")
	defer os.Unsetenv("LIAPROBE_MODE")
	defer os.Unsetenv("LIAPROBE_AI_PROVIDER")

	LoadFromEnv(cfg)
	if cfg.Mode != ModeFull {
		t.Errorf("expected full mode from env, got %s", cfg.Mode)
	}
	if cfg.AI.Provider != "ollama" {
		t.Errorf("expected ollama provider from env, got %s", cfg.AI.Provider)
	}
	if !cfg.AI.Enabled {
		t.Error("expected AI enabled when provider set from env")
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	cfg, err := LoadFromFile("")
	if err != nil {
		t.Errorf("expected no error for missing file, got %v", err)
	}
	if cfg == nil {
		t.Fatal("expected default config")
	}
	if cfg.Mode != ModeSmart {
		t.Errorf("expected default smart mode")
	}
}

func TestLoadFromFile_YAML(t *testing.T) {
	tmp, err := os.CreateTemp("", "liaprobe-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	content := `mode: full
port_workers: 42
ai:
  enabled: true
  provider: ollama
  timeout: 5s
`
	if _, err := tmp.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	cfg, err := LoadFromFile(tmp.Name())
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if cfg.Mode != ModeFull {
		t.Errorf("expected full mode, got %s", cfg.Mode)
	}
	if cfg.PortWorkers != 42 {
		t.Errorf("expected 42 workers, got %d", cfg.PortWorkers)
	}
	if cfg.AI.Provider != "ollama" {
		t.Errorf("expected ollama, got %s", cfg.AI.Provider)
	}
	if cfg.AI.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", cfg.AI.Timeout)
	}
}
