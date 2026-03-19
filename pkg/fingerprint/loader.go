package fingerprint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mo0ogly/liaprobe/pkg/config"
)

// PatternLoader loads and validates fingerprinting patterns from the filesystem.
type PatternLoader struct {
	config config.FingerprintConfig
	mu     sync.RWMutex

	// Optional logger for info/warn messages.
	OnInfo func(component, action, details string)
	OnWarn func(component, action, details string)
}

// globalPatternIndex is the singleton index of loaded patterns in memory.
var (
	globalPatternIndex *PatternIndex
	patternIndexMu     sync.RWMutex
)

// GetPatternIndex returns the global thread-safe index.
func GetPatternIndex() *PatternIndex {
	patternIndexMu.RLock()
	defer patternIndexMu.RUnlock()
	return globalPatternIndex
}

// SetPatternIndex updates the global thread-safe index.
func SetPatternIndex(idx *PatternIndex) {
	patternIndexMu.Lock()
	defer patternIndexMu.Unlock()
	globalPatternIndex = idx
}

// NewPatternLoader creates a loader with the given configuration.
func NewPatternLoader(cfg config.FingerprintConfig) *PatternLoader {
	return &PatternLoader{
		config: cfg,
	}
}

// LoadAll charge tous les repertoires configures et construit l'index.
func (pl *PatternLoader) LoadAll() (*PatternIndex, error) {
	var allPatterns []*FingerprintPattern

	for _, dirConfig := range pl.config.PatternDirs {
		if !dirConfig.Enabled {
			continue
		}

		patterns, err := pl.LoadDir(dirConfig.Path, dirConfig.Source)
		if err != nil {
			pl.warn("FINGERPRINT_LOADER", "DIR_LOAD_FAILED",
				fmt.Sprintf("Failed to load %s: %v", dirConfig.Path, err))
			continue
		}

		allPatterns = append(allPatterns, patterns...)
		pl.info("FINGERPRINT_LOADER", "DIR_LOADED",
			fmt.Sprintf("Loaded %d patterns from %s (source=%s)", len(patterns), dirConfig.Path, dirConfig.Source))
	}

	if len(allPatterns) == 0 {
		pl.warn("FINGERPRINT_LOADER", "NO_PATTERNS",
			"No fingerprint patterns loaded from any directory")
	}

	index := pl.BuildIndex(allPatterns)
	return index, nil
}

// LoadDir charge tous les fichiers JSON d'un repertoire.
func (pl *PatternLoader) LoadDir(dir string, source string) ([]*FingerprintPattern, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("directory not found: %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
	}

	var patterns []*FingerprintPattern
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}

		filePath := filepath.Join(dir, entry.Name())
		filePatterns, err := pl.loadFile(filePath, source)
		if err != nil {
			pl.warn("FINGERPRINT_LOADER", "FILE_LOAD_FAILED",
				fmt.Sprintf("Skipping %s: %v", filePath, err))
			continue
		}

		for _, pattern := range filePatterns {
			if err := pl.ValidatePattern(pattern); err != nil {
				pl.warn("FINGERPRINT_LOADER", "VALIDATION_FAILED",
					fmt.Sprintf("Skipping %s/%s: %v", filePath, pattern.ID, err))
				continue
			}
			patterns = append(patterns, pattern)
		}
	}

	return patterns, nil
}

// loadFile reads and parses a JSON file into FingerprintPattern(s).
// Supports both formats:
//   - Full format: single FingerprintPattern object
//   - Simple format: array of simplified patterns (community-friendly)
func (pl *PatternLoader) loadFile(filePath string, source string) ([]*FingerprintPattern, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Trim whitespace to check first character
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty file")
	}

	var patterns []*FingerprintPattern

	if trimmed[0] == '[' {
		// Array format: try simple format first, then full format
		simplePatterns, err := parseSimplePatterns(data, filepath.Base(filePath))
		if err == nil && len(simplePatterns) > 0 {
			patterns = simplePatterns
		} else {
			// Try full format array
			var fullPatterns []*FingerprintPattern
			if err := json.Unmarshal(data, &fullPatterns); err != nil {
				return nil, fmt.Errorf("invalid JSON array: %w", err)
			}
			patterns = fullPatterns
		}
	} else {
		// Single object format (full)
		var pattern FingerprintPattern
		if err := json.Unmarshal(data, &pattern); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		patterns = append(patterns, &pattern)
	}

	// Set source and normalize
	for _, p := range patterns {
		if p.Source.Type == "" {
			p.Source.Type = source
		}
		pl.normalizePattern(p)
	}

	return patterns, nil
}

// normalizePattern applique les valeurs par defaut et filtre les probes non supportes.
func (pl *PatternLoader) normalizePattern(p *FingerprintPattern) {
	if p.TaxonomyName == "" && p.TaxonomyCode != "" {
		p.TaxonomyName = p.TaxonomyCode
	}

	supportedLayers := map[string]bool{
		"L7_HTTP": true, "L4_TCP": true, "L4_TCP_HEX": true, "TLS_CERT": true,
		"L4_UDP": true, "L4_UDP_SSDP": true, "L4_UDP_MDNS": true,
	}
	var validProbes []PatternProbe
	for _, probe := range p.Probes {
		if supportedLayers[probe.Layer] {
			validProbes = append(validProbes, probe)
		}
	}
	p.Probes = validProbes
}

// ValidatePattern verifie qu'un pattern est conforme au schema lia-fingerprint-v1.
func (pl *PatternLoader) ValidatePattern(p *FingerprintPattern) error {
	if p.Schema != "lia-fingerprint-v1" {
		return fmt.Errorf("invalid $schema: %q (expected lia-fingerprint-v1)", p.Schema)
	}
	if p.ID == "" {
		return fmt.Errorf("id is required")
	}
	if p.TaxonomyCode == "" {
		return fmt.Errorf("taxonomy_code is required")
	}
	if p.TaxonomyName == "" {
		return fmt.Errorf("taxonomy_name is required")
	}
	if !p.Enabled {
		return fmt.Errorf("pattern disabled (enabled=false)")
	}
	if p.ConfidenceThreshold <= 0 || p.ConfidenceThreshold > 1.0 {
		return fmt.Errorf("confidence_threshold must be in (0, 1.0], got %f", p.ConfidenceThreshold)
	}

	allMatchers := append(p.BannerMatchers, p.ServiceMatchers...)
	for _, probe := range p.Probes {
		allMatchers = append(allMatchers, probe.Matchers...)
	}

	for i, m := range allMatchers {
		if m.ConfidenceDelta < 0 || m.ConfidenceDelta > 1.0 {
			return fmt.Errorf("matcher[%d] confidence_delta must be in [0, 1.0], got %f", i, m.ConfidenceDelta)
		}
		if m.Target == "" {
			return fmt.Errorf("matcher[%d] target is required", i)
		}
		if m.MatchType == "" {
			return fmt.Errorf("matcher[%d] match_type is required", i)
		}
	}

	for i, probe := range p.Probes {
		if probe.ID == "" {
			return fmt.Errorf("probe[%d] id is required", i)
		}
		validLayers := map[string]bool{
			"L7_HTTP": true, "L4_TCP": true, "L4_TCP_HEX": true, "TLS_CERT": true,
			"L4_UDP": true, "L4_UDP_SSDP": true, "L4_UDP_MDNS": true,
		}
		if !validLayers[probe.Layer] {
			return fmt.Errorf("probe[%d] invalid layer: %q", i, probe.Layer)
		}
	}

	return nil
}

// BuildIndex construit les index ByPort, ByService, ByTaxonomy, ByLayer.
func (pl *PatternLoader) BuildIndex(patterns []*FingerprintPattern) *PatternIndex {
	index := &PatternIndex{
		All:        patterns,
		ByPort:     make(map[int][]*FingerprintPattern),
		ByService:  make(map[string][]*FingerprintPattern),
		ByTaxonomy: make(map[string]*FingerprintPattern),
		ByLayer:    make(map[string][]*FingerprintPattern),
		HTTPPorts:  make(map[int]bool),
		TLSPorts:   make(map[int]bool),
		Stats: PatternIndexStats{
			BySource: make(map[string]int),
			LoadedAt: time.Now(),
		},
	}

	for _, p := range patterns {
		// Index par taxonomy : priorite source superieure gagne
		if existing, exists := index.ByTaxonomy[p.TaxonomyCode]; !exists {
			index.ByTaxonomy[p.TaxonomyCode] = p
		} else if SourcePriority(p.Source.Type) > SourcePriority(existing.Source.Type) {
			index.ByTaxonomy[p.TaxonomyCode] = p
		}

		// Index par port
		for _, port := range p.DefaultPorts {
			index.ByPort[port] = append(index.ByPort[port], p)
		}
		for _, probe := range p.Probes {
			for _, port := range probe.Ports {
				if !containsPattern(index.ByPort[port], p) {
					index.ByPort[port] = append(index.ByPort[port], p)
				}
			}
		}

		// Index par service_name
		for _, m := range p.ServiceMatchers {
			if m.Target == "service_name" && m.Value != "" {
				svcLower := strings.ToLower(m.Value)
				if !containsPattern(index.ByService[svcLower], p) {
					index.ByService[svcLower] = append(index.ByService[svcLower], p)
				}
			}
		}

		// Index par layer
		layersSeen := make(map[string]bool)
		for _, probe := range p.Probes {
			if probe.Layer != "" && !layersSeen[probe.Layer] {
				layersSeen[probe.Layer] = true
				if !containsPattern(index.ByLayer[probe.Layer], p) {
					index.ByLayer[probe.Layer] = append(index.ByLayer[probe.Layer], p)
				}
			}
		}
		if len(p.BannerMatchers) > 0 && !layersSeen["L4_TCP"] {
			if !containsPattern(index.ByLayer["L4_TCP"], p) {
				index.ByLayer["L4_TCP"] = append(index.ByLayer["L4_TCP"], p)
			}
		}

		// Ports dynamiques HTTP et TLS
		for _, probe := range p.Probes {
			for _, port := range probe.Ports {
				if probe.Layer == "L7_HTTP" {
					index.HTTPPorts[port] = true
				}
				if probe.Layer == "TLS_CERT" {
					index.TLSPorts[port] = true
				}
			}
		}

		// Stats
		index.Stats.BySource[p.Source.Type]++
		index.Stats.TotalProbes += len(p.Probes)
		matcherCount := len(p.BannerMatchers) + len(p.ServiceMatchers)
		for _, probe := range p.Probes {
			matcherCount += len(probe.Matchers)
		}
		index.Stats.TotalMatchers += matcherCount
	}

	index.Stats.TotalPatterns = len(patterns)
	index.Stats.TaxonomiesCovered = len(index.ByTaxonomy)
	index.Stats.DynamicHTTPPorts = len(index.HTTPPorts)
	index.Stats.DynamicTLSPorts = len(index.TLSPorts)

	return index
}

// Reload recharge tous les patterns depuis le filesystem (hot reload).
func (pl *PatternLoader) Reload() error {
	newIndex, err := pl.LoadAll()
	if err != nil {
		return fmt.Errorf("reload failed: %w", err)
	}

	SetPatternIndex(newIndex)

	pl.info("FINGERPRINT_LOADER", "RELOAD_COMPLETE",
		fmt.Sprintf("Reloaded %d patterns (%d taxonomies, %d probes, %d matchers)",
			newIndex.Stats.TotalPatterns,
			newIndex.Stats.TaxonomiesCovered,
			newIndex.Stats.TotalProbes,
			newIndex.Stats.TotalMatchers))

	return nil
}

// containsPattern verifie si un pattern est deja dans une slice (par ID).
func containsPattern(patterns []*FingerprintPattern, p *FingerprintPattern) bool {
	for _, existing := range patterns {
		if existing.ID == p.ID {
			return true
		}
	}
	return false
}

// info appelle le logger info optionnel.
func (pl *PatternLoader) info(component, action, details string) {
	if pl.OnInfo != nil {
		pl.OnInfo(component, action, details)
	}
}

// warn appelle le logger warn optionnel.
func (pl *PatternLoader) warn(component, action, details string) {
	if pl.OnWarn != nil {
		pl.OnWarn(component, action, details)
	}
}
