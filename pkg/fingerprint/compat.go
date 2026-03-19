// Package fingerprint - compatibility layer for simple pattern format.
//
// The simple format is designed for easy community contribution:
//
//	[{
//	  "id": "lia-openssh",
//	  "schema": "lia-fingerprint-v1",
//	  "taxonomy_code": "INFRA.OPENSSH",
//	  "taxonomy_name": "OpenSSH",
//	  "source": "lia",
//	  "default_ports": [22],
//	  "matchers": [
//	    {"field": "tcp_banner", "match_type": "startswith", "value": "SSH-2.0-OpenSSH", "confidence_delta": 0.7}
//	  ],
//	  "cpe_template": "cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*"
//	}]
//
// This file converts that format into the full FingerprintPattern model.
package fingerprint

import (
	"encoding/json"
	"fmt"
	"strings"
)

// simplePattern is the simplified JSON pattern format.
type simplePattern struct {
	ID           string         `json:"id"`
	Schema       string         `json:"schema"`
	TaxonomyCode string         `json:"taxonomy_code"`
	TaxonomyName string         `json:"taxonomy_name"`
	Source       string          `json:"source"`
	Priority     int            `json:"priority"`
	DefaultPorts []int          `json:"default_ports"`
	Probes       []simpleProbe  `json:"probes"`
	Matchers     []simpleMatcher `json:"matchers"`
	CPETemplate  string         `json:"cpe_template"`
}

// simpleProbe is a probe in the simple format.
type simpleProbe struct {
	Layer     string `json:"layer"`
	Path      string `json:"path,omitempty"`
	Method    string `json:"method,omitempty"`
	Send      string `json:"send,omitempty"`
	ReadBytes int    `json:"read_bytes,omitempty"`
	Ports     []int  `json:"ports,omitempty"`
}

// simpleMatcher is a matcher in the simple format.
type simpleMatcher struct {
	Field           string  `json:"field"`
	MatchType       string  `json:"match_type"`
	Value           string  `json:"value"`
	ConfidenceDelta float64 `json:"confidence_delta"`
	VersionGroup    int     `json:"version_group,omitempty"`
}

// parseSimplePatterns attempts to parse data as an array of simple patterns.
// Returns nil if the data doesn't match the simple format.
func parseSimplePatterns(data []byte, sourceFile string) ([]*FingerprintPattern, error) {
	var simples []simplePattern
	if err := json.Unmarshal(data, &simples); err != nil {
		return nil, err
	}

	if len(simples) == 0 {
		return nil, fmt.Errorf("empty pattern array")
	}

	// Verify it's actually simple format (has "matchers" field, not "banner_matchers")
	if simples[0].Schema == "" && simples[0].ID == "" {
		return nil, fmt.Errorf("not a valid simple pattern format")
	}

	var results []*FingerprintPattern
	for _, sp := range simples {
		fp, err := convertSimpleToFull(sp, sourceFile)
		if err != nil {
			continue
		}
		results = append(results, fp)
	}

	return results, nil
}

// convertSimpleToFull converts a simple pattern to the full FingerprintPattern model.
func convertSimpleToFull(sp simplePattern, sourceFile string) (*FingerprintPattern, error) {
	fp := &FingerprintPattern{
		Schema:              sp.Schema,
		ID:                  sp.ID,
		Enabled:             true,
		TaxonomyCode:        sp.TaxonomyCode,
		TaxonomyName:        sp.TaxonomyName,
		DefaultPorts:        sp.DefaultPorts,
		BaseConfidence:      0.0,
		ConfidenceThreshold: 0.50,
		CPE23:               sp.CPETemplate,
		Source: PatternSource{
			Type: sp.Source,
			File: sourceFile,
		},
	}

	// Convert probes
	probesByLayer := make(map[string]*PatternProbe)
	for i, sp := range sp.Probes {
		probeID := fmt.Sprintf("probe-%d-%s", i, strings.ToLower(sp.Layer))
		probe := PatternProbe{
			ID:     probeID,
			Layer:  sp.Layer,
			Path:   sp.Path,
			Method: sp.Method,
			Send:   sp.Send,
			Ports:  sp.Ports,
		}
		fp.Probes = append(fp.Probes, probe)
		probesByLayer[sp.Layer] = &fp.Probes[len(fp.Probes)-1]
	}

	// Distribute matchers
	for _, sm := range sp.Matchers {
		matcher := convertSimpleMatcher(sm)

		field := sm.Field
		switch {
		case field == "tcp_banner":
			matcher.Target = "banner"
			fp.BannerMatchers = append(fp.BannerMatchers, matcher)

		case field == "http_body":
			matcher.Target = "body"
			attachMatcherToProbe(fp, "L7_HTTP", matcher)

		case strings.HasPrefix(field, "http_header."):
			headerName := strings.TrimPrefix(field, "http_header.")
			matcher.Target = "header"
			matcher.Field = headerName
			attachMatcherToProbe(fp, "L7_HTTP", matcher)

		case field == "http_status":
			matcher.Target = "status_code"
			attachMatcherToProbe(fp, "L7_HTTP", matcher)

		case strings.HasPrefix(field, "json_field."):
			jsonField := strings.TrimPrefix(field, "json_field.")
			matcher.Target = "json_field"
			matcher.Field = jsonField
			attachMatcherToProbe(fp, "L7_HTTP", matcher)

		case field == "ssl_cn" || field == "ssl_san":
			matcher.Target = field
			attachMatcherToProbe(fp, "TLS_CERT", matcher)

		case field == "ssdp_header" || field == "ssdp_raw":
			matcher.Target = field
			attachMatcherToProbe(fp, "L4_UDP_SSDP", matcher)

		default:
			// Fallback: treat as banner matcher
			matcher.Target = "banner"
			fp.BannerMatchers = append(fp.BannerMatchers, matcher)
		}
	}

	return fp, nil
}

// convertSimpleMatcher converts a simple matcher to a full PatternMatcher.
func convertSimpleMatcher(sm simpleMatcher) PatternMatcher {
	pm := PatternMatcher{
		MatchType:       normalizeMatchType(sm.MatchType),
		Value:           sm.Value,
		ConfidenceDelta: sm.ConfidenceDelta,
	}

	// Version extraction: if version_group is set and match_type is regex,
	// use the value as version_extract pattern
	if sm.VersionGroup > 0 && sm.MatchType == "regex" {
		pm.VersionExtract = sm.Value
		pm.VersionExtractGroup = sm.VersionGroup
	}

	return pm
}

// normalizeMatchType maps simple match types to full model match types.
func normalizeMatchType(mt string) string {
	switch mt {
	case "startswith":
		return "starts_with"
	case "endswith":
		return "ends_with"
	default:
		return mt
	}
}

// attachMatcherToProbe attaches a matcher to the first probe of the given layer.
// If no probe exists for that layer, creates one.
func attachMatcherToProbe(fp *FingerprintPattern, layer string, matcher PatternMatcher) {
	for i := range fp.Probes {
		if fp.Probes[i].Layer == layer {
			fp.Probes[i].Matchers = append(fp.Probes[i].Matchers, matcher)
			return
		}
	}

	// Create a probe for this layer
	probe := PatternProbe{
		ID:       fmt.Sprintf("auto-%s", strings.ToLower(layer)),
		Layer:    layer,
		Matchers: []PatternMatcher{matcher},
	}
	if layer == "L7_HTTP" {
		probe.Method = "GET"
		probe.Path = "/"
	}
	fp.Probes = append(fp.Probes, probe)
}
