package fingerprint

import (
	"encoding/json"
	"testing"
)

func TestParseSimplePatterns_OpenSSH(t *testing.T) {
	data := `[{
		"id": "lia-openssh",
		"schema": "lia-fingerprint-v1",
		"taxonomy_code": "INFRA.OPENSSH",
		"taxonomy_name": "OpenSSH",
		"source": "lia",
		"priority": 100,
		"default_ports": [22, 2222],
		"probes": [{"layer": "L4_TCP", "send": "", "read_bytes": 256}],
		"matchers": [
			{"field": "tcp_banner", "match_type": "startswith", "value": "SSH-2.0-OpenSSH", "confidence_delta": 0.7},
			{"field": "tcp_banner", "match_type": "regex", "value": "OpenSSH_([\\d.p]+)", "confidence_delta": 0.3, "version_group": 1}
		],
		"cpe_template": "cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*"
	}]`

	patterns, err := parseSimplePatterns([]byte(data), "test.json")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(patterns) != 1 {
		t.Fatalf("expected 1 pattern, got %d", len(patterns))
	}

	p := patterns[0]
	if p.ID != "lia-openssh" {
		t.Errorf("expected id lia-openssh, got %s", p.ID)
	}
	if p.Schema != "lia-fingerprint-v1" {
		t.Errorf("expected schema lia-fingerprint-v1, got %s", p.Schema)
	}
	if !p.Enabled {
		t.Error("expected enabled=true")
	}
	if p.ConfidenceThreshold != 0.50 {
		t.Errorf("expected threshold 0.50, got %f", p.ConfidenceThreshold)
	}
	if p.Source.Type != "lia" {
		t.Errorf("expected source type lia, got %s", p.Source.Type)
	}
	if p.CPE23 != "cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*" {
		t.Errorf("unexpected CPE: %s", p.CPE23)
	}

	// Banner matchers
	if len(p.BannerMatchers) != 2 {
		t.Fatalf("expected 2 banner matchers, got %d", len(p.BannerMatchers))
	}
	if p.BannerMatchers[0].MatchType != "starts_with" {
		t.Errorf("expected starts_with, got %s", p.BannerMatchers[0].MatchType)
	}
	if p.BannerMatchers[1].VersionExtractGroup != 1 {
		t.Errorf("expected version_group 1, got %d", p.BannerMatchers[1].VersionExtractGroup)
	}
}

func TestParseSimplePatterns_HTTPMatchers(t *testing.T) {
	data := `[{
		"id": "lia-jenkins",
		"schema": "lia-fingerprint-v1",
		"taxonomy_code": "CI.JENKINS",
		"taxonomy_name": "Jenkins",
		"source": "lia",
		"default_ports": [8080],
		"probes": [{"layer": "L7_HTTP", "path": "/", "method": "GET"}],
		"matchers": [
			{"field": "http_header.X-Jenkins", "match_type": "exists", "value": "", "confidence_delta": 0.7},
			{"field": "http_header.X-Jenkins", "match_type": "regex", "value": "([\\d.]+)", "confidence_delta": 0.3, "version_group": 1}
		],
		"cpe_template": "cpe:2.3:a:jenkins:jenkins:{version}:*:*:*:*:*:*:*"
	}]`

	patterns, err := parseSimplePatterns([]byte(data), "test.json")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	p := patterns[0]

	// HTTP header matchers should be on the probe
	if len(p.BannerMatchers) != 0 {
		t.Errorf("expected 0 banner matchers, got %d", len(p.BannerMatchers))
	}

	// Find the HTTP probe
	var httpProbe *PatternProbe
	for i := range p.Probes {
		if p.Probes[i].Layer == "L7_HTTP" {
			httpProbe = &p.Probes[i]
			break
		}
	}
	if httpProbe == nil {
		t.Fatal("expected HTTP probe")
	}
	if len(httpProbe.Matchers) != 2 {
		t.Fatalf("expected 2 matchers on HTTP probe, got %d", len(httpProbe.Matchers))
	}
	if httpProbe.Matchers[0].Target != "header" {
		t.Errorf("expected target header, got %s", httpProbe.Matchers[0].Target)
	}
	if httpProbe.Matchers[0].Field != "X-Jenkins" {
		t.Errorf("expected field X-Jenkins, got %s", httpProbe.Matchers[0].Field)
	}
}

func TestParseSimplePatterns_MultipleInArray(t *testing.T) {
	data := `[
		{"id": "a", "schema": "lia-fingerprint-v1", "taxonomy_code": "A", "taxonomy_name": "A", "source": "lia", "default_ports": [1], "matchers": [], "cpe_template": ""},
		{"id": "b", "schema": "lia-fingerprint-v1", "taxonomy_code": "B", "taxonomy_name": "B", "source": "lia", "default_ports": [2], "matchers": [], "cpe_template": ""}
	]`

	patterns, err := parseSimplePatterns([]byte(data), "test.json")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(patterns) != 2 {
		t.Errorf("expected 2 patterns, got %d", len(patterns))
	}
}

func TestConvertSimpleToFull_Serializable(t *testing.T) {
	sp := simplePattern{
		ID:           "test",
		Schema:       "lia-fingerprint-v1",
		TaxonomyCode: "TEST",
		TaxonomyName: "Test",
		Source:       "lia",
		DefaultPorts: []int{80},
	}

	fp, err := convertSimpleToFull(sp, "test.json")
	if err != nil {
		t.Fatal(err)
	}

	// Must be JSON-serializable
	_, err = json.Marshal(fp)
	if err != nil {
		t.Errorf("failed to marshal: %v", err)
	}
}
