package fingerprint

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/mo0ogly/liaprob/pkg/config"
)

// patternTestCase defines a test case for a fingerprint pattern.
type patternTestCase struct {
	PatternID       string
	Description     string
	Data            *CollectedServiceData
	ExpectMatch     bool
	MinConfidence   float64
	ExpectVersion   string // empty = don't check
	ExpectTaxonomy  string
}

// loadTestPatterns loads all patterns from the patterns/lia/ directory.
func loadTestPatterns(t *testing.T) []*FingerprintPattern {
	t.Helper()
	// Find patterns dir relative to this test file
	dirs := []string{
		"../../patterns/lia",
		"../../../patterns/lia",
		"patterns/lia",
	}
	var patternsDir string
	for _, d := range dirs {
		if _, err := os.Stat(d); err == nil {
			patternsDir = d
			break
		}
	}
	if patternsDir == "" {
		t.Fatal("Cannot find patterns/lia/ directory")
	}

	var allPatterns []*FingerprintPattern
	files, _ := filepath.Glob(filepath.Join(patternsDir, "*.json"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("Failed to read %s: %v", f, err)
		}
		patterns, err := parseSimplePatterns(data, f)
		if err != nil {
			t.Fatalf("Failed to parse %s: %v", f, err)
		}
		allPatterns = append(allPatterns, patterns...)
	}
	return allPatterns
}

// findPattern finds a pattern by ID from the loaded patterns.
func findPattern(patterns []*FingerprintPattern, id string) *FingerprintPattern {
	for _, p := range patterns {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// httpData creates CollectedServiceData with an HTTP response for the pattern's first probe.
func httpData(port int, statusCode int, headers map[string]string, body string, pattern *FingerprintPattern) *CollectedServiceData {
	probeID := "auto-l7_http"
	for _, p := range pattern.Probes {
		if p.Layer == "L7_HTTP" {
			probeID = p.ID
			break
		}
	}
	return &CollectedServiceData{
		Port: port,
		HTTPResponses: map[string]*HTTPProbeResponse{
			probeID: {
				StatusCode: statusCode,
				Headers:    headers,
				Body:       body,
			},
		},
	}
}

// tcpData creates CollectedServiceData with a TCP banner.
func tcpData(port int, banner string) *CollectedServiceData {
	return &CollectedServiceData{
		Port:   port,
		Banner: banner,
	}
}

// tcpProbeData creates CollectedServiceData with a TCP probe response.
func tcpProbeData(port int, probeID string, response string) *CollectedServiceData {
	return &CollectedServiceData{
		Port: port,
		TCPResponses: map[string]*TCPProbeResponse{
			probeID: {Data: response},
		},
	}
}

// tcpBannerAndProbe creates CollectedServiceData with both banner and TCP probe response.
func tcpBannerAndProbe(port int, banner string, probeID string, response string) *CollectedServiceData {
	return &CollectedServiceData{
		Port:   port,
		Banner: banner,
		TCPResponses: map[string]*TCPProbeResponse{
			probeID: {Data: response},
		},
	}
}

func TestAllPatterns_Load(t *testing.T) {
	patterns := loadTestPatterns(t)
	if len(patterns) == 0 {
		t.Fatal("No patterns loaded")
	}
	t.Logf("Loaded %d patterns", len(patterns))

	// Verify each pattern has required fields
	for _, p := range patterns {
		if p.ID == "" {
			t.Error("Pattern with empty ID found")
		}
		if p.TaxonomyCode == "" {
			t.Errorf("Pattern %s has empty taxonomy_code", p.ID)
		}
		if p.TaxonomyName == "" {
			t.Errorf("Pattern %s has empty taxonomy_name", p.ID)
		}
		if len(p.DefaultPorts) == 0 {
			t.Errorf("Pattern %s has no default_ports", p.ID)
		}
		hasMatcher := len(p.BannerMatchers) > 0
		for _, probe := range p.Probes {
			if len(probe.Matchers) > 0 {
				hasMatcher = true
			}
		}
		if !hasMatcher {
			t.Errorf("Pattern %s has no matchers", p.ID)
		}
	}
}

func TestAllPatterns_NoDuplicateIDs(t *testing.T) {
	patterns := loadTestPatterns(t)
	seen := make(map[string]int)
	for _, p := range patterns {
		seen[p.ID]++
	}
	for id, count := range seen {
		if count > 1 {
			t.Errorf("Duplicate pattern ID: %s (appears %d times)", id, count)
		}
	}
}

func TestPatterns_BannerMatching(t *testing.T) {
	patterns := loadTestPatterns(t)
	matcher := NewFingerprintMatcher()

	tests := []patternTestCase{
		// === DATABASES ===
		{
			PatternID:     "lia-mysql",
			Description:   "MySQL 8.0 binary handshake with caching_sha2_password",
			Data:          tcpData(3306, "J\x00\x00\x00\x0a8.0.45\x00caching_sha2_password\x00"),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "8.0.45",
			ExpectTaxonomy: "MySQL",
		},
		{
			PatternID:     "lia-mysql",
			Description:   "MySQL 5.7 with mysql_native_password",
			Data:          tcpData(3306, "J\x00\x00\x00\x0a5.7.42\x00mysql_native_password\x00"),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "5.7.42",
			ExpectTaxonomy: "MySQL",
		},
		{
			PatternID:     "lia-mariadb",
			Description:   "MariaDB 11.2 banner",
			Data:          tcpData(3306, "J\x00\x00\x00\x0a11.2.3-MariaDB\x00"),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "11.2.3",
			ExpectTaxonomy: "MariaDB",
		},
		{
			PatternID:     "lia-redis",
			Description:   "Redis PONG response",
			Data:          tcpData(6379, "+PONG\r\n"),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectTaxonomy: "Redis",
		},
		{
			PatternID:     "lia-redis",
			Description:   "Redis NOAUTH response",
			Data:          tcpData(6379, "-NOAUTH Authentication required.\r\n"),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectTaxonomy: "Redis",
		},
		{
			PatternID:     "lia-postgresql",
			Description:   "PostgreSQL error response with SCRAM",
			Data:          tcpData(5432, "EFATAL\x00SCRAM-SHA-256\x00authentication\x00"),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectTaxonomy: "PostgreSQL",
		},
		{
			PatternID:     "lia-mssql",
			Description:   "Microsoft SQL Server banner",
			Data:          tcpData(1433, "\x04\x01Microsoft SQL Server\x00"),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectTaxonomy: "Microsoft SQL Server",
		},
		{
			PatternID:     "lia-mongodb",
			Description:   "MongoDB HTTP error page",
			Data: httpData(27017, 200, map[string]string{}, "It looks like you are trying to access MongoDB over HTTP on the native driver port.", findPattern(patterns, "lia-mongodb")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectTaxonomy: "MongoDB",
		},

		// === INFRASTRUCTURE ===
		{
			PatternID:     "lia-openssh",
			Description:   "OpenSSH 9.6p1 banner",
			Data:          tcpData(22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu1\r\n"),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "9.6p1",
			ExpectTaxonomy: "OpenSSH",
		},
		{
			PatternID:     "lia-openssh",
			Description:   "OpenSSH 8.9p1 banner",
			Data:          tcpData(22, "SSH-2.0-OpenSSH_8.9p1 Debian-5\r\n"),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "8.9p1",
			ExpectTaxonomy: "OpenSSH",
		},
		{
			PatternID:     "lia-vsftpd",
			Description:   "vsFTPd 3.0.5 banner",
			Data:          tcpData(21, "220 (vsFTPd 3.0.5)\r\n"),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "3.0.5",
			ExpectTaxonomy: "vsftpd",
		},
		{
			PatternID:     "lia-postfix",
			Description:   "Postfix SMTP banner",
			Data:          tcpData(25, "220 mail.example.org ESMTP Postfix\r\n"),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectTaxonomy: "Postfix",
		},
		{
			PatternID:     "lia-rabbitmq",
			Description:   "RabbitMQ AMQP banner",
			Data:          tcpData(5672, "AMQP\x00\x00\x09\x01"),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectTaxonomy: "RabbitMQ",
		},
		{
			PatternID:     "lia-rabbitmq",
			Description:   "RabbitMQ management HTML page",
			Data: httpData(15672, 200, map[string]string{}, "<html><head><title>RabbitMQ Management</title></head></html>", findPattern(patterns, "lia-rabbitmq")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectTaxonomy: "RabbitMQ",
		},

		// === HTTP SERVICES ===
		{
			PatternID:     "lia-elasticsearch",
			Description:   "Elasticsearch 8.12.0 JSON response",
			Data: httpData(9200, 200, map[string]string{},
				`{"name":"node-1","cluster_name":"docker-cluster","version":{"number":"8.12.0","lucene_version":"9.9.2"},"tagline":"You Know, for Search"}`,
				findPattern(patterns, "lia-elasticsearch")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "8.12.0",
			ExpectTaxonomy: "Elasticsearch",
		},
		{
			PatternID:     "lia-grafana",
			Description:   "Grafana /api/health response",
			Data: httpData(3000, 200, map[string]string{},
				`{"commit":"abc123","database":"ok","version":"10.3.1"}`,
				findPattern(patterns, "lia-grafana")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "10.3.1",
			ExpectTaxonomy: "Grafana",
		},
		{
			PatternID:     "lia-grafana",
			Description:   "Grafana with spaces in JSON",
			Data: httpData(3000, 200, map[string]string{},
				"{\n  \"commit\": \"abc123\",\n  \"database\": \"ok\",\n  \"version\": \"10.3.1\"\n}",
				findPattern(patterns, "lia-grafana")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "10.3.1",
			ExpectTaxonomy: "Grafana",
		},
		{
			PatternID:     "lia-prometheus",
			Description:   "Prometheus buildinfo response",
			Data: httpData(9090, 200, map[string]string{},
				`{"status":"success","data":{"version":"2.49.1","goVersion":"go1.21.5","revision":"abc","branch":"HEAD","buildUser":"","buildDate":"","goOs":"linux","goArch":"amd64"},"prometheus":"ok"}`,
				findPattern(patterns, "lia-prometheus")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "2.49.1",
			ExpectTaxonomy: "Prometheus",
		},
		{
			PatternID:     "lia-consul",
			Description:   "Consul /v1/agent/self response",
			Data: httpData(8500, 200, map[string]string{},
				`{"Config":{"Datacenter":"dc1","NodeName":"consul-01"},"Coord":{},"Member":{},"Stats":{},"Meta":{},"Consul":{"Revision":"009041f8"}}`,
				findPattern(patterns, "lia-consul")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectTaxonomy: "HashiCorp Consul",
		},
		{
			PatternID:     "lia-gitea",
			Description:   "Gitea HTML page with title",
			Data: httpData(3000, 200, map[string]string{},
				`<!DOCTYPE html><html><head><title>Installation - Gitea: Git with a cup of tea</title></head></html>`,
				findPattern(patterns, "lia-gitea")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectTaxonomy: "Gitea",
		},
		{
			PatternID:     "lia-kibana",
			Description:   "Kibana /api/status response",
			Data: httpData(5601, 200, map[string]string{"kbn-name": "kibana"},
				`{"name":"kibana","uuid":"abc","version":{"number":"8.12.0","build_hash":"abc"}}`,
				findPattern(patterns, "lia-kibana")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "8.12.0",
			ExpectTaxonomy: "Kibana",
		},
		{
			PatternID:     "lia-sonarqube",
			Description:   "SonarQube /api/system/status response",
			Data: httpData(9000, 200, map[string]string{},
				`{"id":"abc","version":"10.7.0.96327","status":"UP"}`,
				findPattern(patterns, "lia-sonarqube")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "10.7.0.96327",
			ExpectTaxonomy: "SonarQube",
		},
		{
			PatternID:     "lia-jenkins",
			Description:   "Jenkins with X-Jenkins header",
			Data: httpData(8080, 200, map[string]string{"X-Jenkins": "2.440.1"},
				`<html><head><title>Dashboard [Jenkins]</title></head></html>`,
				findPattern(patterns, "lia-jenkins")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "2.440.1",
			ExpectTaxonomy: "Jenkins",
		},
		{
			PatternID:     "lia-docker",
			Description:   "Docker Engine /version response",
			Data: httpData(2375, 200, map[string]string{},
				`{"Platform":{"Name":"Docker Engine"},"Components":[],"Version":"24.0.7","ApiVersion":"1.43","Os":"linux","Arch":"amd64"}`,
				findPattern(patterns, "lia-docker")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "24.0.7",
			ExpectTaxonomy: "Docker Engine",
		},

		// === WEB SERVERS ===
		{
			PatternID:     "lia-nginx",
			Description:   "Nginx 1.25.5 Server header",
			Data: httpData(80, 200, map[string]string{"Server": "nginx/1.25.5"}, "<html></html>",
				findPattern(patterns, "lia-nginx")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "1.25.5",
			ExpectTaxonomy: "Nginx",
		},
		{
			PatternID:     "lia-apache",
			Description:   "Apache 2.4.62 Server header",
			Data: httpData(80, 200, map[string]string{"Server": "Apache/2.4.62 (Debian)"}, "<html></html>",
				findPattern(patterns, "lia-apache")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "2.4.62",
			ExpectTaxonomy: "Apache HTTP Server",
		},
		{
			PatternID:     "lia-iis",
			Description:   "Microsoft IIS 10.0 Server header",
			Data: httpData(80, 200, map[string]string{"Server": "Microsoft-IIS/10.0"}, "<html></html>",
				findPattern(patterns, "lia-iis")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "10.0",
			ExpectTaxonomy: "Microsoft IIS",
		},
		{
			PatternID:     "lia-tomcat",
			Description:   "Apache Tomcat welcome page",
			Data: httpData(8080, 200, map[string]string{"Server": "Apache-Coyote/1.1"},
				`<html><head><title>Apache Tomcat/10.1.18</title></head></html>`,
				findPattern(patterns, "lia-tomcat")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectTaxonomy: "Apache Tomcat",
		},
		{
			PatternID:     "lia-lighttpd",
			Description:   "lighttpd 1.4.73 Server header",
			Data: httpData(80, 200, map[string]string{"Server": "lighttpd/1.4.73"}, "<html></html>",
				findPattern(patterns, "lia-lighttpd")),
			ExpectMatch:   true,
			MinConfidence: 0.5,
			ExpectVersion: "1.4.73",
			ExpectTaxonomy: "lighttpd",
		},

		// === NETWORKING / LOAD BALANCERS ===
		{
			PatternID:      "lia-haproxy",
			Description:    "HAProxy 2.8.5 Server header",
			Data:           httpData(8080, 200, map[string]string{"Server": "HAProxy/2.8.5"}, "<html></html>", findPattern(patterns, "lia-haproxy")),
			ExpectMatch:    true,
			MinConfidence:  0.5,
			ExpectVersion:  "2.8.5",
			ExpectTaxonomy: "HAProxy",
		},
		{
			PatternID:     "lia-traefik",
			Description:   "Traefik /api/version response",
			Data: httpData(8080, 200, map[string]string{},
				`{"Version": "3.0.4", "Codename": "beaufort", "startDate": "2024-07-01"}`,
				findPattern(patterns, "lia-traefik")),
			ExpectMatch:    true,
			MinConfidence:  0.5,
			ExpectVersion:  "3.0.4",
			ExpectTaxonomy: "Traefik",
		},
		{
			PatternID:     "lia-envoy",
			Description:   "Envoy admin /server_info response",
			Data: httpData(9901, 200, map[string]string{"Server": "envoy"},
				`{"version": "1.29.1", "state": "LIVE", "command_line_options": {}}`,
				findPattern(patterns, "lia-envoy")),
			ExpectMatch:    true,
			MinConfidence:  0.5,
			ExpectVersion:  "1.29.1",
			ExpectTaxonomy: "Envoy Proxy",
		},
		{
			PatternID:     "lia-squid",
			Description:   "Squid 6.6 Server header",
			Data:          httpData(3128, 200, map[string]string{"Server": "squid/6.6"}, "<html></html>", findPattern(patterns, "lia-squid")),
			ExpectMatch:    true,
			MinConfidence:  0.5,
			ExpectVersion:  "6.6",
			ExpectTaxonomy: "Squid Proxy",
		},
		{
			PatternID:     "lia-varnish",
			Description:   "Varnish Via and X-Varnish headers",
			Data:          httpData(6081, 200, map[string]string{"Via": "1.1 varnish (Varnish/7.4)", "X-Varnish": "32770 3"}, "<html></html>", findPattern(patterns, "lia-varnish")),
			ExpectMatch:    true,
			MinConfidence:  0.5,
			ExpectTaxonomy: "Varnish Cache",
		},
		{
			PatternID:     "lia-caddy",
			Description:   "Caddy 2.7.6 Server header",
			Data:          httpData(443, 200, map[string]string{"Server": "Caddy/2.7.6"}, "<html></html>", findPattern(patterns, "lia-caddy")),
			ExpectMatch:    true,
			MinConfidence:  0.5,
			ExpectVersion:  "2.7.6",
			ExpectTaxonomy: "Caddy",
		},

		// === SECURITY / MONITORING ===
		{
			PatternID:     "lia-vault",
			Description:   "Vault /v1/sys/health response",
			Data: httpData(8200, 200, map[string]string{},
				`{"initialized": true, "sealed": false, "standby": false, "performance_standby": false, "replication_performance_mode": "disabled", "replication_dr_mode": "disabled", "server_time_utc": 1706000000, "version": "1.15.4", "cluster_name": "vault-cluster", "cluster_id": "abc-123"}`,
				findPattern(patterns, "lia-vault")),
			ExpectMatch:    true,
			MinConfidence:  0.5,
			ExpectVersion:  "1.15.4",
			ExpectTaxonomy: "HashiCorp Vault",
		},
		{
			PatternID:     "lia-zabbix",
			Description:   "Zabbix web frontend JSON-RPC page",
			Data: httpData(80, 200, map[string]string{},
				`<html><head><title>Zabbix 7.0 JSON-RPC API</title></head><body>zabbix frontend</body></html>`,
				findPattern(patterns, "lia-zabbix")),
			ExpectMatch:    true,
			MinConfidence:  0.5,
			ExpectVersion:  "7.0",
			ExpectTaxonomy: "Zabbix",
		},
		{
			PatternID:     "lia-zabbix",
			Description:   "Zabbix server TCP banner ZBXD",
			Data:          tcpData(10051, "ZBXD\x01\x00\x00\x00\x00\x00\x00\x00\x00"),
			ExpectMatch:    true,
			MinConfidence:  0.5,
			ExpectTaxonomy: "Zabbix",
		},
		{
			PatternID:     "lia-nagios",
			Description:   "Nagios Core web interface",
			Data: httpData(80, 200, map[string]string{},
				`<html><head><title>Nagios Core</title></head><body>Nagios Core 4.4.14 - www.nagios.org</body></html>`,
				findPattern(patterns, "lia-nagios")),
			ExpectMatch:    true,
			MinConfidence:  0.5,
			ExpectVersion:  "4.4.14",
			ExpectTaxonomy: "Nagios",
		},
		{
			PatternID:     "lia-nexus",
			Description:   "Nexus Repository Manager /service/rest/v1/status",
			Data: httpData(8081, 200, map[string]string{"Server": "Nexus/3.68.1-02"},
				`<html><body>Nexus Repository Manager</body></html>`,
				findPattern(patterns, "lia-nexus")),
			ExpectMatch:    true,
			MinConfidence:  0.5,
			ExpectVersion:  "3.68.1",
			ExpectTaxonomy: "Sonatype Nexus",
		},
		{
			PatternID:     "lia-gitlab",
			Description:   "GitLab CE login page",
			Data: httpData(80, 200, map[string]string{"X-Gitlab-Meta": "true"},
				`<!DOCTYPE html><html class="gl-dark"><head><title>GitLab</title></head><body>gitlab community edition {"version": "16.8.1"}</body></html>`,
				findPattern(patterns, "lia-gitlab")),
			ExpectMatch:    true,
			MinConfidence:  0.5,
			ExpectVersion:  "16.8.1",
			ExpectTaxonomy: "GitLab",
		},

		// === NEGATIVE TESTS (should NOT match) ===
		{
			PatternID:     "lia-mysql",
			Description:   "Random binary data should not match MySQL",
			Data:          tcpData(3306, "\x00\x01\x02\x03\x04\x05random garbage"),
			ExpectMatch:   false,
			ExpectTaxonomy: "MySQL",
		},
		{
			PatternID:     "lia-openssh",
			Description:   "Dropbear SSH should not match OpenSSH",
			Data:          tcpData(22, "SSH-2.0-dropbear_2022.83\r\n"),
			ExpectMatch:   false,
			ExpectTaxonomy: "OpenSSH",
		},
		{
			PatternID:     "lia-nginx",
			Description:   "Apache header should not match Nginx",
			Data: httpData(80, 200, map[string]string{"Server": "Apache/2.4.62"}, "",
				findPattern(patterns, "lia-nginx")),
			ExpectMatch:   false,
			ExpectTaxonomy: "Nginx",
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s/%s", tc.PatternID, tc.Description), func(t *testing.T) {
			pattern := findPattern(patterns, tc.PatternID)
			if pattern == nil {
				t.Fatalf("Pattern %s not found", tc.PatternID)
			}

			result := matcher.EvaluatePattern(pattern, tc.Data)

			if tc.ExpectMatch {
				if result == nil {
					t.Fatalf("Expected match but got nil result")
				}
				if result.Confidence < tc.MinConfidence {
					t.Errorf("Confidence %.2f < minimum %.2f", result.Confidence, tc.MinConfidence)
				}
				if tc.ExpectVersion != "" && result.Version != tc.ExpectVersion {
					t.Errorf("Version: got %q, want %q", result.Version, tc.ExpectVersion)
				}
				t.Logf("PASS: %s -> %s %s (confidence: %.0f%%)",
					tc.PatternID, result.TaxonomyName, result.Version, result.Confidence*100)
			} else {
				if result != nil && result.Confidence >= 0.5 {
					t.Errorf("Expected no match but got %s with confidence %.2f",
						result.TaxonomyName, result.Confidence)
				}
			}
		})
	}
}

func TestPatterns_VersionExtraction(t *testing.T) {
	patterns := loadTestPatterns(t)
	matcher := NewFingerprintMatcher()

	// Test specific version extraction scenarios
	versionTests := []struct {
		PatternID string
		Banner    string
		Expected  string
	}{
		{"lia-openssh", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3", "9.6p1"},
		{"lia-openssh", "SSH-2.0-OpenSSH_8.2p1", "8.2p1"},
		{"lia-openssh", "SSH-2.0-OpenSSH_7.4", "7.4"},
		{"lia-vsftpd", "220 (vsFTPd 3.0.5)\r\n", "3.0.5"},
		{"lia-vsftpd", "220 (vsFTPd 3.0.3)\r\n", "3.0.3"},
		{"lia-mysql", "J\x00\x00\x00\x0a8.0.36\x00caching_sha2_password\x00", "8.0.36"},
		{"lia-mysql", "J\x00\x00\x00\x0a5.7.44\x00mysql_native_password\x00", "5.7.44"},
		{"lia-mariadb", "J\x00\x00\x00\x0a10.11.6-MariaDB\x00", "10.11.6"},
	}

	for _, vt := range versionTests {
		t.Run(fmt.Sprintf("%s/version=%s", vt.PatternID, vt.Expected), func(t *testing.T) {
			pattern := findPattern(patterns, vt.PatternID)
			if pattern == nil {
				t.Fatalf("Pattern %s not found", vt.PatternID)
			}
			data := tcpData(pattern.DefaultPorts[0], vt.Banner)
			result := matcher.EvaluatePattern(pattern, data)
			if result == nil {
				t.Fatal("Expected match but got nil")
			}
			if result.Version != vt.Expected {
				t.Errorf("Version: got %q, want %q", result.Version, vt.Expected)
			}
		})
	}
}

func TestPatterns_JSONSpaceTolerance(t *testing.T) {
	patterns := loadTestPatterns(t)
	matcher := NewFingerprintMatcher()

	// Test that all HTTP JSON patterns work with both compact and spaced JSON
	jsonTests := []struct {
		PatternID string
		Compact   string
		Spaced    string
	}{
		{
			"lia-grafana",
			`{"database":"ok","version":"10.3.1","commit":"abc"}`,
			"{\n  \"database\": \"ok\",\n  \"version\": \"10.3.1\",\n  \"commit\": \"abc\"\n}",
		},
		{
			"lia-prometheus",
			`{"status":"success","data":{"version":"2.49.1"},"prometheus":"ok"}`,
			"{ \"status\" : \"success\", \"data\" : { \"version\" : \"2.49.1\" }, \"prometheus\" : \"ok\" }",
		},
		{
			"lia-elasticsearch",
			`{"version":{"number":"8.12.0","lucene_version":"9.9.2"},"tagline":"You Know, for Search"}`,
			"{ \"version\" : { \"number\" : \"8.12.0\", \"lucene_version\" : \"9.9.2\" }, \"tagline\" : \"You Know, for Search\" }",
		},
		{
			"lia-sonarqube",
			`{"id":"abc","version":"10.7.0","status":"UP"}`,
			"{ \"id\" : \"abc\", \"version\" : \"10.7.0\", \"status\" : \"UP\" }",
		},
	}

	for _, jt := range jsonTests {
		pattern := findPattern(patterns, jt.PatternID)
		if pattern == nil {
			t.Fatalf("Pattern %s not found", jt.PatternID)
			continue
		}

		t.Run(fmt.Sprintf("%s/compact_json", jt.PatternID), func(t *testing.T) {
			data := httpData(pattern.DefaultPorts[0], 200, map[string]string{}, jt.Compact, pattern)
			result := matcher.EvaluatePattern(pattern, data)
			if result == nil {
				t.Error("Expected match on compact JSON but got nil")
			} else {
				t.Logf("Compact: confidence=%.0f%% version=%s", result.Confidence*100, result.Version)
			}
		})

		t.Run(fmt.Sprintf("%s/spaced_json", jt.PatternID), func(t *testing.T) {
			data := httpData(pattern.DefaultPorts[0], 200, map[string]string{}, jt.Spaced, pattern)
			result := matcher.EvaluatePattern(pattern, data)
			if result == nil {
				t.Error("Expected match on spaced JSON but got nil")
			} else {
				t.Logf("Spaced: confidence=%.0f%% version=%s", result.Confidence*100, result.Version)
			}
		})
	}
}

func TestPatterns_CPEFormat(t *testing.T) {
	patterns := loadTestPatterns(t)
	for _, p := range patterns {
		if p.CPE23 == "" {
			t.Errorf("Pattern %s has no CPE template", p.ID)
			continue
		}
		// CPE 2.3 format: cpe:2.3:a:vendor:product:version:...
		if p.CPE23 != "" {
			// Should start with cpe:2.3:
			if len(p.CPE23) < 8 {
				t.Errorf("Pattern %s CPE too short: %s", p.ID, p.CPE23)
			}
		}
	}
}

func TestPatterns_ConfidenceThreshold(t *testing.T) {
	patterns := loadTestPatterns(t)
	for _, p := range patterns {
		if p.ConfidenceThreshold <= 0 || p.ConfidenceThreshold > 1.0 {
			t.Errorf("Pattern %s has invalid confidence_threshold: %.2f", p.ID, p.ConfidenceThreshold)
		}
		// Sum of all matcher deltas should be able to exceed threshold
		var totalDelta float64
		for _, m := range p.BannerMatchers {
			totalDelta += m.ConfidenceDelta
		}
		for _, probe := range p.Probes {
			for _, m := range probe.Matchers {
				totalDelta += m.ConfidenceDelta
			}
		}
		if totalDelta < p.ConfidenceThreshold {
			t.Errorf("Pattern %s: max possible confidence (%.2f) < threshold (%.2f) -- pattern can never match",
				p.ID, p.BaseConfidence+totalDelta, p.ConfidenceThreshold)
		}
	}
}

func TestPatterns_Summary(t *testing.T) {
	patterns := loadTestPatterns(t)
	matcher := NewFingerprintMatcher()

	// Quick pass/fail for every pattern with a positive test
	positiveData := map[string]*CollectedServiceData{
		"lia-mysql":         tcpData(3306, "J\x00\x00\x00\x0a8.0.45\x00caching_sha2_password\x00"),
		"lia-mariadb":       tcpData(3306, "J\x00\x00\x00\x0a11.2.3-MariaDB\x00"),
		"lia-postgresql":    tcpData(5432, "EFATAL\x00SCRAM-SHA-256\x00authentication"),
		"lia-mssql":         tcpData(1433, "\x04\x01Microsoft SQL Server\x00"),
		"lia-mongodb":       httpData(27017, 200, map[string]string{}, "It looks like you are trying to access MongoDB over HTTP", findPattern(patterns, "lia-mongodb")),
		"lia-redis":         tcpData(6379, "+PONG\r\n"),
		"lia-elasticsearch": httpData(9200, 200, map[string]string{}, `{"version":{"number":"8.12.0","lucene_version":"9.9"},"tagline":"You Know, for Search"}`, findPattern(patterns, "lia-elasticsearch")),
		"lia-openssh":       tcpData(22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3"),
		"lia-vsftpd":        tcpData(21, "220 (vsFTPd 3.0.5)\r\n"),
		"lia-postfix":       tcpData(25, "220 mail.example.org ESMTP Postfix\r\n"),
		"lia-rabbitmq":      tcpData(5672, "AMQP\x00\x00\x09\x01"),
		"lia-docker":        httpData(2375, 200, map[string]string{}, `{"Version":"24.0.7","ApiVersion":"1.43","Docker":"ok"}`, findPattern(patterns, "lia-docker")),
		"lia-grafana":       httpData(3000, 200, map[string]string{}, `{"database":"ok","version":"10.3.1","commit":"abc"}`, findPattern(patterns, "lia-grafana")),
		"lia-jenkins":       httpData(8080, 200, map[string]string{"X-Jenkins": "2.440.1"}, "", findPattern(patterns, "lia-jenkins")),
		"lia-prometheus":    httpData(9090, 200, map[string]string{}, `{"status":"success","data":{"version":"2.49.1"},"prometheus":"ok"}`, findPattern(patterns, "lia-prometheus")),
		"lia-consul":        httpData(8500, 200, map[string]string{}, `{"Consul":{"Revision":"abc123"},"consul":"ok"}`, findPattern(patterns, "lia-consul")),
		"lia-gitea":         httpData(3000, 200, map[string]string{}, `<title>Gitea: Git with a cup of tea</title>`, findPattern(patterns, "lia-gitea")),
		"lia-kibana":        httpData(5601, 200, map[string]string{"kbn-name": "kibana"}, `{"name":"kibana","version":{"number":"8.12.0"}}`, findPattern(patterns, "lia-kibana")),
		"lia-sonarqube":     httpData(9000, 200, map[string]string{}, `{"version":"10.7.0","status":"UP"}`, findPattern(patterns, "lia-sonarqube")),
		"lia-nginx":         httpData(80, 200, map[string]string{"Server": "nginx/1.25.5"}, "", findPattern(patterns, "lia-nginx")),
		"lia-apache":        httpData(80, 200, map[string]string{"Server": "Apache/2.4.62 (Debian)"}, "", findPattern(patterns, "lia-apache")),
		"lia-iis":           httpData(80, 200, map[string]string{"Server": "Microsoft-IIS/10.0"}, "", findPattern(patterns, "lia-iis")),
		"lia-tomcat":        httpData(8080, 200, map[string]string{}, "<title>Apache Tomcat/10.1.18</title>", findPattern(patterns, "lia-tomcat")),
		"lia-lighttpd":      httpData(80, 200, map[string]string{"Server": "lighttpd/1.4.73"}, "", findPattern(patterns, "lia-lighttpd")),
		"lia-haproxy":       httpData(8080, 200, map[string]string{"Server": "HAProxy/2.8.5"}, "", findPattern(patterns, "lia-haproxy")),
		"lia-traefik":       httpData(8080, 200, map[string]string{}, `{"Version": "3.0.4", "Codename": "beaufort"}`, findPattern(patterns, "lia-traefik")),
		"lia-envoy":         httpData(9901, 200, map[string]string{"Server": "envoy"}, `{"version": "1.29.1", "state": "LIVE"}`, findPattern(patterns, "lia-envoy")),
		"lia-vault":         httpData(8200, 200, map[string]string{}, `{"initialized": true, "sealed": false, "version": "1.15.4"}`, findPattern(patterns, "lia-vault")),
		"lia-squid":         httpData(3128, 200, map[string]string{"Server": "squid/6.6"}, "", findPattern(patterns, "lia-squid")),
		"lia-varnish":       httpData(6081, 200, map[string]string{"Via": "1.1 varnish (Varnish/7.4)", "X-Varnish": "32770"}, "", findPattern(patterns, "lia-varnish")),
		"lia-caddy":         httpData(443, 200, map[string]string{"Server": "Caddy/2.7.6"}, "", findPattern(patterns, "lia-caddy")),
		"lia-zabbix":        httpData(80, 200, map[string]string{}, `<title>Zabbix 7.0 JSON-RPC API</title><body>zabbix frontend</body>`, findPattern(patterns, "lia-zabbix")),
		"lia-nagios":        httpData(80, 200, map[string]string{}, `<body>Nagios Core 4.4.14 - www.nagios.org</body>`, findPattern(patterns, "lia-nagios")),
		"lia-nexus":         httpData(8081, 200, map[string]string{"Server": "Nexus/3.68.1-02"}, "Nexus Repository Manager", findPattern(patterns, "lia-nexus")),
		"lia-gitlab":        httpData(80, 200, map[string]string{"X-Gitlab-Meta": "true"}, `gitlab community edition {"version": "16.8.1"}`, findPattern(patterns, "lia-gitlab")),
	}

	passed := 0
	failed := 0
	missing := 0

	// Use JSON for pretty output
	type result struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Conf   string `json:"confidence,omitempty"`
		Ver    string `json:"version,omitempty"`
	}
	var results []result

	for _, p := range patterns {
		data, ok := positiveData[p.ID]
		if !ok {
			missing++
			results = append(results, result{ID: p.ID, Status: "NO_TEST_DATA"})
			continue
		}
		r := matcher.EvaluatePattern(p, data)
		if r != nil && r.Confidence >= p.ConfidenceThreshold {
			passed++
			results = append(results, result{
				ID:     p.ID,
				Status: "PASS",
				Conf:   fmt.Sprintf("%.0f%%", r.Confidence*100),
				Ver:    r.Version,
			})
		} else {
			failed++
			conf := "nil"
			if r != nil {
				conf = fmt.Sprintf("%.0f%%", r.Confidence*100)
			}
			results = append(results, result{ID: p.ID, Status: "FAIL", Conf: conf})
		}
	}

	// Print summary
	out, _ := json.MarshalIndent(results, "", "  ")
	t.Logf("\n=== PATTERN TEST SUMMARY ===\nPassed: %d | Failed: %d | No test data: %d | Total: %d\n%s",
		passed, failed, missing, len(patterns), string(out))

	if failed > 0 {
		t.Errorf("%d patterns failed matching", failed)
	}
}

func TestAllSources_Load(t *testing.T) {
	cfg := config.Default()
	// Resolve pattern dirs relative to project root (tests run from pkg/fingerprint/)
	for i := range cfg.Fingerprint.PatternDirs {
		cfg.Fingerprint.PatternDirs[i].Path = "../../" + cfg.Fingerprint.PatternDirs[i].Path
	}
	loader := NewPatternLoader(cfg.Fingerprint)
	index, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll failed: %v", err)
	}

	t.Logf("=== ALL SOURCES LOADED ===")
	t.Logf("Total patterns: %d", index.Stats.TotalPatterns)
	t.Logf("Taxonomies: %d", index.Stats.TaxonomiesCovered)
	t.Logf("Probes: %d", index.Stats.TotalProbes)
	t.Logf("Matchers: %d", index.Stats.TotalMatchers)
	for src, count := range index.Stats.BySource {
		t.Logf("  %s: %d patterns", src, count)
	}
	t.Logf("Ports indexed: %d", len(index.ByPort))
	t.Logf("HTTP ports: %d", index.Stats.DynamicHTTPPorts)
	t.Logf("TLS ports: %d", index.Stats.DynamicTLSPorts)

	if index.Stats.TotalPatterns < 1000 {
		t.Errorf("Expected 1000+ patterns, got %d", index.Stats.TotalPatterns)
	}
}
