// Package fingerprint contains the fingerprinting engine of LiaProbe.
// Evaluates JSON patterns (lia-fingerprint-v1) against collected data
// to identify network service technologies, versions, and CPE.
//
// Architecture:
//   - FingerprintPattern: 1 JSON file = 1 technology
//   - PatternProbe: active probes (HTTP, TCP, TLS, UDP, SSDP, mDNS)
//   - PatternMatcher: matching criteria with additive confidence
//   - PatternIndex: in-memory index for fast lookup by port/service/layer
//
// Extracted from LIA-SEC engine, made standalone for LiaProbe.
package fingerprint

import (
	"time"
)

// --- Pattern principal (1 par technologie) ---

// FingerprintPattern represents a complete fingerprinting pattern for a technology.
// One JSON file = one FingerprintPattern.
type FingerprintPattern struct {
	// Identification
	Schema  string `json:"$schema"`  // "lia-fingerprint-v1"
	ID      string `json:"id"`       // Unique identifier, e.g.: "lia-jenkins", "nmap-openssh"
	Version string `json:"version"`  // Pattern version, e.g.: "1.0.0"
	Enabled bool   `json:"enabled"`  // Active/inactive

	// LIA-Scan mapping
	TaxonomyCode string `json:"taxonomy_code"` // LIA quadrogram: ADDS, MSSQL, JENKINS...
	TaxonomyName string `json:"taxonomy_name"` // Full name: "Jenkins CI/CD"

	// Product identification
	Vendor  string `json:"vendor"`                   // "Jenkins", "Apache Software Foundation"
	Product string `json:"product"`                  // "Jenkins", "HTTP Server"
	CPE23   string `json:"cpe23_template,omitempty"` // "cpe:2.3:a:jenkins:jenkins:{version}:*:*:*:*:*:*:*"

	// Source (mandatory traceability)
	Source   PatternSource    `json:"source"`
	Research []ResearchSource `json:"research,omitempty"`

	// Default ports (or search if no known service)
	DefaultPorts []int `json:"default_ports,omitempty"`

	// Passive matchers (on already collected data)
	BannerMatchers  []PatternMatcher `json:"banner_matchers,omitempty"`
	ServiceMatchers []PatternMatcher `json:"service_matchers,omitempty"`

	// Active probes (send requests)
	Probes []PatternProbe `json:"probes,omitempty"`

	// Deductions (chainable)
	Implies []string `json:"implies,omitempty"` // E.g.: ["JAVA"] for Jenkins

	// Scoring
	BaseConfidence      float64 `json:"base_confidence"`
	ConfidenceThreshold float64 `json:"confidence_threshold"`

	// Metadata
	Notes     string    `json:"notes,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// --- Sources et provenance ---

// PatternSource identifies where the pattern comes from.
type PatternSource struct {
	Type            string `json:"type"`                        // "lia", "nmap", "wappalyzer", "recog", "nuclei", "manual"
	File            string `json:"file"`                        // Original source file
	OriginalID      string `json:"original_id,omitempty"`       // ID in source system
	OriginalPattern string `json:"original_pattern,omitempty"`  // Raw original regex/pattern
	ParsedAt        string `json:"parsed_at,omitempty"`         // ISO date of parsing
	ParserVersion   string `json:"parser_version,omitempty"`    // Version of parsing script
}

// ResearchSource represents research evidence for a pattern.
type ResearchSource struct {
	URL      string `json:"url"`
	Type     string `json:"type"`           // "official_doc", "nuclei_template", "github_issue", "cve_advisory"
	Evidence string `json:"evidence"`
	Date     string `json:"date,omitempty"`
}

// --- Probes actifs ---

// PatternProbe defines an active request to send to a service.
// Supports HTTP GET/POST, TCP raw send, TCP binary (hex), TLS cert, UDP, SSDP, mDNS.
type PatternProbe struct {
	ID    string `json:"id"`    // Unique identifier within the pattern
	Layer string `json:"layer"` // "L7_HTTP", "L4_TCP", "L4_TCP_HEX", "TLS_CERT", "L4_UDP", "L4_UDP_SSDP", "L4_UDP_MDNS"

	// Specific ports for this probe (override DefaultPorts)
	Ports []int `json:"ports,omitempty"`

	// --- HTTP (Layer L7_HTTP) ---
	Method          string            `json:"method,omitempty"`
	Path            string            `json:"path,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	ContentType     string            `json:"content_type,omitempty"`
	FollowRedirects *bool             `json:"follow_redirects,omitempty"`

	// --- TCP raw (Layer L4_TCP) ---
	Send      string `json:"send,omitempty"`
	ReadFirst bool   `json:"read_first,omitempty"` // Read spontaneous banner BEFORE sending (SMTP, FTP)

	// --- TCP binary (Layer L4_TCP_HEX) ---
	SendHex string `json:"send_hex,omitempty"`

	// --- File (Layer L_FILE) ---
	FilePath string `json:"file_path,omitempty"`

	// Timeout for this probe (ms). 0 = global default.
	TimeoutMs int `json:"timeout_ms,omitempty"`

	// Matchers on this probe's response
	Matchers []PatternMatcher `json:"matchers"`

	// Documentation
	Note string `json:"note,omitempty"`
}

// --- Matchers ---

// PatternMatcher defines a single matching criterion.
// Each matching matcher adds its confidence_delta to the total score.
type PatternMatcher struct {
	// Matching target
	Target string `json:"target"` // "banner", "service_name", "product", "version",
	//                                "header", "body", "status_code", "cookie",
	//                                "favicon_hash", "ssl_cn", "ssl_san",
	//                                "response", "json_field", "os_family", "os_name"

	// Specific field (for header, json_field, cookie)
	Field string `json:"field,omitempty"`

	// Match type
	MatchType string `json:"match_type"` // "regex", "contains", "exact", "exists",
	//                                       "starts_with", "ends_with", "not_contains",
	//                                       "json_field", "favicon_hash", "starts_with_hex"

	// Expected value
	Value string `json:"value,omitempty"`

	// Match inversion (NOT)
	Negate bool `json:"negate,omitempty"`

	// Case-insensitive matching (for "regex" only)
	CaseInsensitive bool `json:"case_insensitive,omitempty"`

	// Scoring
	ConfidenceDelta float64 `json:"confidence_delta"`

	// Version extraction
	VersionExtract      string `json:"version_extract,omitempty"`
	VersionExtractField string `json:"version_extract_field,omitempty"`
	VersionExtractGroup int    `json:"version_group,omitempty"`

	// Deactivation (RE2-incompatible matchers from Nmap)
	Disabled       bool   `json:"disabled,omitempty"`
	DisabledReason string `json:"disabled_reason,omitempty"`

	// Documentation
	Note string `json:"note,omitempty"`
}

// --- Resultats ---

// FingerprintResult represents the result of service fingerprinting.
type FingerprintResult struct {
	TaxonomyCode string  `json:"taxonomy_code"`
	TaxonomyName string  `json:"taxonomy_name"`
	Confidence   float64 `json:"confidence"`

	Version string `json:"version,omitempty"`
	CPE23   string `json:"cpe23,omitempty"`

	// Traceability
	PatternID               string                 `json:"pattern_id"`
	PatternSource           string                 `json:"pattern_source"`
	FingerprintMatchDetails []FingerprintMatchDetail `json:"match_details"`
	Evidence                string                 `json:"evidence"`

	// Chainable deductions
	ImpliedTechnologies []string `json:"implied_technologies,omitempty"`
}

// FingerprintMatchDetail traces which matcher contributed to the score.
type FingerprintMatchDetail struct {
	ProbeID          string  `json:"probe_id,omitempty"`
	MatcherTarget    string  `json:"matcher_target"`
	MatcherField     string  `json:"matcher_field,omitempty"`
	ConfidenceDelta  float64 `json:"confidence_delta"`
	MatchedValue     string  `json:"matched_value,omitempty"`
	ExtractedVersion string  `json:"extracted_version,omitempty"`
}

// --- Index en memoire ---

// PatternIndex is the in-memory index of all loaded patterns.
type PatternIndex struct {
	All        []*FingerprintPattern            `json:"-"`
	ByPort     map[int][]*FingerprintPattern     `json:"-"`
	ByService  map[string][]*FingerprintPattern  `json:"-"`
	ByTaxonomy map[string]*FingerprintPattern    `json:"-"`
	ByLayer    map[string][]*FingerprintPattern  `json:"-"`

	// Dynamic ports deduced from probes
	HTTPPorts map[int]bool `json:"-"`
	TLSPorts  map[int]bool `json:"-"`

	Stats PatternIndexStats `json:"stats"`
}

// PatternIndexStats summarizes loaded patterns.
type PatternIndexStats struct {
	TotalPatterns     int            `json:"total_patterns"`
	BySource          map[string]int `json:"by_source"`
	TotalProbes       int            `json:"total_probes"`
	TotalMatchers     int            `json:"total_matchers"`
	TaxonomiesCovered int            `json:"taxonomies_covered"`
	DynamicHTTPPorts  int            `json:"dynamic_http_ports"`
	DynamicTLSPorts   int            `json:"dynamic_tls_ports"`
	LoadedAt          time.Time      `json:"loaded_at"`
}

// --- Donnees collectees (entree du moteur) ---

// CollectedServiceData represents the data of a service to analyze.
// It is the fusion of scanner data + HTTP probes + TCP probes.
type CollectedServiceData struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`     // "tcp", "udp"
	ServiceName string `json:"service_name"` // "http", "ssh", "redis"
	Product     string `json:"product"`      // "Apache httpd", "OpenSSH"
	Version     string `json:"version"`      // "2.4.58", "9.6p1"
	Banner      string `json:"banner"`       // Raw TCP banner
	State       string `json:"state"`        // "open", "filtered"

	// Host OS
	OSFamily  string `json:"os_family,omitempty"`
	OSName    string `json:"os_name,omitempty"`
	OSVersion string `json:"os_version,omitempty"`

	// Probe responses
	HTTPResponses map[string]*HTTPProbeResponse `json:"http_responses,omitempty"`
	TCPResponses  map[string]*TCPProbeResponse  `json:"tcp_responses,omitempty"`
	TLSCert       *TLSCertInfo                  `json:"tls_cert,omitempty"`
	SSDPResponse  *SSDPProbeResponse            `json:"ssdp_response,omitempty"`
	MDNSResponses map[string]*MDNSProbeResponse `json:"mdns_responses,omitempty"`
	UDPResponses  map[string]*UDPProbeResponse  `json:"udp_responses,omitempty"`
	FileResponses map[string]*FileProbeResponse `json:"file_responses,omitempty"`
}

// HasLayerData indicates if necessary data for a layer is present.
func (d *CollectedServiceData) HasLayerData(layer string) bool {
	switch layer {
	case "L4_TCP", "L4_TCP_HEX":
		return d.Banner != "" || len(d.TCPResponses) > 0
	case "L7_HTTP":
		return len(d.HTTPResponses) > 0
	case "TLS_CERT":
		return d.TLSCert != nil
	case "L4_UDP":
		return len(d.UDPResponses) > 0
	case "L4_UDP_SSDP":
		return d.SSDPResponse != nil
	case "L4_UDP_MDNS":
		return len(d.MDNSResponses) > 0
	case "L_FILE":
		return len(d.FileResponses) > 0
	default:
		return false
	}
}

// --- Types de reponse des probes ---

// SSDPProbeResponse represents the SSDP M-SEARCH unicast response.
type SSDPProbeResponse struct {
	Headers map[string]string `json:"headers"`
	RawData string            `json:"raw_data,omitempty"`
}

// MDNSProbeResponse represents the mDNS response.
type MDNSProbeResponse struct {
	Services   []string          `json:"services"`
	TXTRecords map[string]string `json:"txt_records"`
	RawNames   string            `json:"raw_names"`
}

// UDPProbeResponse represents a generic UDP response.
type UDPProbeResponse struct {
	Data    string `json:"data"`
	DataHex string `json:"data_hex"`
	Bytes   []byte `json:"-"`
}

// FileProbeResponse represents the response of a local file probe.
type FileProbeResponse struct {
	FilePath   string `json:"file_path"`
	FileExists bool   `json:"file_exists"`
	Content    string `json:"content,omitempty"`
	SizeBytes  int64  `json:"size_bytes"`
	IsReadable bool   `json:"is_readable"`
}

// HTTPProbeResponse represents the response of an HTTP probe.
type HTTPProbeResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Cookies    map[string]string `json:"cookies,omitempty"`
}

// TCPProbeResponse represents the response of a TCP probe.
type TCPProbeResponse struct {
	Data    string `json:"data"`
	DataHex string `json:"data_hex"`
	Bytes   []byte `json:"-"`
}

// TLSCertInfo represents information extracted from the TLS certificate.
type TLSCertInfo struct {
	CommonName string   `json:"common_name"`
	SANs       []string `json:"sans,omitempty"`
	Issuer     string   `json:"issuer,omitempty"`
	NotBefore  string   `json:"not_before,omitempty"`
	NotAfter   string   `json:"not_after,omitempty"`
	Serial     string   `json:"serial,omitempty"`
}

// --- Helpers ---

// SourcePriority returns the numeric priority for a source.
func SourcePriority(sourceType string) int {
	switch sourceType {
	case "lia":
		return 100
	case "manual":
		return 90
	case "nmap":
		return 80
	case "recog":
		return 60
	case "nuclei":
		return 50
	case "wappalyzer":
		return 40
	default:
		return 10
	}
}
