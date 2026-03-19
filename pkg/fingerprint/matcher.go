package fingerprint

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// FingerprintMatcher evaluates fingerprinting patterns.
// Thread-safe thanks to regex cache protected by mutex.
type FingerprintMatcher struct {
	regexCache map[string]*regexp.Regexp
	regexMu    sync.RWMutex

	// Optional logger for warnings (regex compile errors).
	// If nil, errors are silently ignored.
	OnWarn func(component, action, details string)
}

// NewFingerprintMatcher creates a new matcher with regex cache.
func NewFingerprintMatcher() *FingerprintMatcher {
	return &FingerprintMatcher{
		regexCache: make(map[string]*regexp.Regexp),
	}
}

// EvaluatePattern evaluates a complete pattern against collected data.
// Returns a FingerprintResult if confidence exceeds threshold, nil otherwise.
func (fm *FingerprintMatcher) EvaluatePattern(pattern *FingerprintPattern, data *CollectedServiceData) *FingerprintResult {
	confidence := pattern.BaseConfidence
	var allDetails []FingerprintMatchDetail
	var extractedVersion string

	// 1. Evaluate banner_matchers (passive)
	bannerConf, bannerDetails, bannerVersion := fm.evaluateBannerMatchers(pattern.BannerMatchers, data)
	confidence += bannerConf
	allDetails = append(allDetails, bannerDetails...)
	if bannerVersion != "" {
		extractedVersion = bannerVersion
	}

	// 2. Evaluate service_matchers (passive)
	svcConf, svcDetails, svcVersion := fm.evaluateServiceMatchers(pattern.ServiceMatchers, data)
	confidence += svcConf
	allDetails = append(allDetails, svcDetails...)
	if svcVersion != "" && extractedVersion == "" {
		extractedVersion = svcVersion
	}

	// 3. Evaluate probes (active) - filter by available layer
	for _, probe := range pattern.Probes {
		if !data.HasLayerData(probe.Layer) {
			continue
		}
		probeConf, probeDetails, probeVersion := fm.evaluateProbeMatchers(probe, data)
		confidence += probeConf
		allDetails = append(allDetails, probeDetails...)
		if probeVersion != "" && extractedVersion == "" {
			extractedVersion = probeVersion
		}
	}

	// Cap confidence
	if confidence > 1.0 {
		confidence = 1.0
	}

	// Threshold check
	if confidence < pattern.ConfidenceThreshold {
		return nil
	}

	// If no version extracted, use scanner's version
	if extractedVersion == "" && data.Version != "" {
		extractedVersion = data.Version
	}

	cpe := fm.generateCPE23(pattern.CPE23, extractedVersion)
	evidence := fm.buildEvidenceSummary(pattern, allDetails, confidence)

	return &FingerprintResult{
		TaxonomyCode:            pattern.TaxonomyCode,
		TaxonomyName:            pattern.TaxonomyName,
		Confidence:              confidence,
		Version:                 extractedVersion,
		CPE23:                   cpe,
		PatternID:               pattern.ID,
		PatternSource:           pattern.Source.Type,
		FingerprintMatchDetails: allDetails,
		Evidence:                evidence,
		ImpliedTechnologies:     pattern.Implies,
	}
}

// evaluateBannerMatchers evaluates matchers against the raw TCP banner.
func (fm *FingerprintMatcher) evaluateBannerMatchers(matchers []PatternMatcher, data *CollectedServiceData) (float64, []FingerprintMatchDetail, string) {
	var totalConf float64
	var details []FingerprintMatchDetail
	var version string

	for _, m := range matchers {
		if m.Target != "banner" || m.Disabled {
			continue
		}

		matched, matchedValue := fm.matchSingle(m, data.Banner)
		if m.Negate {
			matched = !matched
		}

		if matched {
			totalConf += m.ConfidenceDelta
			detail := FingerprintMatchDetail{
				MatcherTarget:   m.Target,
				ConfidenceDelta: m.ConfidenceDelta,
				MatchedValue:    truncateStr(matchedValue, 200),
			}

			if v := fm.extractVersion(m, data.Banner); v != "" {
				version = v
				detail.ExtractedVersion = v
			}

			details = append(details, detail)
		}
	}

	return totalConf, details, version
}

// evaluateServiceMatchers evaluates matchers on service_name, product, version, os.
func (fm *FingerprintMatcher) evaluateServiceMatchers(matchers []PatternMatcher, data *CollectedServiceData) (float64, []FingerprintMatchDetail, string) {
	var totalConf float64
	var details []FingerprintMatchDetail
	var version string

	for _, m := range matchers {
		if m.Disabled {
			continue
		}
		var targetValue string
		switch m.Target {
		case "service_name":
			targetValue = data.ServiceName
		case "product":
			targetValue = data.Product
		case "version":
			targetValue = data.Version
		case "os_family":
			targetValue = data.OSFamily
		case "os_name":
			targetValue = data.OSName
		default:
			continue
		}

		matched, matchedValue := fm.matchSingle(m, targetValue)
		if m.Negate {
			matched = !matched
		}

		if matched {
			totalConf += m.ConfidenceDelta
			detail := FingerprintMatchDetail{
				MatcherTarget:   m.Target,
				ConfidenceDelta: m.ConfidenceDelta,
				MatchedValue:    truncateStr(matchedValue, 200),
			}

			if v := fm.extractVersion(m, targetValue); v != "" {
				version = v
				detail.ExtractedVersion = v
			}

			details = append(details, detail)
		}
	}

	return totalConf, details, version
}

// evaluateProbeMatchers evaluates a probe's matchers against collected responses.
func (fm *FingerprintMatcher) evaluateProbeMatchers(probe PatternProbe, data *CollectedServiceData) (float64, []FingerprintMatchDetail, string) {
	var totalConf float64
	var details []FingerprintMatchDetail
	var version string

	for _, m := range probe.Matchers {
		if m.Disabled {
			continue
		}
		var targetValue string

		switch m.Target {
		case "response":
			if tcpResp, ok := data.TCPResponses[probe.ID]; ok {
				targetValue = tcpResp.Data
			} else if udpResp, ok := data.UDPResponses[probe.ID]; ok {
				targetValue = udpResp.Data
			}
		case "response_hex":
			if tcpResp, ok := data.TCPResponses[probe.ID]; ok {
				targetValue = tcpResp.DataHex
			} else if udpResp, ok := data.UDPResponses[probe.ID]; ok {
				targetValue = udpResp.DataHex
			}
		case "body":
			if httpResp, ok := data.HTTPResponses[probe.ID]; ok {
				targetValue = httpResp.Body
			}
		case "header":
			if httpResp, ok := data.HTTPResponses[probe.ID]; ok && m.Field != "" {
				targetValue = httpResp.Headers[m.Field]
				if targetValue == "" {
					for k, v := range httpResp.Headers {
						if strings.EqualFold(k, m.Field) {
							targetValue = v
							break
						}
					}
				}
			}
		case "status_code":
			if httpResp, ok := data.HTTPResponses[probe.ID]; ok {
				targetValue = fmt.Sprintf("%d", httpResp.StatusCode)
			}
		case "cookie":
			if httpResp, ok := data.HTTPResponses[probe.ID]; ok && m.Field != "" {
				targetValue = httpResp.Cookies[m.Field]
			}
		case "favicon_hash":
			if httpResp, ok := data.HTTPResponses[probe.ID]; ok {
				targetValue = Mmh3Hash32([]byte(httpResp.Body))
			}
		case "json_field":
			if httpResp, ok := data.HTTPResponses[probe.ID]; ok && m.Field != "" {
				targetValue = ExtractJSONField(httpResp.Body, m.Field)
			}
			if targetValue == "" {
				if tcpResp, ok := data.TCPResponses[probe.ID]; ok && m.Field != "" {
					targetValue = ExtractJSONField(tcpResp.Data, m.Field)
				}
			}
			if targetValue == "" {
				if udpResp, ok := data.UDPResponses[probe.ID]; ok && m.Field != "" {
					targetValue = ExtractJSONField(udpResp.Data, m.Field)
				}
			}
		case "ssl_cn":
			if data.TLSCert != nil {
				targetValue = data.TLSCert.CommonName
			}
		case "ssl_san":
			if data.TLSCert != nil {
				targetValue = strings.Join(data.TLSCert.SANs, ",")
			}
		case "ssdp_header":
			if data.SSDPResponse != nil && m.Field != "" {
				targetValue = data.SSDPResponse.Headers[strings.ToUpper(m.Field)]
			}
		case "ssdp_raw":
			if data.SSDPResponse != nil {
				targetValue = data.SSDPResponse.RawData
			}
		case "mdns_service":
			if mdnsResp, ok := data.MDNSResponses[probe.ID]; ok && len(mdnsResp.Services) > 0 {
				targetValue = strings.Join(mdnsResp.Services, "\n")
			}
		case "mdns_txt":
			if mdnsResp, ok := data.MDNSResponses[probe.ID]; ok && mdnsResp.TXTRecords != nil {
				if m.Field != "" {
					targetValue = mdnsResp.TXTRecords[m.Field]
				} else {
					var parts []string
					for k, v := range mdnsResp.TXTRecords {
						parts = append(parts, k+"="+v)
					}
					targetValue = strings.Join(parts, "\n")
				}
			}
		case "mdns_raw":
			if mdnsResp, ok := data.MDNSResponses[probe.ID]; ok {
				targetValue = mdnsResp.RawNames
			}
		default:
			continue
		}

		matched, matchedValue := fm.matchSingle(m, targetValue)
		if m.Negate {
			matched = !matched
		}

		if matched {
			totalConf += m.ConfidenceDelta
			detail := FingerprintMatchDetail{
				ProbeID:         probe.ID,
				MatcherTarget:   m.Target,
				MatcherField:    m.Field,
				ConfidenceDelta: m.ConfidenceDelta,
				MatchedValue:    truncateStr(matchedValue, 200),
			}

			extractSource := targetValue
			if m.VersionExtractField != "" {
				if httpResp, ok := data.HTTPResponses[probe.ID]; ok {
					extractSource = ExtractJSONField(httpResp.Body, m.VersionExtractField)
				}
			}
			if v := fm.extractVersion(m, extractSource); v != "" {
				version = v
				detail.ExtractedVersion = v
			}

			details = append(details, detail)
		}
	}

	return totalConf, details, version
}

// matchSingle dispatches matching based on match_type.
func (fm *FingerprintMatcher) matchSingle(matcher PatternMatcher, value string) (bool, string) {
	switch matcher.MatchType {
	case "contains":
		if strings.Contains(strings.ToLower(value), strings.ToLower(matcher.Value)) {
			return true, value
		}
	case "exact":
		if strings.EqualFold(value, matcher.Value) {
			return true, value
		}
	case "regex":
		re := fm.getCompiledRegex(matcher.Value, matcher.CaseInsensitive)
		if re != nil && re.MatchString(value) {
			match := re.FindString(value)
			return true, match
		}
	case "exists":
		if value != "" {
			return true, value
		}
	case "not_contains":
		if !strings.Contains(strings.ToLower(value), strings.ToLower(matcher.Value)) {
			return true, ""
		}
	case "starts_with":
		if strings.HasPrefix(strings.ToLower(value), strings.ToLower(matcher.Value)) {
			return true, value
		}
	case "ends_with":
		if strings.HasSuffix(strings.ToLower(value), strings.ToLower(matcher.Value)) {
			return true, value
		}
	case "starts_with_hex":
		valueHex := strings.ToLower(hex.EncodeToString([]byte(value)))
		matchHex := strings.ToLower(matcher.Value)
		if strings.HasPrefix(valueHex, matchHex) {
			return true, value
		}
	case "favicon_hash":
		if value == matcher.Value {
			return true, value
		}
	case "json_field":
		if value != "" {
			if matcher.Value == "" {
				return true, value
			}
			re := fm.getCompiledRegex(matcher.Value, matcher.CaseInsensitive)
			if re != nil && re.MatchString(value) {
				return true, value
			}
		}
	}

	return false, ""
}

// extractVersion extracts version from a value using the matcher's regex.
func (fm *FingerprintMatcher) extractVersion(matcher PatternMatcher, value string) string {
	if value == "" || matcher.VersionExtract == "" {
		return ""
	}

	re := fm.getCompiledRegex(matcher.VersionExtract, matcher.CaseInsensitive)
	if re == nil {
		return ""
	}

	groups := re.FindStringSubmatch(value)
	if groups == nil {
		return ""
	}

	group := matcher.VersionExtractGroup
	if group == 0 {
		group = 1
	}

	if group < len(groups) {
		return strings.TrimSpace(groups[group])
	}

	return ""
}

// generateCPE23 interpolates {version} in the CPE 2.3 template.
func (fm *FingerprintMatcher) generateCPE23(template string, version string) string {
	if template == "" {
		return ""
	}
	if version == "" {
		return strings.ReplaceAll(template, "{version}", "*")
	}
	return strings.ReplaceAll(template, "{version}", version)
}

// getCompiledRegex returns a compiled regex with thread-safe cache.
func (fm *FingerprintMatcher) getCompiledRegex(pattern string, caseInsensitive bool) *regexp.Regexp {
	cacheKey := pattern
	if caseInsensitive {
		cacheKey = "(?i)" + pattern
	}

	fm.regexMu.RLock()
	if re, ok := fm.regexCache[cacheKey]; ok {
		fm.regexMu.RUnlock()
		return re
	}
	fm.regexMu.RUnlock()

	compiled := pattern
	if caseInsensitive {
		compiled = "(?i)" + pattern
	}

	re, err := regexp.Compile(compiled)
	if err != nil {
		if fm.OnWarn != nil {
			fm.OnWarn("FINGERPRINT_MATCHER", "REGEX_COMPILE_ERROR",
				fmt.Sprintf("Failed to compile regex '%s' (case_insensitive=%v): %v", pattern, caseInsensitive, err))
		}
		return nil
	}

	fm.regexMu.Lock()
	fm.regexCache[cacheKey] = re
	fm.regexMu.Unlock()

	return re
}

// buildEvidenceSummary builds a human-readable matching summary.
func (fm *FingerprintMatcher) buildEvidenceSummary(pattern *FingerprintPattern, details []FingerprintMatchDetail, confidence float64) string {
	if len(details) == 0 {
		return fmt.Sprintf("No matchers matched for %s", pattern.TaxonomyCode)
	}

	parts := make([]string, 0, len(details))
	for _, d := range details {
		part := d.MatcherTarget
		if d.MatcherField != "" {
			part += ":" + d.MatcherField
		}
		if d.ProbeID != "" {
			part = d.ProbeID + "/" + part
		}
		parts = append(parts, part)
	}

	return fmt.Sprintf("Matched %s (%.0f%%) via %s",
		pattern.TaxonomyCode,
		confidence*100,
		strings.Join(parts, " + "))
}

// ExtractJSONField extracts a field from a JSON body.
// Supports simplified JSONPath: $.result, $.version, $.data.version
func ExtractJSONField(body string, fieldPath string) string {
	if body == "" || fieldPath == "" {
		return ""
	}

	path := strings.TrimPrefix(fieldPath, "$.")
	if path == "" {
		return ""
	}

	var parsed interface{}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return ""
	}

	parts := strings.Split(path, ".")
	current := parsed
	for _, part := range parts {
		obj, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		current, ok = obj[part]
		if !ok {
			return ""
		}
	}

	switch v := current.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%g", v)
	case bool:
		return fmt.Sprintf("%v", v)
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// Mmh3Hash32 computes the MurmurHash3 32-bit hash (Shodan method for favicon).
func Mmh3Hash32(data []byte) string {
	if len(data) == 0 {
		return "0"
	}

	const (
		c1   = 0xcc9e2d51
		c2   = 0x1b873593
		seed = 0
	)

	h := uint32(seed)
	length := len(data)
	nblocks := length / 4

	for i := 0; i < nblocks; i++ {
		k := uint32(data[i*4]) |
			uint32(data[i*4+1])<<8 |
			uint32(data[i*4+2])<<16 |
			uint32(data[i*4+3])<<24

		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2

		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}

	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h ^= k1
	}

	h ^= uint32(length)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16

	return fmt.Sprintf("%d", int32(h))
}

// truncateStr truncates a string to max length.
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// containsInt checks if an int is in a slice.
func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}
