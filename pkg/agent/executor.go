package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mo0ogly/liaprobe/pkg/ai"
	"github.com/mo0ogly/liaprobe/pkg/config"
	"github.com/mo0ogly/liaprobe/pkg/fingerprint"
	"github.com/mo0ogly/liaprobe/pkg/portdb"
	"github.com/mo0ogly/liaprobe/pkg/scanner"
)

// ToolKit groups all tools available to the executor.
type ToolKit struct {
	TCPScanner   *scanner.TCPScanner
	AliveChecker *scanner.AliveChecker
	Matcher      *fingerprint.FingerprintMatcher
	ProbeExec    *fingerprint.ProbeExecutor
	AI           ai.AIProvider
	Config       *config.Config
}

// Executor executes tasks from a plan.
type Executor struct {
	tools   *ToolKit
	memory  *WorkingMemory
	journal *Journal
}

// NewExecutor creates an executor.
func NewExecutor(tools *ToolKit, memory *WorkingMemory, journal *Journal) *Executor {
	return &Executor{
		tools:   tools,
		memory:  memory,
		journal: journal,
	}
}

// ExecuteTask executes a task and returns an observation.
func (e *Executor) ExecuteTask(ctx context.Context, task *ScanTask) Observation {
	start := time.Now()
	task.Status = TaskRunning

	e.journal.LogTask("TASK_START", task.ID, map[string]interface{}{
		"type": string(task.Type),
	}, 0)

	var obs Observation

	switch task.Type {
	case TaskExpandTargets:
		obs = e.executeExpand(ctx, task)
	case TaskAliveCheck:
		obs = e.executeAlive(ctx, task)
	case TaskPortScan:
		obs = e.executePortScan(ctx, task)
	case TaskBannerGrab:
		obs = e.executeBannerGrab(ctx, task)
	case TaskFingerprint:
		obs = e.executeFingerprint(ctx, task)
	case TaskContextExpand:
		obs = e.executeContextExpand(ctx, task)
	case TaskValidate:
		obs = e.executeValidate(ctx, task)
	case TaskAIAnalyze:
		obs = e.executeAIAnalyze(ctx, task)
	case TaskReport:
		obs = e.executeReport(ctx, task)
	default:
		task.Status = TaskFailed
		task.Error = fmt.Sprintf("unknown task type: %s", task.Type)
		obs = Observation{NeedsReplan: false}
	}

	task.Duration = time.Since(start)

	e.journal.LogTask("TASK_DONE", task.ID, map[string]interface{}{
		"type":         string(task.Type),
		"status":       string(task.Status),
		"needs_replan": obs.NeedsReplan,
	}, time.Since(start).Milliseconds())

	return obs
}

// executeExpand resolves targets (CIDR, hostname -> IPs).
func (e *Executor) executeExpand(ctx context.Context, task *ScanTask) Observation {
	targets, err := scanner.ExpandTargets(task.Targets, e.tools.Config.MaxSubdomains)
	if err != nil {
		task.Status = TaskFailed
		task.Error = err.Error()
		return Observation{NeedsReplan: true, Trigger: TriggerHostTimeout, Details: err.Error()}
	}

	task.Status = TaskComplete
	task.Result = targets
	e.memory.Stats.TargetsTotal = len(targets)

	for _, t := range targets {
		e.memory.AddHost(t.IP, t.Hostname, false)
	}

	if len(targets) > 1000 {
		return Observation{
			NeedsReplan: true,
			Trigger:     TriggerTooManyHosts,
			Details:     fmt.Sprintf("%d targets expanded, may need sampling", len(targets)),
		}
	}

	return Observation{}
}

// executeAlive filters active hosts.
func (e *Executor) executeAlive(ctx context.Context, task *ScanTask) Observation {
	// Retrieve targets from previous task result
	targets := e.targetsFromMemory()

	ac := e.tools.AliveChecker
	alive := ac.CheckAlive(ctx, targets)

	for _, t := range alive {
		e.memory.AddHost(t.IP, t.Hostname, true)
	}

	task.Status = TaskComplete
	task.Result = alive

	if len(alive) == 0 {
		return Observation{
			NeedsReplan: true,
			Trigger:     TriggerHostTimeout,
			Details:     "no alive hosts detected",
		}
	}

	return Observation{}
}

// executePortScan scans TCP ports.
func (e *Executor) executePortScan(ctx context.Context, task *ScanTask) Observation {
	ps := e.tools.TCPScanner
	aliveHosts := e.aliveFromMemory()

	for _, host := range aliveHosts {
		select {
		case <-ctx.Done():
			task.Status = TaskFailed
			task.Error = "cancelled"
			return Observation{}
		default:
		}

		openPorts := ps.ScanPorts(ctx, host.IP, task.Ports)
		for _, op := range openPorts {
			e.memory.AddOpenPort(host.IP, op.Port, op.Protocol, "")
		}
	}

	task.Status = TaskComplete
	return Observation{}
}

// executeBannerGrab grabs banners from open ports.
func (e *Executor) executeBannerGrab(ctx context.Context, task *ScanTask) Observation {
	ps := e.tools.TCPScanner
	timeout := 2 * time.Second
	unknownBanners := 0

	e.memory.mu.RLock()
	hosts := make([]*HostState, 0, len(e.memory.Hosts))
	for _, h := range e.memory.Hosts {
		if h.Alive {
			hosts = append(hosts, h)
		}
	}
	e.memory.mu.RUnlock()

	for _, host := range hosts {
		for i, port := range host.OpenPorts {
			select {
			case <-ctx.Done():
				task.Status = TaskFailed
				task.Error = "cancelled"
				return Observation{}
			default:
			}

			banner := ps.GrabBanner(host.IP, port.Port, timeout)
			if banner != "" {
				e.memory.mu.Lock()
				if h, ok := e.memory.Hosts[host.IP]; ok && i < len(h.OpenPorts) {
					h.OpenPorts[i].Banner = banner
				}
				e.memory.Stats.BannersGrabbed++
				e.memory.mu.Unlock()
			} else {
				unknownBanners++
			}
		}
	}

	task.Status = TaskComplete

	if unknownBanners > 0 {
		return Observation{
			NeedsReplan: false,
			NeedsAI:     true,
			Details:     fmt.Sprintf("%d ports with empty banners", unknownBanners),
		}
	}

	return Observation{}
}

// executeFingerprint runs the fingerprinting engine on open ports.
func (e *Executor) executeFingerprint(ctx context.Context, task *ScanTask) Observation {
	matcher := e.tools.Matcher
	probeExec := e.tools.ProbeExec

	if matcher == nil || probeExec == nil {
		task.Status = TaskSkipped
		return Observation{}
	}

	e.memory.mu.RLock()
	hosts := make([]*HostState, 0, len(e.memory.Hosts))
	for _, h := range e.memory.Hosts {
		if h.Alive && len(h.OpenPorts) > 0 {
			hosts = append(hosts, h)
		}
	}
	e.memory.mu.RUnlock()

	for _, host := range hosts {
		for _, port := range host.OpenPorts {
			select {
			case <-ctx.Done():
				task.Status = TaskFailed
				task.Error = "cancelled"
				return Observation{}
			default:
			}

			// Get patterns for this port
			index := fingerprint.GetPatternIndex()
			if index == nil {
				continue
			}
			patterns := index.ByPort[port.Port]
			if len(patterns) == 0 {
				continue
			}

			// Phase 0: Pre-probe HTTP/TLS for HTTP ports with no banner
			collected := &fingerprint.CollectedServiceData{
				Port:     port.Port,
				Protocol: port.Protocol,
				Banner:   port.Banner,
			}

			if port.Banner == "" && index.HTTPPorts[port.Port] {
				// HTTP ports need a request to get headers - do a default HTTP probe
				defaultHTTPProbe := fingerprint.PatternProbe{
					ID:    "_auto_http",
					Layer: "L7_HTTP",
					Ports: []int{port.Port},
				}
				probeExec.ExecuteProbes(ctx, host.IP, port.Port,
					[]fingerprint.PatternProbe{defaultHTTPProbe}, collected)
			}
			if index.TLSPorts[port.Port] && collected.TLSCert == nil {
				// TLS ports: grab cert for CN/SAN matching
				tlsProbe := fingerprint.PatternProbe{
					ID:    "_auto_tls",
					Layer: "TLS_CERT",
					Ports: []int{port.Port},
				}
				probeExec.ExecuteProbes(ctx, host.IP, port.Port,
					[]fingerprint.PatternProbe{tlsProbe}, collected)
			}

			// Phase 1: Passive matching (banner + service + HTTP headers)
			maxProbes := e.tools.Config.Fingerprint.MaxProbesPerService
			if maxProbes <= 0 {
				maxProbes = 10
			}
			var candidates []*fingerprint.FingerprintPattern
			for _, pattern := range patterns {
				result := matcher.EvaluatePattern(pattern, collected)
				if result != nil && result.Confidence > 0 {
					candidates = append(candidates, pattern)
				}
			}

			// If no passive matches, take top-priority patterns (limit to maxProbes)
			if len(candidates) == 0 {
				limit := maxProbes
				if limit > len(patterns) {
					limit = len(patterns)
				}
				candidates = patterns[:limit]
			}

			// Phase 2: Active probes only on candidates (limited)
			if len(candidates) > maxProbes {
				candidates = candidates[:maxProbes]
			}
			for _, pattern := range candidates {
				probeExec.ExecuteProbes(ctx, host.IP, port.Port, pattern.Probes, collected)
			}

			// Phase 3: Final matching on enriched data
			for _, pattern := range candidates {
				result := matcher.EvaluatePattern(pattern, collected)
				if result != nil && result.Confidence >= e.tools.Config.Fingerprint.ConfidenceThreshold {
					e.memory.AddService(host.IP, ServiceState{
						Port:       port.Port,
						Name:       result.TaxonomyName,
						Product:    result.TaxonomyCode,
						Version:    result.Version,
						CPE:        result.CPE23,
						Confidence: result.Confidence,
						PatternID:  result.PatternID,
					})
				}
			}
		}
	}

	task.Status = TaskComplete
	return Observation{}
}

// executeContextExpand adds contextual ports based on services found.
func (e *Executor) executeContextExpand(ctx context.Context, task *ScanTask) Observation {
	e.memory.mu.RLock()
	var foundServices []string
	for _, host := range e.memory.Hosts {
		for _, svc := range host.Services {
			foundServices = append(foundServices, svc.Name)
		}
		// Also enrich via known banners
		for _, port := range host.OpenPorts {
			if port.Banner != "" {
				svc := portdb.GuessServiceFromBanner(port.Banner)
				if svc != "" {
					foundServices = append(foundServices, svc)
				}
			}
		}
	}
	e.memory.mu.RUnlock()

	// Deduplication
	seen := make(map[string]bool)
	var unique []string
	for _, s := range foundServices {
		if !seen[s] {
			seen[s] = true
			unique = append(unique, s)
		}
	}

	// Get additional ports via service names
	var extraPorts []int
	for _, svc := range unique {
		ports := portdb.ContextPortsForService(svc)
		extraPorts = append(extraPorts, ports...)
	}

	if len(extraPorts) == 0 {
		task.Status = TaskComplete
		return Observation{}
	}

	// Scan additional ports on alive hosts
	aliveHosts := e.aliveFromMemory()
	ps := e.tools.TCPScanner

	for _, host := range aliveHosts {
		select {
		case <-ctx.Done():
			task.Status = TaskFailed
			task.Error = "cancelled"
			return Observation{}
		default:
		}

		openPorts := ps.ScanPorts(ctx, host.IP, extraPorts)
		for _, op := range openPorts {
			e.memory.AddOpenPort(host.IP, op.Port, op.Protocol, "")
		}
	}

	task.Status = TaskComplete
	task.Result = map[string]interface{}{
		"services_found": unique,
		"extra_ports":    extraPorts,
	}

	return Observation{}
}

// executeAIAnalyze asks AI to analyze results.
func (e *Executor) executeAIAnalyze(ctx context.Context, task *ScanTask) Observation {
	if !e.tools.AI.Available() {
		task.Status = TaskSkipped
		return Observation{}
	}

	// Build prompt with memory data
	stats := e.memory.GetStats()
	prompt := fmt.Sprintf(
		"Analyze this network scan result:\n"+
			"- Targets: %d\n- Alive hosts: %d\n- Open ports: %d\n"+
			"- Services identified: %d\n- Banners grabbed: %d\n"+
			"Provide security observations and recommendations.",
		stats.TargetsTotal, stats.HostsAlive, stats.PortsOpen,
		stats.ServicesIdentified, stats.BannersGrabbed,
	)

	start := time.Now()
	resp, err := e.tools.AI.Query(ctx, ai.Request{
		SystemPrompt: "You are a network security analyst. Analyze scan results concisely.",
		UserPrompt:   prompt,
		MaxTokens:    512,
		Temperature:  0.3,
	})

	if err != nil {
		task.Status = TaskFailed
		task.Error = err.Error()
		e.journal.LogAI("AI_QUERY_FAILED", "", map[string]interface{}{
			"error": err.Error(),
		}, time.Since(start).Milliseconds())
		return Observation{}
	}

	task.Status = TaskComplete
	task.Result = resp.Content

	e.memory.mu.Lock()
	e.memory.Stats.AIQueries++
	e.memory.mu.Unlock()

	e.journal.LogAI("AI_ANALYSIS", "", map[string]interface{}{
		"provider":    resp.Provider,
		"model":       resp.Model,
		"tokens_used": resp.TokensUsed,
	}, resp.DurationMs)

	return Observation{}
}

// executeValidate compares expected services against discovered services.
func (e *Executor) executeValidate(_ context.Context, task *ScanTask) Observation {
	// Get goal from the plan via journal/params -- we use the executor's memory
	// The expectations are passed as task params by the agent
	expectations, ok := task.Params["expectations"].([]ServiceExpectation)
	if !ok || len(expectations) == 0 {
		task.Status = TaskSkipped
		return Observation{Details: "no expectations to validate"}
	}

	for _, exp := range expectations {
		host := e.memory.GetHost(exp.IP)

		// Host not found or not alive
		if host == nil || !host.Alive {
			e.memory.AddValidation(ValidationState{
				IP:       exp.IP,
				Port:     exp.Port,
				Expected: exp.Service,
				Found:    "",
				Verdict:  "UNREACHABLE",
				Details:  "host not alive or not found",
			})
			continue
		}

		// Find the service on the expected port
		var found *ServiceState
		for _, svc := range host.Services {
			if svc.Port == exp.Port {
				found = &svc
				break
			}
		}

		if found == nil {
			// Check if the port is open but no service identified
			portOpen := false
			for _, p := range host.OpenPorts {
				if p.Port == exp.Port {
					portOpen = true
					break
				}
			}
			if !portOpen {
				e.memory.AddValidation(ValidationState{
					IP:       exp.IP,
					Port:     exp.Port,
					Expected: exp.Service,
					Found:    "",
					Verdict:  "UNREACHABLE",
					Details:  "port not open",
				})
			} else {
				e.memory.AddValidation(ValidationState{
					IP:       exp.IP,
					Port:     exp.Port,
					Expected: exp.Service,
					Found:    "",
					Verdict:  "UNKNOWN",
					Details:  "port open but service not identified",
				})
			}
			continue
		}

		// Compare expected vs found
		if matchesExpectation(exp.Service, *found) {
			e.memory.AddValidation(ValidationState{
				IP:         exp.IP,
				Port:       exp.Port,
				Expected:   exp.Service,
				Found:      found.Name,
				Verdict:    "PASS",
				Confidence: found.Confidence,
			})
		} else {
			e.memory.AddValidation(ValidationState{
				IP:         exp.IP,
				Port:       exp.Port,
				Expected:   exp.Service,
				Found:      found.Name,
				Verdict:    "FAIL",
				Confidence: found.Confidence,
				Details:    fmt.Sprintf("expected %s, found %s", exp.Service, found.Name),
			})
		}
	}

	task.Status = TaskComplete
	return Observation{}
}

// matchesExpectation checks if a found service matches the expected service name.
// Supports exact (case-insensitive), contains, and partial matching.
func matchesExpectation(expected string, found ServiceState) bool {
	norm := strings.ToLower(expected)

	// Exact match on name or product
	if strings.EqualFold(found.Name, expected) || strings.EqualFold(found.Product, expected) {
		return true
	}

	// Contains match
	if strings.Contains(strings.ToLower(found.Name), norm) ||
		strings.Contains(strings.ToLower(found.Product), norm) {
		return true
	}

	return false
}

// executeReport is a no-op in the executor (formatting is done outside).
func (e *Executor) executeReport(_ context.Context, task *ScanTask) Observation {
	task.Status = TaskComplete
	return Observation{}
}

// targetsFromMemory rebuilds the target list from memory.
func (e *Executor) targetsFromMemory() []scanner.Target {
	e.memory.mu.RLock()
	defer e.memory.mu.RUnlock()
	targets := make([]scanner.Target, 0, len(e.memory.Hosts))
	for _, h := range e.memory.Hosts {
		targets = append(targets, scanner.Target{IP: h.IP, Hostname: h.Hostname})
	}
	return targets
}

// aliveFromMemory returns alive hosts from memory.
func (e *Executor) aliveFromMemory() []scanner.Target {
	e.memory.mu.RLock()
	defer e.memory.mu.RUnlock()
	var alive []scanner.Target
	for _, h := range e.memory.Hosts {
		if h.Alive {
			alive = append(alive, scanner.Target{IP: h.IP, Hostname: h.Hostname})
		}
	}
	return alive
}
