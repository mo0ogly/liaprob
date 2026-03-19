package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/mo0ogly/liaprob/pkg/ai"
	"github.com/mo0ogly/liaprob/pkg/config"
	"github.com/mo0ogly/liaprob/pkg/fingerprint"
	"github.com/mo0ogly/liaprob/pkg/portdb"
	"github.com/mo0ogly/liaprob/pkg/scanner"
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
	case TaskAIAnalyze:
		obs = e.executeAIAnalyze(ctx, task)
	case TaskAIIdentify:
		obs = e.executeAIIdentifyBanner(ctx, task)
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

	if unknownBanners > 0 && e.tools.AI.Available() {
		return Observation{
			NeedsReplan: true,
			NeedsAI:     true,
			Trigger:     TriggerUnknownBanner,
			Details:     fmt.Sprintf("%d ports with empty banners, AI available for identification", unknownBanners),
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

			// Collect probe data
			collected := &fingerprint.CollectedServiceData{}
			for _, pattern := range patterns {
				probeExec.ExecuteProbes(ctx, host.IP, port.Port, pattern.Probes, collected)
			}

			// Match patterns against collected data
			for _, pattern := range patterns {
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

// executeAIAnalyze asks AI to analyze results with full scan data.
func (e *Executor) executeAIAnalyze(ctx context.Context, task *ScanTask) Observation {
	if !e.tools.AI.Available() {
		task.Status = TaskSkipped
		return Observation{}
	}

	// Build detailed prompt with real scan data
	e.memory.mu.RLock()
	var hostDetails string
	for _, h := range e.memory.Hosts {
		if !h.Alive {
			continue
		}
		hostDetails += fmt.Sprintf("\nHost: %s", h.IP)
		if h.Hostname != "" {
			hostDetails += fmt.Sprintf(" (%s)", h.Hostname)
		}
		hostDetails += "\n"
		for _, p := range h.OpenPorts {
			hostDetails += fmt.Sprintf("  Port %d/%s open", p.Port, p.Protocol)
			if p.Banner != "" {
				banner := p.Banner
				if len(banner) > 100 {
					banner = banner[:100]
				}
				hostDetails += fmt.Sprintf(" banner=%q", banner)
			}
			hostDetails += "\n"
		}
		for _, svc := range h.Services {
			hostDetails += fmt.Sprintf("  Service: %s %s (confidence: %.0f%%) CPE: %s\n",
				svc.Name, svc.Version, svc.Confidence*100, svc.CPE)
		}
	}
	stats := e.memory.GetStats()
	e.memory.mu.RUnlock()

	prompt := fmt.Sprintf(
		"SCAN SUMMARY: %d targets, %d alive, %d open ports, %d services fingerprinted.\n\n"+
			"HOST DATA:\n%s\n"+
			"Provide your analysis following the output format specified in the system prompt.",
		stats.TargetsTotal, stats.HostsAlive, stats.PortsOpen,
		stats.ServicesIdentified, hostDetails,
	)

	e.journal.LogAI("AI_QUERY_START", "", map[string]interface{}{
		"provider":   e.tools.AI.Name(),
		"prompt_len": len(prompt),
	}, 0)

	systemPrompt := "You are a network security auditor analyzing automated scan results from LiaProbe.\n\n" +
		"RULES:\n" +
		"- Only report findings supported by the scan data below. Never invent CVEs or versions not present in the data.\n" +
		"- If a service version is unknown, say \"version unknown\" -- do not guess.\n" +
		"- Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO.\n\n" +
		"OUTPUT FORMAT (follow exactly):\n" +
		"## Critical Findings\n" +
		"* [SEVERITY] Host:Port - Finding description\n\n" +
		"## Risk Assessment\n" +
		"* Host IP - CRITICAL|HIGH|MEDIUM|LOW - One-line justification\n\n" +
		"## Remediation (priority order)\n" +
		"1. Action - affected hosts - reason\n\n" +
		"EXAMPLE:\n" +
		"## Critical Findings\n" +
		"* [CRITICAL] 10.0.0.5:6379 - Redis exposed without authentication\n" +
		"* [HIGH] 10.0.0.3:22 - OpenSSH 7.4 (EOL, CVE-2023-38408)\n" +
		"* [MEDIUM] 10.0.0.1:80 - Apache 2.4.49 (path traversal CVE-2021-41773)\n\n" +
		"## Risk Assessment\n" +
		"* 10.0.0.5 - CRITICAL - Unauthenticated data store exposed\n\n" +
		"## Remediation (priority order)\n" +
		"1. Bind Redis to 127.0.0.1 or enable AUTH - 10.0.0.5 - data exfiltration risk"

	// Scale max tokens based on host count (minimum 1024, +128 per host)
	maxTokens := 1024 + stats.HostsAlive*128
	if maxTokens > 4096 {
		maxTokens = 4096
	}

	start := time.Now()
	resp, err := e.tools.AI.Query(ctx, ai.Request{
		SystemPrompt: systemPrompt,
		UserPrompt:   prompt,
		MaxTokens:    maxTokens,
		Temperature:  0.2,
	})

	if err != nil {
		task.Status = TaskFailed
		task.Error = err.Error()
		e.journal.LogAI("AI_QUERY_FAILED", "", map[string]interface{}{
			"error":    err.Error(),
			"provider": e.tools.AI.Name(),
		}, time.Since(start).Milliseconds())
		return Observation{}
	}

	task.Status = TaskComplete
	task.Result = resp.Content

	e.memory.mu.Lock()
	e.memory.Stats.AIQueries++
	e.memory.AIAnalysis = resp.Content
	e.memory.mu.Unlock()

	e.journal.LogAI("AI_ANALYSIS_COMPLETE", "", map[string]interface{}{
		"provider":    resp.Provider,
		"model":       resp.Model,
		"tokens_used": resp.TokensUsed,
		"response_len": len(resp.Content),
	}, resp.DurationMs)

	return Observation{}
}

// executeAIIdentifyBanner asks AI to identify unknown services from banners.
// Collects all ports without an identified service and sends them in batch.
func (e *Executor) executeAIIdentifyBanner(ctx context.Context, task *ScanTask) Observation {
	if !e.tools.AI.Available() {
		task.Status = TaskSkipped
		return Observation{}
	}

	// Collect unidentified ports with banners
	e.memory.mu.RLock()
	var unknownPorts []string
	identifiedPorts := make(map[string]bool)
	for _, h := range e.memory.Hosts {
		for _, svc := range h.Services {
			key := fmt.Sprintf("%s:%d", h.IP, svc.Port)
			identifiedPorts[key] = true
		}
	}
	for _, h := range e.memory.Hosts {
		if !h.Alive {
			continue
		}
		for _, p := range h.OpenPorts {
			key := fmt.Sprintf("%s:%d", h.IP, p.Port)
			if identifiedPorts[key] {
				continue
			}
			entry := fmt.Sprintf("  %s port %d/%s", h.IP, p.Port, p.Protocol)
			if p.Banner != "" {
				banner := p.Banner
				if len(banner) > 120 {
					banner = banner[:120]
				}
				entry += fmt.Sprintf(" banner=%q", banner)
			}
			unknownPorts = append(unknownPorts, entry)
		}
	}
	e.memory.mu.RUnlock()

	if len(unknownPorts) == 0 {
		task.Status = TaskComplete
		return Observation{}
	}

	prompt := fmt.Sprintf(
		"Identify each service below. Output one line per entry, nothing else.\n\n"+
			"UNIDENTIFIED PORTS:\n%s",
		stringJoin(unknownPorts, "\n"),
	)

	bannerSystemPrompt := "You identify network services from port numbers and TCP banners.\n\n" +
		"RULES:\n" +
		"- One line per service, no extra text.\n" +
		"- Format: IP:PORT -> ServiceName Version (cpe:2.3:a:vendor:product:version)\n" +
		"- If banner contains a version string, extract it exactly. Do not round or guess versions.\n" +
		"- If the service cannot be identified with confidence, output: IP:PORT -> UNKNOWN\n" +
		"- If the service is identified but version is unknown: IP:PORT -> ServiceName (no version)\n" +
		"- Common port hints: 3306=MySQL, 5432=PostgreSQL, 6379=Redis, 27017=MongoDB, 5672=RabbitMQ, " +
		"9200=Elasticsearch, 9090=Prometheus, 8500=Consul, 5601=Kibana, 8080/8443=HTTP proxy.\n\n" +
		"EXAMPLES:\n" +
		"Input:  10.0.0.1 port 3306/tcp banner=\"J 8.0.36\\x00..caching_sha2_p\"\n" +
		"Output: 10.0.0.1:3306 -> MySQL 8.0.36 (cpe:2.3:a:oracle:mysql:8.0.36)\n\n" +
		"Input:  10.0.0.2 port 22/tcp banner=\"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu1\"\n" +
		"Output: 10.0.0.2:22 -> OpenSSH 9.6p1 (cpe:2.3:a:openbsd:openssh:9.6p1)\n\n" +
		"Input:  10.0.0.3 port 8080/tcp\n" +
		"Output: 10.0.0.3:8080 -> UNKNOWN"

	e.journal.LogAI("AI_BANNER_ID_START", "", map[string]interface{}{
		"unknown_count": len(unknownPorts),
		"provider":      e.tools.AI.Name(),
	}, 0)

	// Scale tokens: ~40 tokens per identification line
	maxBannerTokens := len(unknownPorts)*40 + 64
	if maxBannerTokens < 256 {
		maxBannerTokens = 256
	}
	if maxBannerTokens > 2048 {
		maxBannerTokens = 2048
	}

	start := time.Now()
	resp, err := e.tools.AI.Query(ctx, ai.Request{
		SystemPrompt: bannerSystemPrompt,
		UserPrompt:   prompt,
		MaxTokens:    maxBannerTokens,
		Temperature:  0.0,
	})

	if err != nil {
		task.Status = TaskFailed
		task.Error = err.Error()
		e.journal.LogAI("AI_BANNER_ID_FAILED", "", map[string]interface{}{
			"error": err.Error(),
		}, time.Since(start).Milliseconds())
		return Observation{}
	}

	task.Status = TaskComplete
	task.Result = resp.Content

	e.memory.mu.Lock()
	e.memory.Stats.AIQueries++
	e.memory.mu.Unlock()

	e.journal.LogAI("AI_BANNER_ID_COMPLETE", "", map[string]interface{}{
		"provider":    resp.Provider,
		"model":       resp.Model,
		"tokens_used": resp.TokensUsed,
		"identifications": resp.Content,
	}, resp.DurationMs)

	return Observation{}
}

// stringJoin joins strings with a separator (avoids importing strings in executor).
func stringJoin(elems []string, sep string) string {
	if len(elems) == 0 {
		return ""
	}
	result := elems[0]
	for _, e := range elems[1:] {
		result += sep + e
	}
	return result
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
