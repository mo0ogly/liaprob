# LiaProbe

**Intelligent agentic network scanner.** Pure Go, zero dependencies, zero nmap.

LiaProbe combines TCP port scanning with an **OODA agentic loop** (Observe-Orient-Decide-Act) that dynamically adapts its strategy based on what it discovers. When unknown services are found, LiaProbe replans on the fly -- adding AI-powered banner identification, contextual port expansion, or concurrency adjustments -- without human intervention.

```
Goal -> Plan -> Execute -> Observe -> Replan -> Execute -> ... -> Report
```

## Why LiaProbe?

| Traditional scanner | LiaProbe |
|--------------------|------------------------------------|
| Static port list | Adaptive: discovers DB on 3306, expands to 3307-3310 |
| Dumb banner grab | AI identifies unknown services in real-time |
| Fixed concurrency | Detects rate limiting, backs off automatically |
| Flat output | Full audit journal (JSONL), every decision traced |
| Requires nmap/masscan | Single binary, zero external dependencies |

## Install

```bash
go install github.com/mo0ogly/liaprob/cmd/liaprobe@latest
```

Or build from source:

```bash
git clone https://github.com/mo0ogly/liaprob.git
cd liaprob
make build
# Binary: ./bin/liaprobe
```

**Requirements:** Go 1.22+

## Quick Start

```bash
# Smart scan -- adaptive, discovers and expands (recommended)
liaprobe 192.168.1.0/24

# Specific ports only
liaprobe --mode specific --ports 22,80,443,3306,5432 10.0.0.1

# Hunt for a service across a range
liaprobe --mode hunt --hunt-service jenkins 10.0.0.0/24

# Full 65535 ports with table output
liaprobe --mode full --output table 192.168.1.1

# With AI-powered analysis (Groq -- fast, free tier)
liaprobe --ai groq 192.168.1.0/24

# With AI-powered analysis (Ollama -- local, private)
liaprobe --ai ollama --ai-model qwen2.5:7b 192.168.1.0/24

# With AI-powered analysis (Claude)
ANTHROPIC_API_KEY=sk-... liaprobe --ai claude 192.168.1.0/24

# Stealth profile -- slow, minimal footprint
liaprobe --profile stealth 10.0.0.0/24

# Dry run -- plan only, no packets sent
liaprobe --dry-run 192.168.1.0/24

# API server mode (for integration with other tools)
liaprobe --serve --api-port 8082
```

## OODA Agentic Loop

LiaProbe is not a port scanner with AI bolted on. The AI is part of the **decision loop**.

```
                    +--------+
               +--->|  PLAN  |---+
               |    +--------+   |
               |                 v
          +---------+      +---------+
          | REPLAN  |<-----| EXECUTE |
          +---------+      +---------+
               ^                 |
               |    +---------+  |
               +----| OBSERVE |<-+
                    +---------+
```

Each scan produces an ordered task graph with dependencies:

1. **Expand targets** -- resolve CIDR, hostnames to IPs
2. **Alive check** -- TCP RST detection (not just connect; "connection refused" = host alive)
3. **Port scan** -- concurrent TCP connect with configurable workers
4. **Banner grab** -- raw TCP read + TLS handshake on common ports
5. **Fingerprint** -- 35 pattern-based probes with CPE 2.3 output and confidence scoring
6. **Context expand** -- discover DB on :3306? auto-expand to :3307-3310 (smart mode)
7. **AI analyze** -- send full scan context to LLM for risk assessment
8. **Report** -- structured output (JSON or table)

When the observer detects anomalies, it triggers a **replan**:

| Trigger | Action |
|---------|--------|
| Unknown banners detected | Add AI banner identification task |
| Too many hosts (>1000) | Add sampling task |
| Host timeout | Retry with exponential backoff (max 3) |
| Rate limiting detected | Reduce concurrency, add delay |
| Unexpected service found | Add contextual port expansion |

The entire process is traced in a non-disableable **journal** (JSONL) for full audit traceability. Every task start, completion, observation, replan decision, and AI query is recorded with timestamps and durations.

## AI Providers

LiaProbe supports any LLM for real-time banner identification and risk assessment. The AI is optional -- scans work fine without it, but with AI you get service identification for unknown banners and a risk analysis in the report.

| Provider | Flag | Env var (auto-detected) | Default model |
|----------|------|------------------------|---------------|
| Groq | `--ai groq` | `GROQ_API_KEY` | llama-3.3-70b-versatile |
| OpenAI | `--ai openai` | `OPENAI_API_KEY` | gpt-4o |
| Anthropic | `--ai anthropic` | `ANTHROPIC_API_KEY` | claude-sonnet-4-20250514 |
| Ollama | `--ai ollama` | -- | (local, user-specified) |
| Custom | `--ai custom` | `--ai-key KEY` | `--ai-model MODEL` |

```bash
# API keys auto-detected from environment
export GROQ_API_KEY=gsk_...
liaprobe --ai groq 10.0.0.0/24

# Or pass explicitly
liaprobe --ai openai --ai-key sk-... --ai-model gpt-4o-mini 10.0.0.0/24

# Override endpoint for self-hosted / proxied
liaprobe --ai custom --ai-endpoint http://my-llm:8080/v1 --ai-model my-model 10.0.0.0/24
```

When AI is enabled, two additional tasks appear in the plan:
- **AI Analyze** -- full scan context sent to LLM for risk assessment (critical findings, host risk levels, prioritized remediation)
- **AI Banner ID** -- batch identification of services on ports where fingerprinting returned no match

## Scan Modes

| Mode | Description | Default Ports |
|------|-------------|---------------|
| `smart` | Adaptive: top 1000 + contextual expansion based on discoveries | Top 1000 |
| `full` | All 65535 ports | 1-65535 |
| `specific` | Only user-specified ports | `--ports` required |
| `hunt` | Search for a specific service | Top 1000 |

## Scan Profiles

| Profile | Workers | Timeout | Use Case |
|---------|---------|---------|----------|
| `fast` | 500 | 300ms | Quick reconnaissance |
| `standard` | 200 | 500ms | Default balanced scan |
| `thorough` | 100 | 1000ms | Complete inventory |
| `stealth` | 5 | 2000ms | Minimal network footprint |

## Fingerprint Engine

35 built-in patterns covering:

- **Web Servers**: Nginx, Apache, IIS, Tomcat, lighttpd, Caddy
- **Databases**: MySQL, MariaDB, PostgreSQL, MSSQL, MongoDB, Redis, Elasticsearch
- **Infrastructure**: OpenSSH, vsftpd, Postfix, RabbitMQ, Docker, Grafana, Jenkins, Prometheus
- **Networking**: HAProxy, Traefik, Envoy, Consul, Vault, Squid, Varnish
- **Security/DevOps**: Zabbix, Nagios, Kibana, SonarQube, Nexus, Gitea, GitLab

Patterns use the `lia-fingerprint-v1` schema with HTTP/TCP/TLS probes, regex matchers, confidence scoring, and CPE 2.3 output.

### Contributing a Pattern

Patterns are simple JSON arrays. Drop a file in `patterns/lia/`:

```json
[{
  "id": "lia-myservice",
  "schema": "lia-fingerprint-v1",
  "taxonomy_code": "CAT.MYSERVICE",
  "taxonomy_name": "My Service",
  "source": "community",
  "default_ports": [8080],
  "probes": [
    {"layer": "L7_HTTP", "path": "/api/health", "method": "GET"}
  ],
  "matchers": [
    {"field": "http_body", "match_type": "contains", "value": "myservice", "confidence_delta": 0.7},
    {"field": "http_body", "match_type": "regex", "value": "version\":\"([\\d.]+)\"", "confidence_delta": 0.3, "version_group": 1}
  ],
  "cpe_template": "cpe:2.3:a:vendor:myservice:{version}:*:*:*:*:*:*:*"
}]
```

## Configuration

Configuration is loaded in order (later overrides earlier):

1. **Defaults** -- sensible out-of-the-box
2. **YAML config** -- `liaprobe.yaml`, `~/.config/liaprobe/config.yaml`, `/etc/liaprobe/config.yaml`
3. **Environment variables** -- `LIAPROBE_MODE`, `LIAPROBE_AI_PROVIDER`, etc.
4. **CLI flags** -- highest priority

```yaml
# liaprobe.yaml
mode: smart
profile: standard
port_workers: 200
alive_workers: 50

fingerprint:
  probes_enabled: true
  confidence_threshold: 0.50
  pattern_dirs:
    - path: patterns/lia
      source: lia
      priority: 100
      enabled: true

ai:
  enabled: true
  provider: groq
  timeout: 120s

store:
  type: file
  path: .liaprobe

output_format: json
journal: true
max_replans: 5
```

## API Server Mode

Run LiaProbe as an HTTP API server for integration with security platforms:

```bash
liaprobe --serve --api-port 8082
```

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/version` | Version info |
| POST | `/api/scan` | Start a scan (async) |
| GET | `/api/scan/status?id=X` | Scan status |
| POST | `/api/scan/stop?id=X` | Stop a running scan |
| GET | `/api/scan/results?id=X` | Scan results (JSON) |
| GET | `/api/scan/journal?id=X` | Full audit journal |
| GET | `/api/scan/stream?id=X` | SSE live event stream |

## Discovery Lab

A Docker Compose lab with 14 real services for testing:

```bash
docker compose -f docker-compose.lab.yml up -d
liaprobe --mode smart --ai groq --output table 172.20.0.0/24
docker compose -f docker-compose.lab.yml down
```

Services: Nginx, Apache, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, RabbitMQ, Grafana, Prometheus, Consul, Gitea, SonarQube, Kibana.

## CLI Reference

```
Usage: liaprobe [flags] <targets...>

Targets: IPv4 address, CIDR range, hostname

Flags:
  --mode        string   Scan mode: smart, full, specific, hunt (default: smart)
  --profile     string   Scan profile: fast, standard, thorough, stealth
  --ports       string   Ports to scan, comma-separated (mode specific)
  --hunt-service string  Service name to hunt (mode hunt)
  --hunt-banner string   Banner pattern to hunt (mode hunt)
  --output      string   Output format: json, table (default: json)
  -o            string   Output file (default: stdout)
  --ai          string   AI provider: ollama, openai, groq, anthropic, claude, custom
  --ai-endpoint string   AI provider endpoint URL
  --ai-model    string   AI model name
  --ai-key      string   AI API key
  --no-ai                Disable AI (default: false)
  --workers     int      Port scan workers (default: profile-dependent)
  --timeout     int      Port connect timeout in ms (default: profile-dependent)
  --config      string   Config file path
  --store       string   Store backend: file, memory (default: file)
  --store-dir   string   Store directory (default: .liaprobe)
  --serve                Start API server mode
  --api-port    int      API server port (default: 8082)
  --dry-run              Plan without executing
  --verbose              Enable debug output
  --version              Print version and exit
```

## Development

```bash
make build      # Build binary to ./bin/liaprobe
make test       # Run tests with race detector
make cover      # Coverage report
make vet        # Go vet
make lint       # golangci-lint + staticcheck
make release    # Cross-compile: linux/darwin/windows, amd64/arm64
make clean      # Remove build artifacts
make install    # Install to $GOPATH/bin
```

## Architecture

```
liaprobe/
  cmd/liaprobe/        CLI entry point, flag parsing, AI provider factory
  api/                 HTTP API server + SSE live streaming
  pkg/
    agent/             OODA agentic loop
      planner.go         Goal decomposition, task graph generation
      executor.go        Task execution (scan, banner, fingerprint, AI)
      observer.go        Result analysis, anomaly detection
      replanner.go       Dynamic plan modification
      journal.go         Non-disableable audit trail (JSONL)
      memory.go          Working memory (hosts, ports, banners, dedup)
    ai/                AI provider abstraction
      provider.go        Interface definition
      ollama.go          Ollama local provider
      openai.go          OpenAI-compatible (Groq, OpenAI, custom)
      anthropic.go       Anthropic Messages API (Claude)
      multi.go           Multi-provider fallback chain
      liasec.go          LIA-SEC platform integration
      noop.go            No-op (AI disabled)
    config/            Configuration (YAML, env, profiles, validation)
    fingerprint/       Pattern-based service identification engine
    log/               Lightweight structured CLI logger
    output/            Output formatters (JSON, table)
    portdb/            Known ports database + service hints
    scanner/           TCP scanner, alive checker, target expander
    store/             Scan result persistence (file, memory)
  patterns/lia/        Fingerprint pattern definitions (JSON)
  internal/version/    Build-time version injection (ldflags)
```

**8,400+ lines of Go** | 50 source files | 8 test files | 35 fingerprint patterns

## License

[MIT](LICENSE)
