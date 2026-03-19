# LiaProbe

Intelligent agentic network scanner. Pure Go, zero dependencies, zero nmap.

LiaProbe combines traditional port scanning with an **OODA agentic loop** (Observe-Orient-Decide-Act) that dynamically adapts its scan strategy based on what it discovers.

## Features

- **Agentic scanning**: OODA loop with goal decomposition, dynamic replanning, and contextual port expansion
- **4 scan modes**: smart (adaptive), full (all ports), specific (user-defined), hunt (find a service)
- **4 scan profiles**: fast, standard, thorough, stealth
- **35 fingerprint patterns**: web servers, databases, infrastructure, networking, security tools
- **AI integration**: Ollama (local), OpenAI-compatible, or custom providers for banner analysis
- **Dual mode**: CLI standalone + HTTP API server (`--serve` for LIA-SEC integration)
- **SSE live streaming**: Real-time journal events via Server-Sent Events
- **YAML config**: File-based configuration with env var and CLI flag overrides
- **Pure Go**: Zero CGO, zero nmap, zero external binary dependency

## Install

```bash
go install github.com/mo0ogly/liaprobe/cmd/liaprobe@latest
```

Or build from source:

```bash
git clone https://github.com/mo0ogly/liaprobe.git
cd liaprobe
make build
```

## Quick Start

```bash
# Smart scan (adaptive, recommended)
liaprobe 192.168.1.0/24

# Specific ports
liaprobe --mode specific --ports 22,80,443,8080 10.0.0.1

# Hunt for a service across a range
liaprobe --mode hunt --hunt-service jenkins 10.0.0.0/24

# Full scan with table output
liaprobe --mode full --output table 192.168.1.1

# With AI-assisted banner analysis (Ollama)
liaprobe --ai ollama --ai-model qwen2.5:7b 192.168.1.0/24

# Stealth profile (slow, low footprint)
liaprobe --profile stealth 10.0.0.0/24

# Dry run (plan only, no execution)
liaprobe --dry-run 192.168.1.0/24

# API server mode (for LIA-SEC integration)
liaprobe --serve --api-port 8082
```

## Scan Modes

| Mode | Description | Default Ports |
|------|-------------|---------------|
| `smart` | Adaptive: top 1000 + contextual expansion based on discoveries | Top 1000 |
| `full` | All 65535 ports, all probes | 1-65535 |
| `specific` | Only user-specified ports | `--ports` required |
| `hunt` | Search for a specific service across wide port ranges | Top 1000 |

## Scan Profiles

| Profile | Workers | Timeout | Use Case |
|---------|---------|---------|----------|
| `fast` | 500 | 300ms | Quick reconnaissance |
| `standard` | 200 | 500ms | Default balanced scan |
| `thorough` | 100 | 1000ms | Complete inventory |
| `stealth` | 5 | 2000ms | Minimal network footprint |

## Configuration

LiaProbe loads configuration in this order (later overrides earlier):

1. Defaults
2. YAML config file (`liaprobe.yaml`, `~/.config/liaprobe/`, `/etc/liaprobe/`)
3. Environment variables (`LIAPROBE_MODE`, `LIAPROBE_AI_PROVIDER`, etc.)
4. CLI flags

Example `liaprobe.yaml`:

```yaml
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
  provider: ollama
  endpoint: http://localhost:11434
  model: qwen2.5:7b
  timeout: 10s

store:
  type: file
  path: .liaprobe

output_format: json
journal: true
max_replans: 5
```

## OODA Agentic Loop

LiaProbe is not just a port scanner. It's an **agentic system** that:

1. **Plans**: Decomposes the scan goal into ordered tasks with dependencies
2. **Executes**: Runs each task (expand targets, alive check, port scan, banner grab, fingerprint)
3. **Observes**: Analyzes results for anomalies (unknown banners, rate limiting, unexpected services)
4. **Replans**: Dynamically adjusts the plan (add AI banner ID, reduce concurrency, expand context ports)

The entire process is traced in a non-disableable **journal** (JSONL format) for full audit traceability.

### Replan Triggers

| Trigger | Action |
|---------|--------|
| Too many hosts (>1000) | Add sampling task |
| Host timeout | Retry with backoff (max 3) |
| Unknown banner | Add AI banner identification |
| Rate limited | Reduce concurrency, add delay |
| Unexpected service | Add contextual port expansion |

## Fingerprint Patterns

35 patterns covering common technologies:

**Web Servers**: Nginx, Apache, IIS, Tomcat, lighttpd, Caddy
**Databases**: MySQL, MariaDB, PostgreSQL, MSSQL, MongoDB, Redis, Elasticsearch
**Infrastructure**: OpenSSH, vsftpd, Postfix, RabbitMQ, Docker, Grafana, Jenkins, Prometheus
**Networking**: HAProxy, Traefik, Envoy, Consul, Vault, Squid, Varnish
**Security/DevOps**: Zabbix, Nagios, Kibana, SonarQube, Nexus, Gitea, GitLab

Patterns use the `lia-fingerprint-v1` schema with CPE 2.3 templates and confidence scoring.

### Community Patterns

Patterns are simple JSON arrays. Contributing a new pattern:

```json
[{
  "id": "lia-myservice",
  "schema": "lia-fingerprint-v1",
  "taxonomy_code": "CAT.MYSERVICE",
  "taxonomy_name": "My Service",
  "source": "lia",
  "default_ports": [8080],
  "probes": [{"layer": "L7_HTTP", "path": "/health", "method": "GET"}],
  "matchers": [
    {"field": "http_body", "match_type": "contains", "value": "myservice", "confidence_delta": 0.7},
    {"field": "http_body", "match_type": "regex", "value": "version\":\"([\\d.]+)\"", "confidence_delta": 0.3, "version_group": 1}
  ],
  "cpe_template": "cpe:2.3:a:vendor:myservice:{version}:*:*:*:*:*:*:*"
}]
```

## API Server Mode

Start LiaProbe as an HTTP API server for integration with LIA-SEC or other tools:

```bash
liaprobe --serve --api-port 8082
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/version` | Version info |
| POST | `/api/scan` | Start a scan |
| GET | `/api/scan/status?id=X` | Scan status |
| POST | `/api/scan/stop?id=X` | Stop a scan |
| GET | `/api/scan/results?id=X` | Scan results |
| GET | `/api/scan/journal?id=X` | Scan journal |
| GET | `/api/scan/stream?id=X` | SSE live stream |

## Discovery Lab

A Docker Compose lab is provided for testing patterns against real services:

```bash
docker compose -f docker-compose.lab.yml up -d
liaprobe --mode smart 172.20.0.0/24
docker compose -f docker-compose.lab.yml down
```

## Development

```bash
make build      # Build binary
make test       # Run tests with race detector
make cover      # Generate coverage report
make vet        # Go vet
make lint       # golangci-lint
make release    # Cross-compile for 5 platforms
make clean      # Clean build artifacts
```

## Architecture

```
liaprobe/
  cmd/liaprobe/     CLI entry point
  api/              HTTP API server + SSE streaming
  pkg/
    agent/          OODA agentic loop (planner, executor, observer, replanner, journal, memory)
    ai/             AI provider abstraction (ollama, openai, liasec, multi-fallback, noop)
    config/         Configuration (YAML, env, profiles, validation)
    fingerprint/    Pattern-based service fingerprinting engine
    log/            Lightweight CLI logger
    output/         Output formatters (JSON, table)
    portdb/         Known ports and service hints
    scanner/        TCP scanner, alive checker, target expander
    store/          Result persistence (file, memory)
  patterns/lia/     Fingerprint pattern definitions (JSON)
  internal/version/ Build-time version injection
```

## License

MIT
