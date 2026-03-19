# LiaProbe - CLAUDE.md

> Scanner reseau agentique standalone. Projet isole du monolithe LIA-SEC.

**Projet:** LiaProbe - Intelligent Agentic Network Scanner
**Maintainer:** mo0ogly@proton.me
**Base:** `/opt/lia-sec/liaprobe/`
**Stack:** Go 1.25.1, pure Go, zero CGO, zero nmap
**Repo:** Standalone git repo (separe de LIA-SEC)

---

## Contexte : Isolation du monolithe LIA-SEC

LiaProbe etait initialement dans `/opt/lia-sec/dev/liaprobe/`. Il a ete deplace le 2026-03-19 vers `/opt/lia-sec/liaprobe/` pour les raisons suivantes :

1. **Hooks parasites** : Les hooks Claude Code du projet parent (`dev/.claude/hooks/`) bloquaient le dev LiaProbe :
   - `security_check.sh` : bloquait `fmt.Sprintf` (regex `fmt\.Print`), URLs hardcodees (endpoints AI normaux ici)
   - `enforce_cleanup_services.sh` : bloquait `go build` direct (forcait `build_secure_lia.sh`)
   - `check_build_list.sh` : verifiait presence dans la whitelist du monolithe
2. **Regles incompatibles** : LiaProbe est un outil CLI standalone open-source, pas un monolithe 560+ routes avec PostgreSQL/React
3. **Git propre** : Son propre repo git, son propre `.claude/`, ses propres regles

### Layout VPS actuel

```
/opt/lia-sec/
├── source/      # PROD LIA-SEC (servi par nginx + systemd)
├── dev/         # DEV MIRROR LIA-SEC (Claude Code, hooks LIA-SEC)
├── liaprobe/    # STANDALONE LiaProbe (isole, son propre git)
├── backups/     # Backups PostgreSQL
└── n8n/         # n8n Docker
```

### Relation avec LIA-SEC

LiaProbe peut fonctionner de 2 facons :
- **CLI standalone** : `liaprobe --ai groq 192.168.1.0/24` (open-source, communaute)
- **API mode** : `liaprobe --serve --api-port 8082` (appele par le backend LIA-SEC)

Le backend LIA-SEC (`/opt/lia-sec/source/cmd/sigma_web/`) appelle LiaProbe via son API REST.
LiaProbe n'a AUCUNE dependance vers LIA-SEC (pas d'import, pas de config partagee).

---

## Architecture

```
liaprobe/
├── cmd/liaprobe/        # CLI entry point, flag parsing, provider factory
├── api/                 # HTTP API server + SSE streaming
├── pkg/
│   ├── agent/           # Boucle OODA (planner, executor, observer, replanner, journal, memory)
│   ├── ai/              # Abstraction AI (ollama, openai, anthropic, liasec, multi, noop)
│   ├── config/          # Configuration (YAML, env, profiles, validation)
│   ├── fingerprint/     # Moteur fingerprinting par patterns (35 patterns)
│   ├── log/             # Logger CLI leger
│   ├── output/          # Formateurs sortie (JSON, table)
│   ├── portdb/          # Ports connus et hints services
│   ├── scanner/         # TCP scanner, alive checker, target expander
│   └── store/           # Persistence resultats (file, memory)
├── patterns/lia/        # Definitions patterns fingerprint (JSON)
├── internal/version/    # Injection version build-time
└── docker-compose.lab.yml  # Lab Docker 14 services pour tests
```

## Boucle OODA Agentique

```
Goal -> Plan -> [Execute -> Observe -> Replan?] -> Report
```

Le plan est une liste ordonnee de taches avec dependances :
1. `t1-expand` : Expansion cibles (CIDR -> IPs, hostname -> IP)
2. `t2-alive` : Detection hotes vivants (TCP RST = alive)
3. `t3-portscan` : Scan ports TCP
4. `t4-banner` : Capture banners
5. `t5-fingerprint` : Identification services par patterns
6. `t6-context-expand` : Expansion contextuelle (mode smart)
7. `t7-ai-analyze` : Analyse IA globale
8. `t8-report` : Generation rapport

**Replan dynamique** : Si des banners inconnus sont detectes et l'IA est disponible, le replanner ajoute une tache `t-ai-banner-rN` pour identification par IA.

---

## Build et Test

```bash
# Build
make build
# ou directement :
go build -mod=mod -o bin/liaprobe ./cmd/liaprobe/

# Test
make test

# Lab Docker (14 services)
docker compose -f docker-compose.lab.yml up -d
./bin/liaprobe --mode smart --output table 172.20.0.0/24
docker compose -f docker-compose.lab.yml down
```

**PAS de `build_secure_lia.sh`** -- c'est un outil LIA-SEC, pas LiaProbe.
**PAS de `cleanup_services.sh`** -- LiaProbe est un binaire CLI, pas un service systemd.

---

## Providers IA

| Provider | Flag CLI | Env var auto-detectee | Modele par defaut |
|----------|----------|----------------------|-------------------|
| Ollama | `--ai ollama` | - | (local) |
| Groq | `--ai groq` | `GROQ_API_KEY` | llama-3.3-70b-versatile |
| OpenAI | `--ai openai` | `OPENAI_API_KEY` | gpt-4o |
| Anthropic | `--ai anthropic` ou `--ai claude` | `ANTHROPIC_API_KEY` | claude-sonnet-4-20250514 |
| Custom | `--ai custom --ai-endpoint URL` | `--ai-key` | - |
| LIA-SEC | `--ai liasec` (API mode) | - | UniversalAIManager |
| Noop | `--no-ai` | - | - |

En mode standalone, les API keys sont resolues dans cet ordre :
1. `--ai-key` (flag CLI)
2. Variable d'environnement (`GROQ_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`)

---

## Conventions specifiques LiaProbe

- **`fmt.Sprintf` autorise** : Pas de restriction sur `fmt` (contrairement au monolithe LIA-SEC)
- **`go build` direct** : Pas de whitelist de fichiers
- **Pas de PostgreSQL** : Tout est fichier ou memoire
- **Pas de JWT/fetchWithConfig** : Pas de frontend React
- **Logger leger** : `pkg/log/` avec `log.Info()`, `log.Error()`, `log.Debug()`, pas `LogSystemEvent()`
- **Journal non desactivable** : Tracabilite OODA dans `.liaprobe/journals/` (JSONL)

---

## Discovery Lab

14 services Docker sur le reseau `172.20.0.0/24` :

| Service | IP | Port(s) |
|---------|-----|---------|
| Nginx | 172.20.0.10 | 80 |
| Apache | 172.20.0.11 | 80 |
| MySQL | 172.20.0.20 | 3306 |
| PostgreSQL | 172.20.0.21 | 5432 |
| Redis | 172.20.0.22 | 6379 |
| MongoDB | 172.20.0.23 | 27017 |
| Elasticsearch | 172.20.0.24 | 9200, 9300 |
| RabbitMQ | 172.20.0.30 | 5672, 15672 |
| Grafana | 172.20.0.31 | 3000 |
| Prometheus | 172.20.0.32 | 9090 |
| Consul | 172.20.0.33 | 8500 |
| Gitea | 172.20.0.40 | 3000, 22 |
| SonarQube | 172.20.0.41 | 9000 |
| Kibana | 172.20.0.42 | 5601 |
