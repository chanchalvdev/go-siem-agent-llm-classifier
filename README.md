# Go SIEM Agent — LLM Classifier

An open-source AI security operations platform built in Go. It ingests security logs, classifies and triages them with an LLM, maps them to MITRE ATT&CK, and investigates high-severity events with an autonomous agent — with a responsive React dashboard for semantic search and analytics.

Where it is heading — detection rules, incident correlation, automated response and integrations — is in the **[roadmap](ROADMAP.md)**. Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).

[![CI](https://github.com/chanchalvdev/go-siem-agent-llm-classifier/actions/workflows/ci.yml/badge.svg)](https://github.com/chanchalvdev/go-siem-agent-llm-classifier/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-MIT-blue)
![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)
![React](https://img.shields.io/badge/React-19-61DAFB?logo=react)
![Tailwind](https://img.shields.io/badge/Tailwind-CSS-38BDF8?logo=tailwindcss)

---

## Try it in one command

You need Docker. No API key, no setup:

```bash
git clone https://github.com/chanchalvdev/go-siem-agent-llm-classifier.git
cd go-siem-agent-llm-classifier
make demo        # or: docker compose -f siemagent/demo/compose.yml up -d --build --wait
```

Open **http://localhost:3000** and sign in as `admin` / `siemagent-demo`. A
prepared attack (SSH brute force → root shell, a port scan, ransomware deleting
shadow copies) is replayed on first start, so there are already three incidents,
a kill chain and response actions waiting for approval. Approve the IP block and
watch it arrive at the stand-in firewall: `docker compose -f siemagent/demo/compose.yml logs webhook`.

The demo runs **rules-only** (`LLM_PROVIDER=none`). For AI classification and
investigations, start it with a key: `LLM_PROVIDER=gemini GEMINI_API_KEY=... make demo`.
Stop with `make demo-down`. Demo only: fixed password, no TLS.

---

## What It Does

Send logs over syslog, paste or upload them (syslog, nginx, auth.log, Windows Event, etc.) and the agent:

1. **Parses** the raw log into structured fields (host, app, timestamp, message)
2. **Detects** known attacks with Sigma rules — instantly, with no LLM call
3. **Classifies** everything else via LLM — attack type, severity (P1–P5), confidence score
3. **Maps** to MITRE ATT&CK tactic + technique (e.g. T1110 Brute Force)
4. **Extracts IOCs** — IPs, domains, file hashes with VirusTotal / AbuseIPDB links
5. **Generates remediation** steps tailored to the specific threat
6. **Stores** a vector embedding in Qdrant for semantic similarity search
7. **Investigates** high-severity events with an autonomous LLM agent that calls threat-intel tools (MITRE, AbuseIPDB, OTX, similar-event recall)
8. **Streams** live incidents to the dashboard over WebSocket — global alert ticker + incident detail overlay
9. **Persists** every classified event to PostgreSQL so history survives restarts
10. **Displays** everything in a real-time responsive dashboard

---

## Features

**Detect**
- **Sigma detection rules**: a built-in rule pack plus any Sigma rules you add (e.g. SigmaHQ); rule matches skip the LLM, cutting cost and latency ([docs/DETECTION.md](docs/DETECTION.md))
- **Threshold rules**: `count() by src_ip >= 10` over a time window catches brute force, password spraying, web scans and port scans
- **Rule management**: enable or disable rules from the dashboard, with hit counts
- **IOC watchlists**: known-bad IPs, ranges, domains and hashes from threat feeds, files or analysts raise matching events instantly ([docs/WATCHLISTS.md](docs/WATCHLISTS.md))
- **AI classification**: Gemini, a fully local model via Ollama, or any OpenAI-compatible API, with structured JSON output
- **MITRE ATT&CK mapping and severity triage**: tactic, technique and P1 Critical → P5 Info for every event

**Investigate**
- **Incidents and case management**: related alerts grouped by IP, user or host, with status, assignee, resolution, comments, a kill-chain view and a full timeline ([docs/INCIDENTS.md](docs/INCIDENTS.md))
- **AI investigation of whole incidents**: tool-calling agent (AbuseIPDB, OTX, MITRE, similar events) writes a cited report, once per P1/P2 incident or on demand; analysts rate it
- **Incident reports**: self-contained Markdown export
- **SOC metrics**: MTTD, MTTA and MTTR (median, mean, p90), alert and incident volume, false-positive rate, backlog ageing and analyst workload
- **Suppressions**: snooze a noisy IP, user, host, rule or attack type for a while; matching events are kept but open no incident
- **Semantic search**: vector embeddings via Ollama + Qdrant to find similar past events
- **Live stream**: `/ws/alerts` WebSocket shows investigations as they run

**Respond**
- **Response playbooks**: YAML playbooks propose block IP, disable user, isolate host, notify or webhook actions; analysts approve or reject; dry-run mode; audited ([docs/RESPONSE.md](docs/RESPONSE.md))

**Operate**
- **Users, roles and audit log**: viewer / analyst / admin, bcrypt passwords, sessions, lockout, every change audited ([docs/USERS.md](docs/USERS.md)); API keys for machines
- **Syslog ingestion**: UDP/TCP listener with back-pressure and drop metrics; batch upload of `.log` files
- **Durable storage**: PostgreSQL, with an in-memory fallback for quick local runs
- **Prometheus metrics** at `/metrics`, **Swagger UI** at `/docs`
- **Dashboard**: responsive, light and dark themes meeting WCAG AA contrast

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Go 1.25, Chi router |
| LLM Provider | Gemini (default), Ollama (local), or any OpenAI-compatible API |
| LLM Model | `gemini-3.8-flash` / `llama3.2` (configurable) |
| Vector DB | Qdrant (gRPC) |
| Embeddings | Ollama — `nomic-embed-text` (768-dim) |
| Database | PostgreSQL 16 |
| Metrics | Prometheus |
| Frontend | React 19, TypeScript, Vite, Tailwind CSS, Recharts |
| Infrastructure | Docker Compose |

---

## Architecture

```
 syslog / HTTP / upload
          │
          ▼
 ┌──────────────────────────────── SIEMAgent (Go :8080) ─────────────────────────────────┐
 │ auth (API key · session · roles · CSRF · audit)                                        │
 │   → parse (RFC 5424 / 3164 / JSON)                                                     │
 │   → detect (Sigma + threshold rules; a match skips the LLM)                            │
 │   → classify (LLM: Gemini / Ollama / OpenAI-compatible; MITRE, severity, IOCs)          │
 │   → store (events)                                                                     │
 │   → correlate into incidents (shared IP / user / host within a window)                 │
 │       ├─ investigate (AI agent on the whole incident, once per P1/P2 incident)         │
 │       └─ respond (playbooks propose block IP / disable user / isolate host / notify;   │
 │                   an analyst approves → RESPONSE_WEBHOOK_URL / Slack)                  │
 └───────┬──────────────────────┬──────────────────────┬──────────────────────┬───────────┘
         ▼                      ▼                      ▼                      ▼
   PostgreSQL              Qdrant + Ollama           LLM               React dashboard :5173
   events, incidents,      embeddings,                                 Events · Incidents · Response
   actions, users, audit   similar events                              Analytics · Rules · Users · Audit
```

The full end-to-end flow, with diagrams, is in
**[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**. To try every feature with a
prepared attack scenario, follow **[docs/TESTING.md](docs/TESTING.md)**.

---

## Project Structure

```
go-siem-agent-llm-classifier/
├── siemagent/
│   ├── cmd/siemagent/        # Main entrypoint (CLI + HTTP server)
│   ├── internal/
│   │   ├── agent/            # LLM tool-calling agent + tools (MITRE, AbuseIPDB, OTX, similar events)
│   │   ├── api/              # HTTP handlers, router, auth/roles/CSRF/audit middleware, WS hub
│   │   ├── auth/             # Users, roles, sessions, audit log
│   │   ├── classifier/       # LLM-based event classifier
│   │   ├── config/           # Environment config loader + provider selection
│   │   ├── detection/        # Sigma + threshold rule engine, built-in rules (rules/*.yml)
│   │   ├── incident/         # Alert correlation, case management, reports, AI briefs
│   │   ├── metrics/          # Prometheus metrics
│   │   ├── mitre/            # Offline MITRE ATT&CK subset
│   │   ├── ingest/           # Syslog UDP/TCP listener
│   │   ├── logsafe/          # Strips control characters from untrusted log fields
│   │   ├── models/           # Shared data models
│   │   ├── parser/           # Syslog & JSON log parsers
│   │   ├── pipeline/         # Concurrent worker pool
│   │   ├── response/         # Playbooks, proposed actions, approvals, webhook/Slack executor
│   │   └── store/            # Event store and rule states: PostgreSQL + in-memory fallback
│   ├── pkg/
│   │   ├── ollama/           # Ollama embeddings client
│   │   └── qdrant/           # Qdrant vector DB client + adapter
│   ├── web/                  # React frontend
│   │   ├── e2e/              # Playwright end-to-end tests
│   │   └── src/
│   │       ├── auth/         # Sign-in gate and role context
│   │       ├── components/   # EventCard, IncidentDetail, KillChain, ActionCard, AlertTicker…
│   │       ├── hooks/        # useAlertStream, useActionDecisions
│   │       ├── lib/          # API client (fetch + SSE), shared labels
│   │       ├── pages/        # Dashboard, Incidents, Response, Rules, Users, Audit, Docs, Search
│   │       └── __tests__/    # Vitest + Testing Library unit tests
│   ├── docker-compose.yml    # Qdrant + Postgres + Ollama
│   ├── Makefile              # Dev commands
│   ├── demo/attack-scenario.log  # Brute force, port scan and ransomware story (docs/TESTING.md)
│   ├── sample.log            # Sample log file for CLI mode
│   └── test-logs.txt         # 30-line test file for UI upload
├── docs/                     # ARCHITECTURE, TESTING, DETECTION, INCIDENTS, RESPONSE, USERS, BRANCHING…
├── specs/                    # Feature specs
├── ROADMAP.md                # Platform roadmap
└── README.md
```

---

## Quick Start

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Go | 1.25+ | Backend |
| Node.js | 18+ | Frontend |
| Docker + Compose | Latest | Qdrant, Postgres, Ollama |
| LLM | — | A Gemini API key, or Ollama for a fully local model |

### 1. Clone

```bash
git clone https://github.com/chanchalvdev/go-siem-agent-llm-classifier.git
cd go-siem-agent-llm-classifier/siemagent
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and choose an LLM — either a Gemini key:

```env
GEMINI_API_KEY=your_key_here
```

or a fully local model with no key (logs never leave your machine):

```env
LLM_PROVIDER=ollama
OLLAMA_MODEL=llama3.2
```

> Get a Gemini key at [aistudio.google.com/apikey](https://aistudio.google.com/apikey). Any OpenAI-compatible provider also works — see `.env.example`.

### 3. Install dependencies

```bash
make setup
```

### 4. Start Docker services

```bash
make docker-up
```

Starts Qdrant (vector DB), PostgreSQL, and Ollama in the background.

> **Note:** If port 5432 is already in use locally, the Postgres container is mapped to `5433` by default.

### 5. Pull Ollama embedding model

```bash
make pull-models
```

Downloads `nomic-embed-text` (~274 MB, required for semantic search) and `llama3.2` (used when `LLM_PROVIDER=ollama`).

### 6. Build the backend

```bash
make build
```

### 7. Start the backend

```bash
make serve
```

Server starts at `http://localhost:8080`. You should see:

```
INFO  LLM provider configured  provider=gemini model=gemini-3.8-flash
INFO  Qdrant connected, semantic search enabled
INFO  events persisted to Postgres
INFO  SIEMAgent HTTP server starting  addr=:8080
```

### 8. Start the frontend

```bash
cd web && npm run dev
```

Dashboard available at **http://localhost:5173**

---

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `LLM_PROVIDER` | `gemini`, `ollama`, `openai` (OpenAI-compatible) or `none` (rules only, no AI) | auto: `gemini` if `GEMINI_API_KEY` is set |
| `GEMINI_API_KEY` | Gemini API key | — |
| `GEMINI_MODEL` | Gemini model | `gemini-3.8-flash` |
| `OLLAMA_MODEL` | Local chat model when `LLM_PROVIDER=ollama` | `llama3.2` |
| `KIMCHI_API_KEY` / `OPENAI_API_KEY` | Key for an OpenAI-compatible endpoint | — |
| `KIMCHI_BASE_URL` | OpenAI-compatible base URL | `https://api.kimchi.ai/v1` |
| `SIEM_MODEL` | Model for the OpenAI-compatible endpoint | `kimi-k2-5` |
| `SIEM_API_KEYS` | Comma-separated API keys for machine access (admin role) | — |
| `SIEM_ADMIN_USER` / `SIEM_ADMIN_PASSWORD` | Creates the first dashboard admin when no user exists ([docs/USERS.md](docs/USERS.md)) | — |
| `SIEM_SESSION_TTL` / `SIEM_COOKIE_SECURE` | Login lifetime; Secure cookie behind HTTPS | `12h` / `false` |
| `INCIDENT_WINDOW` / `INCIDENT_MIN_SEVERITY` | Alert correlation window and threshold ([docs/INCIDENTS.md](docs/INCIDENTS.md)) | `1h` / `P3` |
| `PLAYBOOKS_DIR` | Extra response playbooks ([docs/RESPONSE.md](docs/RESPONSE.md)) | — |
| `RESPONSE_WEBHOOK_URL` / `SLACK_WEBHOOK_URL` | Where approved containment actions and notifications go | — |
| `RETENTION_EVENTS_DAYS` / `RETENTION_INCIDENTS_DAYS` / `RETENTION_AUDIT_DAYS` | Days to keep events, resolved incidents and audit entries (Postgres only); `0` keeps forever | `0` |
| `POSTGRES_DSN` | Postgres connection string; empty keeps events in memory | see `.env.example` |
| `DETECTION_MODE` | `rules-first`, `enrich` or `off` ([docs/DETECTION.md](docs/DETECTION.md)) | `rules-first` |
| `SIGMA_RULES_DIR` | Extra Sigma rules folder, searched recursively | — |
| `SYSLOG_UDP_ADDR` / `SYSLOG_TCP_ADDR` | Syslog listener addresses, e.g. `:5514` | disabled |
| `IOC_WATCHLIST_DIR` | Directory of read-only IOC list files ([docs/WATCHLISTS.md](docs/WATCHLISTS.md)) | — |
| `SEED_LOG_FILE` | Log file replayed through the pipeline on first start, when no events are stored (demos) | — |
| `CONDUCTOR_PORT` | HTTP server port | `8080` |
| `ALLOWED_ORIGIN` | CORS origin | `http://localhost:5173` |
| `QDRANT_ADDR` | Qdrant gRPC address | `localhost:6334` |
| `OLLAMA_URL` | Ollama base URL (embeddings, local LLM) | `http://localhost:11434` |
| `ABUSEIPDB_KEY` | AbuseIPDB API key for the agent's IP-reputation tool | optional |
| `OTX_API_KEY` | AlienVault OTX API key for the agent's threat-intel tool | optional |

Dashboard (in `siemagent/web/.env.local`): `VITE_SIEM_API_KEY` — the key the dashboard sends when `SIEM_API_KEYS` is set.

---

## Sending Logs over Syslog

Enable the listener in `.env`:

```env
SYSLOG_UDP_ADDR=:5514
SYSLOG_TCP_ADDR=:5514
```

Point rsyslog at it (`/etc/rsyslog.d/90-siemagent.conf`):

```
*.* @siemagent-host:5514      # UDP
*.* @@siemagent-host:5514     # TCP (newline-framed)
```

Or test by hand:

```bash
logger -n 127.0.0.1 -P 5514 -d "Failed password for root from 203.0.113.9 port 22 ssh2"
```

Each line is parsed (RFC 5424, RFC 3164 with or without `<PRI>` as written to `/var/log/auth.log`, or rsyslog's RFC 3339 "high-precision" format, falling back to raw text), queued and classified by the worker pool. When the queue is full, lines are dropped rather than slowing senders down; watch `ingest_dropped_total` in `/metrics`.

---

## Authentication

Three ways to authenticate (details in [docs/USERS.md](docs/USERS.md)):

- **User accounts**: set `SIEM_ADMIN_USER` and `SIEM_ADMIN_PASSWORD` to create
  the first admin, then sign in to the dashboard and add users as **viewer**,
  **analyst** or **admin**. Sessions use an `HttpOnly`, `SameSite=Strict`
  cookie; every change is written to the audit log.
- **API keys** for scripts and integrations: set `SIEM_API_KEYS`
  (comma-separated, so keys can be rotated). A key acts as an admin:

  ```bash
  curl -H "Authorization: Bearer $KEY" http://localhost:8080/api/events
  curl -H "X-API-Key: $KEY"            http://localhost:8080/api/events
  ```

  Browsers cannot set headers on a WebSocket handshake, so `/ws/alerts` also
  accepts `?api_key=<key>` (plain HTTP requests do not).
- **Open mode**: with neither configured, everything is allowed. For local
  development only; the server warns at start.

`/health`, `/health/ready`, `/docs` and `/api/auth/login` are always public.
See [SECURITY.md](SECURITY.md) for deployment advice.

---

## API Reference

All examples assume auth is off; add `-H "X-API-Key: $KEY"` when `SIEM_API_KEYS` is set.

### `POST /api/classify`

Classify a single log line.

```bash
curl -X POST http://localhost:8080/api/classify \
  -H "Content-Type: application/json" \
  -d '{"log": "Failed password for root from 192.168.1.100 port 22", "format": "auto"}'
```

**Response:**
```json
{
  "event": { "raw": "...", "hostname": "webserver01", "source": "syslog" },
  "attack_type": "Brute Force",
  "severity": "P3",
  "confidence": 0.90,
  "mitre": { "tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force" },
  "iocs": ["192.168.1.100", "root"],
  "summary": "Failed SSH login attempt for root from 192.168.1.100",
  "remediation": "Block IP, enforce key-based auth, disable root login"
}
```

### `POST /api/classify/stream`

Same as `/classify` but streams LLM tokens via SSE.

### `POST /api/ingest`

Batch classify up to 500 log lines and store in Qdrant + Postgres.

```bash
curl -X POST http://localhost:8080/api/ingest \
  -H "Content-Type: application/json" \
  -d '{"logs": ["log line 1", "log line 2"], "format": "auto"}'
```

### `GET /api/events?limit=100`

Most recent stored events, newest first (`limit` 1–500, default 100). With Postgres this includes history from before the last restart.

### `GET /api/detections/rules`

Loaded Sigma rules with level, tags, source, type (`single` or `threshold`),
enabled state and match count since start.

### `PATCH /api/detections/rules/{id}`

Enable or disable a rule: `{"enabled": false}`. Saved in Postgres, so it
survives restarts.

### Incidents

Related alerts are grouped into incidents with status, assignee, comments and
history. See [docs/INCIDENTS.md](docs/INCIDENTS.md).

- `GET /api/incidents?status=open&entity=ip:1.2.3.4`
- `GET /api/incidents/stats`
- `GET /api/soc/metrics?days=30`: MTTD/MTTA/MTTR, volume, workload ([docs/INCIDENTS.md](docs/INCIDENTS.md#soc-metrics))
- `GET /api/incidents/{id}`
- `PATCH /api/incidents/{id}` with `{"status","assignee","severity","resolution"}`
- `POST /api/incidents/{id}/comments` with `{"body": "..."}`
- `POST /api/incidents/{id}/investigate`: AI investigation of the whole incident
- `GET /api/incidents/{id}/report`: Markdown incident report
- `POST /api/incidents/{id}/feedback` with `{"helpful": true}`
- `GET /api/watchlists` · `GET /api/ioc/lookup?value=`: IOC watchlists ([docs/WATCHLISTS.md](docs/WATCHLISTS.md))
- `GET /api/suppressions` · `POST /api/suppressions` · `DELETE /api/suppressions/{id}`: snooze noisy alerts

### Users and audit

See [docs/USERS.md](docs/USERS.md): `POST /api/auth/login`, `GET /api/auth/me`,
`/api/users` (admin) and `GET /api/audit` (admin).

### Response playbooks

Playbooks propose actions (block IP, disable user, isolate host, notify) that
analysts approve. See [docs/RESPONSE.md](docs/RESPONSE.md).

- `GET /api/playbooks`
- `GET /api/response/actions?status=pending`
- `POST /api/response/actions/{id}/approve` · `POST /api/response/actions/{id}/reject`
- `POST /api/incidents/{id}/playbooks/{playbook}/run`

### `GET /api/search?q=brute+force&limit=10`

Semantic vector search over stored events.

### `GET /api/analytics/summary`

Returns attack type counts, severity distribution, 6h timeline, and MITRE tactic breakdown.

### `GET /ws/alerts`

WebSocket endpoint streaming live incident/agent events (JSON frames). Each frame
is a sanitized `AgentEvent` — the UI reduces these into incident cards shown in the
alert ticker and incident overlay.

```bash
websocat ws://localhost:8080/ws/alerts
```

### `GET /health`

```json
{"status": "ok"}
```

### `GET /health/ready`

Checks the LLM, Postgres (when configured) and Qdrant; returns 503 if any is down.

### `GET /docs`

Interactive Swagger UI.

### `GET /metrics`

Prometheus metrics endpoint.

---

## Using the Dashboard

### Classify a log manually

Paste any log line in the input bar and press **Enter** or click **Classify**:

```
Failed password for root from 45.33.32.156 port 22
vssadmin.exe delete shadows /all /quiet
GET /etc/passwd HTTP/1.1 200
sudo: hacker USER=root COMMAND=/bin/bash
```

### Upload a log file

Click **Upload** and select any `.log` or `.txt` file. The UI classifies all lines in parallel batches and shows a progress bar.

A ready-made test file with 30 mixed-severity events is included:

```
siemagent/test-logs.txt
```

### Severity filter

Use the sidebar checkboxes to filter events by P1–P5. Event counts per severity are shown live.

### Event detail

Click any event card to open the detail panel showing:
- Severity badge + confidence bar
- MITRE ATT&CK tactic + technique (links to attack.mitre.org)
- IOCs with VirusTotal / AbuseIPDB links
- Remediation steps (collapsible)
- Raw log
- Similar past events (semantic search)

### Analytics

Switch to the **Analytics** tab (mobile) or view the right panel (desktop) for:
- Critical / High event counters
- Attack type bar chart (color-coded by severity)
- Event rate timeline (6h, 10-min buckets)
- MITRE ATT&CK tactic pie chart
- MITRE heatmap and threat intel panel

### Live incidents

When the agent investigates a high-severity event, its progress streams in over
`/ws/alerts` and appears in the **alert ticker** at the top of the app. Click a
ticker entry to open the **incident overlay** — tool calls, findings, and the
final verdict update live as the agent works.

---

## CLI Mode

Classify a log file directly from the terminal without starting the HTTP server:

```bash
./bin/siemagent sample.log
```

Output results to JSON:

```bash
./bin/siemagent --output results.json sample.log
```

---

## Development

```bash
make dev          # Go backend (air hot-reload) + Vite frontend in parallel
make test         # Run all unit tests with race detector
make vet          # go vet
make lint         # golangci-lint
make seed         # POST 10 sample syslog events to /classify
make docker-down  # Stop all Docker services
make clean        # Remove build artifacts
```

### Run everything in containers

```bash
cd siemagent
docker compose --profile app up -d --build
# Dashboard: http://localhost:3000   API: http://localhost:8080
```

Released images are published to GHCR as `ghcr.io/chanchalvdev/siemagent-api`
and `ghcr.io/chanchalvdev/siemagent-web`, with binaries for Linux and macOS on
the [releases page](https://github.com/chanchalvdev/go-siem-agent-llm-classifier/releases).
How branches, pull requests and releases work is described in
[docs/BRANCHING.md](docs/BRANCHING.md).

---

## Responsive Design

The dashboard is fully responsive:

| Breakpoint | Layout |
|---|---|
| Mobile (< 768px) | Hamburger sidebar, tab bar (Events / Analytics), bottom-sheet event detail |
| Tablet (768–1280px) | Collapsible sidebar, full event list, detail panel as overlay |
| Desktop (> 1280px) | Three-column layout — sidebar + events + detail/analytics panel |

---

## Running Tests

```bash
cd siemagent
make test                  # Go unit tests (with -race)
make test-integration      # Integration tests (requires Qdrant running)

# or, from the repository root, exactly what CI runs:
make quality-gate

cd web
npx vitest run             # Frontend unit tests (Vitest + Testing Library)
npx playwright test        # End-to-end tests (requires backend running)
```

---

## Contributing

Bug reports, detection content, parsers and integrations are all welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) to get set up, and check the [roadmap](ROADMAP.md) for where help is most useful. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © [ChanchalS7](https://github.com/ChanchalS7)
