# Go SIEM Agent — LLM Classifier

A production-ready Security Information and Event Management (SIEM) agent built in Go that uses LLM-based AI to classify, triage, and investigate security log events in real time. Features a fully responsive React dashboard with semantic search, analytics, and MITRE ATT&CK mapping.

![License](https://img.shields.io/badge/license-MIT-blue)
![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)
![React](https://img.shields.io/badge/React-19-61DAFB?logo=react)
![Tailwind](https://img.shields.io/badge/Tailwind-CSS-38BDF8?logo=tailwindcss)

---

## What It Does

Paste or upload any log line (syslog, nginx, auth.log, Windows Event, etc.) and the agent:

1. **Parses** the raw log into structured fields (host, app, timestamp, message)
2. **Classifies** it via LLM — determines attack type, severity (P1–P5), confidence score
3. **Maps** to MITRE ATT&CK tactic + technique (e.g. T1110 Brute Force)
4. **Extracts IOCs** — IPs, domains, file hashes with VirusTotal / AbuseIPDB links
5. **Generates remediation** steps tailored to the specific threat
6. **Stores** a vector embedding in Qdrant for semantic similarity search
7. **Investigates** high-severity events with an autonomous LLM agent that calls threat-intel tools (MITRE, AbuseIPDB, OTX, similar-event recall)
8. **Streams** live incidents to the dashboard over WebSocket — global alert ticker + incident detail overlay
9. **Displays** everything in a real-time responsive dashboard

---

## Features

- **AI classification** — OpenAI-compatible LLM (default: Kimchi / minimax-m3) with structured JSON output
- **MITRE ATT&CK mapping** — tactic, technique ID, and technique name for every event
- **Severity triage** — P1 Critical → P5 Info with visual indicators and pulse animation on P1
- **Semantic search** — vector embeddings via Ollama + Qdrant to find similar past events
- **IOC enrichment** — auto-detects IPs, hashes, domains and links to threat intel platforms
- **Batch ingestion** — drag-and-drop `.log` / `.txt` files, classifies up to 500 lines
- **Streaming classify** — SSE endpoint streams LLM response token-by-token
- **Analytics dashboard** — attack type bar chart, event rate timeline, MITRE tactic pie chart
- **Agent investigation (Phase 3)** — tool-calling LLM loop: MITRE lookup, AbuseIPDB IP reputation, AlienVault OTX intel, Qdrant similar-event recall, final verdict synthesis
- **Live incident stream** — `/ws/alerts` WebSocket hub broadcasts sanitized agent progress; alert ticker + incident overlay in the UI
- **MITRE heatmap & threat intel panel** — tactic/technique heat view and enriched intel summaries
- **Prometheus metrics** — `/metrics` endpoint for Grafana integration
- **Swagger UI** — interactive API docs at `/docs`
- **Fully responsive** — works on mobile, tablet, and desktop

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Go 1.25, Chi router |
| LLM Provider | Kimchi (`llm.kimchi.dev`) — any OpenAI-compatible API |
| LLM Model | minimax-m3 (configurable) |
| Vector DB | Qdrant (gRPC) |
| Embeddings | Ollama — `nomic-embed-text` (768-dim) |
| Database | PostgreSQL 16 |
| Metrics | Prometheus |
| Frontend | React 19, TypeScript, Vite, Tailwind CSS, Recharts |
| Infrastructure | Docker Compose |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    React Dashboard                       │
│         (Vite dev :5173 → proxies /api → :8080)        │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTP / SSE / WebSocket
┌───────────────────────▼─────────────────────────────────┐
│                   Go HTTP Server :8080                   │
│   Chi router · Rate limiter · CORS · Security headers   │
│                                                         │
│  POST /api/classify      → LLM classify single log      │
│  POST /api/classify/stream → SSE streaming classify     │
│  POST /api/ingest        → Batch classify + store       │
│  GET  /api/search        → Semantic vector search       │
│  GET  /api/analytics/summary → Charts data              │
│  GET  /ws/alerts         → Live incident WebSocket      │
│  GET  /metrics           → Prometheus                   │
│  GET  /docs              → Swagger UI                   │
│                                                         │
│  Agent (Phase 3): LLM tool loop → sanitize → WS hub     │
│    tools: MITRE · AbuseIPDB · OTX · similar events      │
└───┬───────────────┬─────────────────┬───────────────────┘
    │               │                 │
    ▼               ▼                 ▼
┌───────┐    ┌──────────┐    ┌──────────────┐
│Kimchi │    │  Qdrant  │    │    Ollama    │
│  LLM  │    │ Vector DB│    │  Embeddings  │
│  API  │    │  :6334   │    │   :11434     │
└───────┘    └──────────┘    └──────────────┘
```

> For a guided walkthrough of the codebase see
> [IMPLEMENTATION_TRACE_HIGH_LEVEL.md](IMPLEMENTATION_TRACE_HIGH_LEVEL.md) (architecture & flows)
> and [IMPLEMENTATION_TRACE_LOW_LEVEL.md](IMPLEMENTATION_TRACE_LOW_LEVEL.md) (file/line trace).

---

## Project Structure

```
go-siem-agent-llm-classifier/
├── siemagent/
│   ├── cmd/siemagent/        # Main entrypoint (CLI + HTTP server)
│   ├── internal/
│   │   ├── agent/            # LLM tool-calling agent + tools (MITRE, AbuseIPDB, OTX, similar events)
│   │   ├── api/              # HTTP handlers, router, WS hub + sanitizer, middleware
│   │   ├── classifier/       # LLM-based event classifier
│   │   ├── config/           # Environment config loader
│   │   ├── metrics/          # Prometheus metrics
│   │   ├── models/           # Shared data models
│   │   ├── parser/           # Syslog & JSON log parsers
│   │   ├── pipeline/         # Concurrent worker pool
│   │   └── store/            # In-memory event store
│   ├── pkg/
│   │   ├── ollama/           # Ollama embeddings client
│   │   └── qdrant/           # Qdrant vector DB client + adapter
│   ├── web/                  # React frontend
│   │   ├── e2e/              # Playwright end-to-end tests
│   │   └── src/
│   │       ├── components/   # EventCard, AlertTicker, MITREHeatmap, ThreatIntelPanel…
│   │       ├── hooks/        # useAlertStream (WebSocket incident state)
│   │       ├── lib/          # API client (fetch + SSE)
│   │       ├── pages/        # Dashboard, Search, Docs, Incident
│   │       └── __tests__/    # Vitest + Testing Library unit tests
│   ├── docker-compose.yml    # Qdrant + Postgres + Ollama
│   ├── Makefile              # Dev commands
│   ├── sample.log            # Sample log file for CLI mode
│   └── test-logs.log         # 30-line test file for UI upload
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
| Kimchi API key | — | LLM inference at `llm.kimchi.dev` |

### 1. Clone

```bash
git clone https://github.com/ChanchalS7/go-siem-agent-llm-classifier.git
cd go-siem-agent-llm-classifier/siemagent
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env`:

```env
KIMCHI_API_KEY=your_key_here
KIMCHI_BASE_URL=https://llm.kimchi.dev/openai/v1
SIEM_MODEL=minimax-m3
CONDUCTOR_PORT=8080
ALLOWED_ORIGIN=http://localhost:5173
QDRANT_ADDR=localhost:6334
POSTGRES_DSN=postgres://siemagent:siemagent@localhost:5433/siemagent?sslmode=disable
OLLAMA_URL=http://localhost:11434
```

> Get a free API key at [app.kimchi.dev](https://app.kimchi.dev). Any OpenAI-compatible provider works — set `KIMCHI_BASE_URL` and `SIEM_MODEL` accordingly.

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

Downloads `nomic-embed-text` (~274 MB) — required for semantic search.

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
INFO  SIEMAgent HTTP server starting  addr=:8080
INFO  Qdrant connected, semantic search enabled
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
| `KIMCHI_API_KEY` | LLM provider API key | required |
| `KIMCHI_BASE_URL` | LLM base URL | `https://llm.kimchi.dev/openai/v1` |
| `SIEM_MODEL` | Model ID | `minimax-m3` |
| `CONDUCTOR_PORT` | HTTP server port | `8080` |
| `ALLOWED_ORIGIN` | CORS origin | `http://localhost:5173` |
| `QDRANT_ADDR` | Qdrant gRPC address | `localhost:6334` |
| `POSTGRES_DSN` | Postgres connection string | see `.env.example` |
| `OLLAMA_URL` | Ollama base URL | `http://localhost:11434` |
| `ABUSEIPDB_KEY` | AbuseIPDB API key for the agent's IP-reputation tool | optional |
| `OTX_API_KEY` | AlienVault OTX API key for the agent's threat-intel tool | optional |

---

## API Reference

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
siemagent/test-logs.log
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

### Build single binary with embedded frontend

```bash
make build-all
./bin/siemagent --serve --port 8080
# Visit http://localhost:8080 — no separate Vite server needed
```

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

cd web
npx vitest run             # Frontend unit tests (Vitest + Testing Library)
npx playwright test        # End-to-end tests (requires backend running)
```

---

## License

MIT © [ChanchalS7](https://github.com/ChanchalS7)
