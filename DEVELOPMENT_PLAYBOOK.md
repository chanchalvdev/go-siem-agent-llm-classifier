# SIEMAgent — Complete Development Playbook

Step-by-step feature prompts for every phase.  
Each prompt is ready to paste directly into Claude or your AI coding tool.

---

## Stack Reference

| Layer | Technology | Port |
|---|---|---|
| Backend API | Go 1.25 + Chi v5 | 8080 |
| LLM | Kimchi → kimi-k2.6 (OpenAI-compatible) | remote |
| Vector DB | Qdrant | 6334 |
| Embeddings | Ollama + nomic-embed-text | 11434 |
| Frontend | React 18 + TypeScript + Vite + Tailwind | 5173 |
| Database | PostgreSQL (Phase 3) | 5432 |
| Realtime | WebSocket via gorilla/websocket | ws://8080 |

---

## Development Environment Setup

**Prompt — Initial environment setup**
> I have the SIEMAgent Go project scaffolded at `./siemagent` with module name `siemagent`.
> Write a `docker-compose.yml` that starts Qdrant (port 6333/6334), PostgreSQL 16 (port 5432),
> and Ollama (port 11434) with a named volume for each. Include a `healthcheck` for each service.
> Also write a `scripts/pull-models.sh` bash script that calls `ollama pull nomic-embed-text`
> and `ollama pull llama3.2` after the Ollama container is healthy.

**Prompt — Makefile targets**
> Extend the existing `Makefile` in the SIEMAgent project with these targets:
> `make setup` (copies .env.example → .env, runs go mod download, npm install in web/),
> `make dev` (runs Go server with live-reload via `air` and Vite dev server in parallel),
> `make docker-up` / `make docker-down` (docker compose),
> `make seed` (sends 10 POST requests to /classify with sample syslog lines for smoke testing),
> `make build-all` (builds Go binary + React SPA into web/dist, embeds into binary with go:embed).

---

---

# PHASE 1 — Core Classifier

**Goal:** Parse syslog + JSON logs, classify with Kimchi LLM, serve via Chi API, display in a React dashboard.

---

## 1-A · Backend

---

### Feature: Graceful shutdown

**Prompt**
> In `cmd/siemagent/main.go` in the SIEMAgent Go project, add graceful shutdown to the HTTP server.
> Use `os/signal` to listen for SIGINT and SIGTERM. When a signal is received, call
> `srv.Shutdown(ctx)` with a 15-second timeout context. Log "shutting down" before and
> "shutdown complete" after. The server is created with `&http.Server{Addr: addr, Handler: srv}`.

---

### Feature: Middleware stack

**Prompt**
> In `internal/api/server.go`, configure the Chi middleware stack in this order:
> `middleware.RequestID`, `middleware.RealIP`, a custom `slog`-based structured request logger
> that emits `method`, `path`, `status`, `latency_ms`, and `request_id` fields,
> `middleware.Recoverer`, and a simple in-memory rate limiter that allows 100 req/s per IP
> using `golang.org/x/time/rate`. For the rate limiter, create a `map[string]*rate.Limiter`
> protected by a `sync.Mutex` and clean up entries older than 5 minutes in a background goroutine.

---

### Feature: Request validation

**Prompt**
> In `internal/api/server.go`, add input validation to the `POST /classify` handler.
> The `log` field is required and must not exceed 8192 bytes.
> The `format` field must be one of `syslog`, `json`, or `auto` (default `auto`).
> Return HTTP 400 with a JSON body `{"error": "...", "field": "..."}` for validation failures.
> Extract the validation logic into a separate `validateClassifyRequest` function.

---

### Feature: Health check with LLM probe

**Prompt**
> Create `internal/api/health.go` in the SIEMAgent project.
> The `GET /health` handler should return `{"status":"ok"}` with HTTP 200 in under 5ms.
> Add a second endpoint `GET /health/ready` that:
> (1) sends a minimal 1-token chat completion to the Kimchi endpoint using the classifier's
> client to verify the LLM is reachable,
> (2) checks that the Qdrant gRPC port is connectable with a 2-second dial timeout,
> (3) returns `{"status":"ready","checks":{"llm":"ok","qdrant":"ok"}}` or HTTP 503 if any check fails.
> Cache the result for 10 seconds to avoid hammering downstream services.

---

### Feature: Prometheus metrics

**Prompt**
> Add Prometheus metrics to the SIEMAgent Go API. Install `github.com/prometheus/client_golang`.
> Create `internal/metrics/metrics.go` that defines:
> `events_classified_total` counter (labels: severity, attack_type),
> `classification_duration_seconds` histogram (buckets: 0.1, 0.5, 1, 2, 5, 10),
> `llm_stream_errors_total` counter.
> Instrument the classifier in `internal/classifier/classifier.go` to record these.
> Register a `GET /metrics` route in the Chi server that serves the Prometheus text format.

---

### Feature: CLI progress display

**Prompt**
> In `cmd/siemagent/main.go`, improve the CLI mode (when reading a log file).
> After parsing, print a summary line: `Parsed N events (K syslog, J json, M errors)`.
> During classification, show a real-time progress bar using only the standard library:
> print `\r[■■■■□□□□] 4/10 classified — latest: P2 brute_force` updating in place on each result.
> At the end, print a summary table sorted by severity showing count per attack type.
> Use ANSI escape codes for P1=red, P2=orange, P3=yellow, P4=blue, P5=grey.

---

### Feature: /classify streaming response (SSE)

**Prompt**
> Add a `POST /classify/stream` endpoint to the SIEMAgent Chi server that returns a
> Server-Sent Events stream instead of waiting for the full classification.
> As each chunk arrives from the Kimchi streaming response, forward it to the HTTP response
> as `data: {"chunk":"..."}` SSE events. When the full JSON is assembled and parsed,
> send a final `data: {"result": {...ClassifiedEvent...}, "done": true}` event.
> Set `Content-Type: text/event-stream`, `Cache-Control: no-cache`, and flush after each event.

---

## 1-B · Frontend Setup

---

### Feature: React + TypeScript + Vite scaffold

**Prompt**
> Create a `web/` directory inside the SIEMAgent project root.
> Scaffold a React 18 + TypeScript + Vite project inside it using `npm create vite@latest`.
> Install and configure: Tailwind CSS v3, `@tanstack/react-query` v5, `axios`,
> `react-router-dom` v6, `lucide-react`, and `recharts`.
> In `vite.config.ts`, add a dev proxy that forwards `/api/**` and `/ws/**` to `http://localhost:8080`.
> Add a `"dev"` script to `web/package.json` that runs on port 5173.

---

### Feature: API client

**Prompt**
> Create `web/src/lib/api.ts` in the SIEMAgent frontend.
> Define TypeScript interfaces that exactly mirror the Go structs:
> `LogEvent`, `Classification` (with Severity type `"P1"|"P2"|"P3"|"P4"|"P5"`), `ClassifiedEvent`.
> Create an axios instance with `baseURL: "/api"` and a 30-second timeout.
> Export typed functions: `classifyLog(log: string, format?: string): Promise<ClassifiedEvent>`,
> `getHealth(): Promise<{status: string}>`.
> Add a request interceptor that logs request duration to the console in development.

---

## 1-C · UI/UX Components

---

### Feature: Design tokens and theme

**Prompt**
> Create `web/src/styles/tokens.ts` in the SIEMAgent frontend.
> Define a severity colour map: P1=#DC2626 (red-600), P2=#EA580C (orange-600),
> P3=#CA8A04 (yellow-600), P4=#2563EB (blue-600), P5=#6B7280 (gray-500).
> Create a `useDarkMode` hook that reads from localStorage and toggles a `dark` class on `<html>`.
> Configure Tailwind to support dark mode via the `class` strategy.
> The overall theme is dark-first: bg-gray-950 background, gray-900 cards, gray-800 borders,
> with the Geist Mono font for all log text and Geist Sans for UI text.

---

### Feature: SeverityBadge component

**Prompt**
> Create `web/src/components/SeverityBadge.tsx` in the SIEMAgent frontend.
> It takes a `severity: "P1"|"P2"|"P3"|"P4"|"P5"` prop and renders a small pill badge.
> P1 pulses with a CSS animation to convey urgency. P5 is muted.
> Include a `size` prop: `sm` (text-xs, px-1.5 py-0.5) and `md` (text-sm, px-2 py-1).
> Export a `SEVERITY_LABELS` map: P1="Critical", P2="High", P3="Medium", P4="Low", P5="Info".

---

### Feature: MITREBadge component

**Prompt**
> Create `web/src/components/MITREBadge.tsx`.
> It takes `tactic: string` and `technique: string` props.
> Render the tactic as a small gray chip and the technique ID (e.g. T1110.001) as a monospace
> link that opens `https://attack.mitre.org/techniques/T1110/001/` in a new tab.
> If either value is `"none"` or empty, render nothing.
> Add a tooltip on hover showing the technique ID full name if it is in a local lookup table
> of the top 20 most common techniques (hardcode the map in the component).

---

### Feature: IOCList component

**Prompt**
> Create `web/src/components/IOCList.tsx`.
> It takes `iocs: string[]` prop. Render each IOC as a chip with an icon:
> IPs (regex for IPv4/IPv6) get a `Network` icon and link to `https://www.abuseipdb.com/check/{ip}`,
> MD5/SHA hashes (32/40/64 hex chars) get a `Hash` icon and link to VirusTotal,
> domains get a `Globe` icon and link to VirusTotal URL scan.
> All chips are monospace, dark background, and open links in new tabs.
> If `iocs` is empty, render nothing.

---

### Feature: EventCard component

**Prompt**
> Create `web/src/components/EventCard.tsx`.
> Props: `event: ClassifiedEvent`, `onClick: () => void`, `selected: boolean`.
> Layout: left border coloured by severity, then severity badge + attack_type label,
> then the source host and app name, then a truncated (max 80 chars) summary,
> then MITRE tactic chip, timestamp (relative: "2m ago"), and confidence as a small bar.
> Selected state adds a ring and slightly lighter background.
> The entire card is a button with hover and focus-visible styles.

---

### Feature: Dashboard page

**Prompt**
> Create `web/src/pages/Dashboard.tsx`.
> Layout: fixed left sidebar (240px) with app name, nav links (Dashboard, Search, Incidents),
> and severity filter checkboxes. Main area has a sticky header with a log file upload button
> and a "Classify log line" text input + submit button.
> Below that: a scrollable event list using `EventCard` with pull-to-refresh.
> A right detail panel (360px) slides in when an event is selected, showing full classification
> details with all components (SeverityBadge, MITREBadge, IOCList, recommended action).
> Use `@tanstack/react-query` to manage the event list state and invalidate on new classify.

---

### Feature: Log file upload

**Prompt**
> Add a log file upload feature to `web/src/pages/Dashboard.tsx`.
> Create a `DropZone` component that accepts drag-and-drop or click-to-browse for `.log` and `.txt` files.
> On file select, read the file client-side with `FileReader`, split by newlines,
> filter non-empty non-comment lines, and send each line to `POST /api/classify` in batches of 5
> using `Promise.allSettled`. Show a progress bar: "Classifying 12 / 47 events".
> Display a toast summary when done: "47 events classified — 2 Critical, 5 High, 40 others".

---

## 1-D · Testing & Validation

---

### Feature: Syslog parser unit tests

**Prompt**
> Create `internal/parser/syslog_test.go` in the SIEMAgent project.
> Write table-driven tests for `ParseSyslog` covering:
> (1) valid RFC 5424 line — assert all fields parsed correctly,
> (2) valid line with NILVALUE procid (`-`) — assert PID is 0,
> (3) line with UTC timestamp — assert timezone is UTC,
> (4) empty string — assert error returned,
> (5) plain syslog without RFC 5424 PRI header — assert error returned,
> (6) kernel log with PID 0 and long message containing brackets.
> Use only the standard `testing` package, no third-party assertion libraries.

---

### Feature: JSON log parser unit tests

**Prompt**
> Create `internal/parser/json_log_test.go` in the SIEMAgent project.
> Write table-driven tests for `ParseJSON` covering these real-world formats:
> (1) logrus format (`level`, `msg`, `time`),
> (2) zap format (`level`, `message`, `ts` as Unix float),
> (3) zerolog format (`level`, `message`, `time` as RFC3339),
> (4) bunyan format (`level` as int, `msg`, `hostname`),
> (5) missing timestamp — assert fallback to approximately `time.Now()`,
> (6) invalid JSON — assert error returned,
> (7) empty `{}` object — assert event with empty fields, no error.

---

### Feature: Classifier mock test

**Prompt**
> Create `internal/classifier/classifier_test.go` in the SIEMAgent project.
> Write a test for `Classifier.Classify` that uses a mock OpenAI-compatible HTTP server
> (use `net/http/httptest`) that returns a valid SSE stream with the classification JSON.
> Assert that the returned `*Classification` has the correct `AttackType`, `Severity`,
> and `MITRETechnique` matching what the mock returned.
> Write a second test where the mock returns JSON wrapped in markdown fences (```json...```)
> and assert the fence-stripping logic in `unmarshalLLM` handles it correctly.
> Write a third test where the mock returns malformed JSON and assert the error is non-nil.

---

### Feature: API integration tests

**Prompt**
> Create `internal/api/server_test.go` in the SIEMAgent project.
> Use `net/http/httptest.NewRecorder()` and `httptest.NewServer` to test the Chi handlers
> without a real LLM. Mock the classifier using an interface:
> create a `ClassifierInterface` with a `Classify` method, and inject a mock that returns
> a fixed `*models.Classification`.
> Test: `GET /health` returns 200 with `{"status":"ok"}`.
> Test: `POST /classify` with a valid syslog line returns 200 with a `ClassifiedEvent`.
> Test: `POST /classify` with an empty body returns 400.
> Test: `POST /classify` with a body > 8192 bytes returns 400.

---

### Feature: Frontend component tests

**Prompt**
> In `web/src`, set up Vitest + React Testing Library.
> Install `@testing-library/react`, `@testing-library/user-event`, `@testing-library/jest-dom`,
> and configure `vitest.config.ts` with jsdom environment.
> Write tests for `SeverityBadge`: assert correct text ("Critical" for P1), correct color class,
> and that P1 has the pulse animation class.
> Write tests for `IOCList`: assert IP `192.168.1.1` renders an AbuseIPDB link,
> MD5 hash renders a VirusTotal link, and empty array renders nothing.
> Write a test for `EventCard`: assert clicking calls `onClick`, selected state adds ring class.

---

---

# PHASE 2 — RAG Pipeline

**Goal:** Embed every classified event, store in Qdrant, surface similar past events on new classifications.

---

## 2-A · Backend

---

### Feature: Ollama embeddings client

**Prompt**
> Create `pkg/ollama/embeddings.go` in the SIEMAgent project.
> Implement an `Embedder` struct with a `NewEmbedder(baseURL string) *Embedder` constructor
> (default baseURL: `http://localhost:11434`).
> Implement `func (e *Embedder) Embed(ctx context.Context, text string) ([]float32, error)`.
> POST to `/api/embeddings` with `{"model":"nomic-embed-text","prompt":text}`.
> Parse the response `{"embedding":[...]}` and return the float32 slice.
> Add a `func (e *Embedder) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error)`
> that calls Embed concurrently with a semaphore limiting to 5 parallel requests.

---

### Feature: Qdrant collection initialization

**Prompt**
> Implement `EnsureCollection` in `pkg/qdrant/client.go` in the SIEMAgent project.
> Use `s.client.CreateCollection` from `github.com/qdrant/go-client/qdrant` to create the
> collection with `VectorsConfig` set to cosine distance and 768 dimensions
> (matching nomic-embed-text output). If the collection already exists, swallow the
> "already exists" gRPC error and return nil. Add an `indexPayloadField` call to
> create a keyword index on the `severity` and `attack_type` payload fields for hybrid filtering.

---

### Feature: Event upsert pipeline

**Prompt**
> Implement `Upsert` in `pkg/qdrant/client.go` in the SIEMAgent project.
> Accept `id string, vector []float32, payload map[string]any`.
> Construct a `*qdrant.PointStruct` where the ID is a UUID derived from the event ID string
> (use `fmt.Sprintf` + deterministic hashing to convert string ID to uint64),
> the vector is a named vector map `{"default": vector}`, and the payload is the provided map.
> Call `s.client.Upsert(ctx, &qdrant.UpsertPoints{CollectionName: s.collection, Points: []*qdrant.PointStruct{pt}})`.
> Return any error wrapped with `fmt.Errorf`.

---

### Feature: Semantic search

**Prompt**
> Implement `Search` in `pkg/qdrant/client.go` in the SIEMAgent project.
> Use `s.client.Query` to run a nearest-neighbour search against the collection.
> Accept `queryVector []float32`, `topK uint64`, and an optional `filter *qdrant.Filter`.
> Return `[]SearchResult` where `SearchResult` has `ID string`, `Score float32`, and `Payload map[string]any`.
> In `internal/api/server.go`, wire `GET /search?q=<text>&severity=P2&limit=10` to:
> embed the query text with the Ollama client, optionally build a Qdrant keyword filter for severity,
> run the search, and return the results as JSON.

---

### Feature: Post-classify ingestion

**Prompt**
> In `internal/classifier/classifier.go`, after a successful classification, automatically
> index the event into Qdrant. Inject the Ollama `Embedder` and Qdrant `Store` into the
> `Classifier` struct (make them optional with nil checks so Phase 1 tests still pass).
> The text to embed should be: `"{source} {app} {message} {attack_type} {mitre_tactic}"`.
> The payload stored in Qdrant should be the full `ClassifiedEvent` marshalled to a `map[string]any`.
> Run the embed + upsert in a separate goroutine so it does not block the HTTP response.

---

### Feature: Bulk ingestion endpoint

**Prompt**
> Implement `POST /ingest` in `internal/api/server.go` in the SIEMAgent project.
> Accept a JSON body `{"logs": ["line1", "line2", ...], "format": "auto"}` with up to 500 lines.
> Parse all lines, classify them using the worker pool from `cmd/siemagent/main.go`'s
> `classifyPool` function (extract it into `internal/pipeline/pool.go`),
> then return `{"accepted": 47, "classified": 45, "errors": 2, "results": [...ClassifiedEvent]}`.
> Stream progress using `Transfer-Encoding: chunked` — flush a progress JSON line every 10 events.

---

## 2-B · Frontend

---

### Feature: Semantic search page

**Prompt**
> Create `web/src/pages/Search.tsx` in the SIEMAgent frontend.
> Layout: a large search bar at the top, optional severity filter checkboxes.
> On submit, call `GET /api/search?q={query}&severity={filter}&limit=20`.
> Render results as a list of `EventCard` components sorted by relevance score.
> Add a `score` prop to `EventCard` that shows a small "92% match" badge in the top-right corner.
> Show an empty state illustration when there are no results.
> Debounce the search input with a 300ms delay and trigger search automatically as the user types.

---

### Feature: SimilarEvents panel

**Prompt**
> Add a `SimilarEvents` section to the event detail panel in `web/src/pages/Dashboard.tsx`.
> When an event is selected, fire a `GET /api/search?q={summary}&limit=5` request
> using the event's summary as the query.
> Show a "Similar past events" section below the classification details with 3–5 compact cards.
> Each compact card shows: severity badge, attack type, source, and "N hours ago".
> Add a loading skeleton while the search is in flight.

---

### Feature: Analytics charts

**Prompt**
> Create `web/src/components/AnalyticsPanel.tsx` using recharts.
> Render three charts stacked vertically:
> (1) a BarChart of event count by attack_type (last 24h), bars coloured by severity,
> (2) a LineChart of event count over time (last 6h, 10-minute buckets) with separate
>     lines for P1/P2/P3 coloured by their severity colours,
> (3) a PieChart of MITRE tactic distribution.
> All charts use dark backgrounds matching the app theme.
> Data comes from a new `GET /api/analytics/summary` endpoint that you should also create
> in the Go backend, computing stats from an in-memory store of the last 1000 classified events.

---

## 2-C · Testing

---

### Feature: Qdrant integration test

**Prompt**
> Create `pkg/qdrant/client_integration_test.go` in the SIEMAgent project.
> Add a `//go:build integration` build tag so it runs only with `go test -tags integration`.
> The test connects to Qdrant at `localhost:6334` (or `QDRANT_TEST_HOST` env var).
> It: creates a test collection with 4-dimensional vectors, upserts 5 test points with payloads,
> searches for the nearest 3 to a query vector, asserts the top result matches expected,
> then deletes the test collection to clean up.

---

### Feature: Embedding consistency test

**Prompt**
> Create `pkg/ollama/embeddings_test.go` in the SIEMAgent project.
> Write a unit test using `httptest.NewServer` that simulates the Ollama API.
> Assert that `Embed` returns a slice of the expected length (768 for nomic-embed-text).
> Assert that `EmbedBatch` calls the mock server exactly N times for N inputs.
> Write a separate `//go:build integration` test that calls real Ollama and asserts
> that the same text embedded twice returns identical vectors (determinism check)
> and that two different texts have cosine similarity < 1.0.

---

### Feature: API load test

**Prompt**
> Create `internal/api/load_test.go` in the SIEMAgent project (Go benchmark, not k6).
> Write `BenchmarkClassifyEndpoint` using `httptest.NewServer` with a mock classifier
> that returns instantly. Benchmark concurrent requests using `b.SetParallelism(10)` and `b.RunParallel`.
> Also write `BenchmarkParseLogFile` that benchmarks reading and parsing 1000 lines from
> `testdata/sample.log` repeated. Run with `go test -bench=. -benchmem -benchtime=10s`.

---

---

# PHASE 3 — Agentic Incident Responder

**Goal:** Custom tool-use loop that autonomously gathers threat intel and generates incident playbooks, streamed live over WebSocket.

---

## 3-A · Backend — Tool System

---

### Feature: Tool type definitions

**Prompt**
> Create `internal/agent/tools.go` in the SIEMAgent project.
> Define a `Tool` interface with `Name() string`, `Description() string`, `Schema() json.RawMessage`,
> and `Execute(ctx context.Context, input json.RawMessage) (string, error)`.
> Define an `openai.Tool`-compatible builder function `ToOpenAITool(t Tool) openai.Tool`
> that constructs the `openai.Tool` struct with the tool's name, description, and JSON schema.
> Define a `ToolRegistry` struct with a `map[string]Tool` and methods `Register(Tool)` and
> `Dispatch(ctx context.Context, name string, input json.RawMessage) (string, error)`.

---

### Feature: AbuseIPDB tool

**Prompt**
> Create `internal/agent/tools/abuseipdb.go` in the SIEMAgent project.
> Implement the `Tool` interface for AbuseIPDB IP reputation lookup.
> JSON input schema: `{"ip": "string (required — IPv4 or IPv6 address)"}`.
> Call `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90`
> with header `Key: {ABUSEIPDB_KEY}` from env.
> Return a concise JSON string: `{"ip":"...","abuse_score":87,"country":"CN","isp":"...","total_reports":142,"last_reported":"2024-01-10"}`.
> If the IP is private (RFC1918) return `{"ip":"...","note":"private IP, skipping lookup"}` without an API call.
> Respect a 3000 req/day budget by tracking call count in a package-level atomic counter.

---

### Feature: AlienVault OTX tool

**Prompt**
> Create `internal/agent/tools/otx.go` in the SIEMAgent project.
> Implement the `Tool` interface for AlienVault OTX threat intel lookup.
> JSON input schema: `{"indicator": "string (required)", "type": "string (ip|domain|hash)"}`.
> For IP: GET `https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general`.
> For domain: GET `.../domain/{indicator}/general`.
> For hash: GET `.../file/{indicator}/general`.
> Header: `X-OTX-API-KEY: {OTX_API_KEY}` from env.
> Parse the response and return a concise summary string with: pulse count, threat labels,
> country, and the most recent pulse name and date.

---

### Feature: MITRE ATT&CK lookup tool

**Prompt**
> Create `internal/agent/tools/mitre.go` in the SIEMAgent project.
> Implement a `MITRELookup` tool that needs NO API key (uses local data).
> On package init, download and cache the MITRE ATT&CK STIX bundle from
> `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
> to a local file `data/mitre_attack.json` if it doesn't exist, then load it into memory.
> JSON input schema: `{"technique_id": "string (e.g. T1110.001)"}`.
> Return: technique name, tactic, description (first 300 chars), platform list, and detection guidance.

---

### Feature: Qdrant search tool (agent-accessible)

**Prompt**
> Create `internal/agent/tools/similar_events.go` in the SIEMAgent project.
> Implement a `SimilarEventsTool` that wraps the Qdrant `Store` and Ollama `Embedder`.
> JSON input schema: `{"query": "string (natural language description of the incident)","limit": "integer (default 5)"}`.
> Embed the query, search Qdrant, and return the top N similar past events as a JSON array
> with fields: event_id, timestamp, source, attack_type, severity, summary, mitre_technique.
> Format the return as a single compact JSON string the LLM can reason over.

---

### Feature: Agent loop

**Prompt**
> Create `internal/agent/agent.go` in the SIEMAgent project.
> Implement `func RunIncidentAgent(ctx context.Context, client *openai.Client, model string, registry *ToolRegistry, event models.ClassifiedEvent) (string, error)`.
> This is the core tool-use loop:
> 1. Build an initial system prompt describing the agent's role as a security incident responder.
> 2. Build a user message with the full classification details.
> 3. Call `client.CreateChatCompletion` with `tools` built from `registry.AllTools()`.
> 4. If `FinishReason == "tool_calls"`, iterate over tool calls, dispatch each via `registry.Dispatch`,
>    append `ChatMessageRoleTool` messages, and loop again. Cap at 8 iterations.
> 5. When `FinishReason == "stop"`, return the assistant's final message as the incident playbook.
> Log each tool call (name, input, output length) with slog.

---

### Feature: Streaming agent loop over WebSocket

**Prompt**
> Extend `internal/agent/agent.go` in the SIEMAgent project to support streaming.
> Add `func RunIncidentAgentStream(ctx context.Context, client *openai.Client, model string, registry *ToolRegistry, event models.ClassifiedEvent, send func(AgentEvent)) error`.
> `AgentEvent` is a struct with `Type string` and `Data string`.
> Send events: `{"type":"tool_call","data":"{\"name\":\"check_abuseipdb\",\"input\":{...}}"}` when a tool is called,
> `{"type":"tool_result","data":"..."}` after the tool returns,
> `{"type":"chunk","data":"..."}` for each LLM streaming token in the final response,
> `{"type":"done","data":""}` when complete, `{"type":"error","data":"..."}` on failure.
> Use `CreateChatCompletionStream` only for the final synthesis step (after all tools are done).

---

### Feature: WebSocket hub

**Prompt**
> Create `internal/api/hub.go` in the SIEMAgent project.
> Implement a `Hub` struct that manages WebSocket client connections with:
> `Register(conn *websocket.Conn) string` (returns a client ID),
> `Unregister(id string)`, `Broadcast(msg []byte)`, `Send(id string, msg []byte)`.
> Use a `map[string]*websocket.Conn` protected by `sync.RWMutex`.
> Run each connection's write loop in a separate goroutine using a buffered `chan []byte` of size 256.
> Drop messages silently for clients whose write buffer is full (non-blocking send).
> In `internal/api/ws_handler.go`, implement `handleAlertStream` to upgrade, register, and unregister.

---

### Feature: P1/P2 auto-trigger

**Prompt**
> In `internal/api/server.go` in the SIEMAgent project, after every successful `POST /classify`,
> check if the classification severity is P1 or P2.
> If so, launch a goroutine that calls `agent.RunIncidentAgentStream` and, for each `AgentEvent`,
> marshals it to JSON and calls `hub.Broadcast`.
> The broadcast message format is: `{"incident_id":"...", "event_id":"...", "type":"...", "data":"..."}`.
> The incident_id is a new UUID generated at the start of each agent run.
> Inject the `Hub` into the `Server` struct.

---

## 3-B · Frontend

---

### Feature: useAlertStream hook

**Prompt**
> Create `web/src/hooks/useAlertStream.ts` in the SIEMAgent frontend.
> This React hook opens a WebSocket to `ws://localhost:8080/ws/alerts`.
> It manages reconnection with exponential backoff (1s, 2s, 4s, max 30s).
> It returns `{ connected: boolean, incidents: Map<string, Incident>, latestEvent: AgentEvent | null }`.
> `Incident` accumulates `AgentEvent` messages by `incident_id`: it tracks tool calls, results,
> and assembles the streaming playbook text chunk by chunk.
> Expose `clearIncident(id: string)` to remove an incident from the map.

---

### Feature: Live alert ticker

**Prompt**
> Create `web/src/components/AlertTicker.tsx` in the SIEMAgent frontend.
> This is a fixed banner at the top of the app that shows active P1/P2 incidents.
> When a new incident starts, it slides in from the right with a CSS transition.
> Each alert shows: severity badge (pulsing for P1), source host, attack type, and "Investigating…"
> with a spinner, switching to "Playbook ready" with a checkmark when `type === "done"` is received.
> Click on the alert to navigate to the incident detail page.
> Auto-dismiss P3+ events after 10 seconds.

---

### Feature: Incident detail page

**Prompt**
> Create `web/src/pages/Incident.tsx` in the SIEMAgent frontend.
> It receives an `incidentId` URL param and reads from the `useAlertStream` hook.
> Layout: left column (40%) shows the original classified event — all fields from Phase 1's detail panel.
> Right column (60%) shows the agent's investigation in real-time:
> a timeline of tool calls (each collapsible, showing name, input, output),
> then the streaming playbook text rendered as Markdown using `react-markdown`.
> A "Copy Playbook" button copies the full markdown text to the clipboard.
> Add a "Status" chip: Investigating / Enriching / Synthesizing / Complete / Failed.

---

### Feature: Threat intel cards

**Prompt**
> Create `web/src/components/ThreatIntelPanel.tsx` in the SIEMAgent frontend.
> Given an array of `AgentEvent` objects from a completed incident, extract all
> `tool_result` events where the tool name is `check_abuseipdb` or `check_otx`.
> For each AbuseIPDB result, render a card: IP, abuse score as a coloured gauge (green/yellow/red),
> country flag emoji, ISP name, and report count.
> For each OTX result, render a card: indicator, threat labels as chips, pulse count.
> Show a "No external threat intel" placeholder when no tool results exist.

---

### Feature: MITRE ATT&CK heatmap

**Prompt**
> Create `web/src/components/MITREHeatmap.tsx` in the SIEMAgent frontend using recharts or d3-lite.
> It takes `events: ClassifiedEvent[]` as a prop.
> Build a grid: rows = 14 MITRE tactics (in kill-chain order from Reconnaissance to Impact),
> columns = weekdays (Mon–Sun for the last 7 days).
> Each cell's opacity maps to event count (0 = transparent, max count = full colour).
> Cell colour = the highest severity seen for that tactic+day (P1=red, P2=orange, P3=yellow).
> Click a cell to filter the event list to matching events.
> Show a legend and a total event count below the grid.

---

## 3-C · Testing

---

### Feature: Tool unit tests with mock HTTP

**Prompt**
> Create `internal/agent/tools/abuseipdb_test.go` in the SIEMAgent project.
> Write tests for the AbuseIPDB tool using `httptest.NewServer` as the mock API server.
> Test (1): valid IP → correct JSON fields in the return string.
> Test (2): RFC1918 private IP (`10.0.0.1`) → no HTTP call made, note returned.
> Test (3): API returns 429 → error is wrapped and returned.
> Test (4): API returns malformed JSON → error is returned.
> Do the same for the OTX tool in `otx_test.go`.

---

### Feature: Agent loop test with mock LLM

**Prompt**
> Create `internal/agent/agent_test.go` in the SIEMAgent project.
> Mock the OpenAI-compatible HTTP server using `httptest.NewServer`.
> Scenario 1: LLM returns one tool call (`check_abuseipdb`), then on the second call returns `finish_reason: stop`.
> Assert the loop calls the tool exactly once and returns the final text.
> Scenario 2: LLM returns `finish_reason: stop` immediately (no tools). Assert no tools are called.
> Scenario 3: LLM always returns tool_calls. Assert the loop breaks after 8 iterations and returns an error.
> Use a `ToolRegistry` with a mock tool that records its call count.

---

### Feature: WebSocket integration test

**Prompt**
> Create `internal/api/hub_test.go` in the SIEMAgent project.
> Start a `httptest.NewServer` with the full Chi router including the WebSocket endpoint.
> Connect 3 WebSocket clients using `gorilla/websocket.DefaultDialer.Dial`.
> Call `hub.Broadcast([]byte("test"))` and assert all 3 clients receive the message within 1 second.
> Disconnect client 2, broadcast again, assert clients 1 and 3 receive it but no panic occurs.
> Test that `Send` to a specific client ID reaches only that client.

---

### Feature: E2E test with Playwright

**Prompt**
> Create `web/e2e/classify.spec.ts` in the SIEMAgent frontend using Playwright.
> Set up `playwright.config.ts` with a `baseURL: "http://localhost:5173"` and a `webServer`
> that starts the Go backend (with a test KIMCHI_API_KEY that uses a mock server) and Vite dev server.
> Write test 1: navigate to Dashboard, type a syslog line into the classify input, submit,
> assert a new EventCard appears with a severity badge and MITRE technique.
> Write test 2: click the EventCard, assert the detail panel opens with recommended action text.
> Write test 3: navigate to /search, type "brute force", assert results appear within 3 seconds.

---

---

# CROSS-CUTTING CONCERNS

---

## Security Hardening

**Prompt**
> Audit the SIEMAgent Go API for security issues and fix them.
> (1) Add `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`,
> and `Referrer-Policy` response headers in a middleware.
> (2) Sanitise all log content before returning it in API responses — strip ANSI codes
> and control characters that could enable log injection.
> (3) Add CORS middleware allowing only `http://localhost:5173` in development
> and the production domain in production, controlled by an `ALLOWED_ORIGIN` env var.
> (4) Validate that IOC IPs extracted from logs are valid IP addresses before passing
> them to the AbuseIPDB tool to prevent SSRF via crafted log lines.

---

## Observability

**Prompt**
> Add structured observability to the SIEMAgent project.
> (1) In every slog log line across all packages, add a `"component"` field (classifier, parser, agent, api).
> (2) Add OpenTelemetry tracing using `go.opentelemetry.io/otel`: create a tracer in main,
> start a span in the classifier around the LLM call, and in the agent around each tool execution.
> Export traces to a local Jaeger instance (add Jaeger to docker-compose).
> (3) Add a `GET /debug/pprof` endpoint (protected by a secret header) for CPU and memory profiling.

---

## Production Dockerfile

**Prompt**
> Write a multi-stage `Dockerfile` for the SIEMAgent project.
> Stage 1 (`build-frontend`): use `node:22-alpine`, run `npm ci` and `npm run build` in `web/`.
> Stage 2 (`build-backend`): use `golang:1.25-alpine`, copy `go.mod`/`go.sum` and run `go mod download`,
> then copy source and run `go build -ldflags="-s -w" -o /siemagent ./cmd/siemagent`.
> The binary should embed the React build output via `//go:embed web/dist` and serve it from `GET /*`.
> Stage 3 (`runtime`): use `gcr.io/distroless/static-debian12`, copy only the binary.
> The final image should be under 30MB. Add a `HEALTHCHECK` instruction calling `/health`.

---

## CI/CD Pipeline

**Prompt**
> Write a `.github/workflows/ci.yml` for the SIEMAgent project.
> Jobs:
> `lint`: runs `golangci-lint` on Go code and `eslint` on TypeScript.
> `test-unit`: runs `go test ./...` and `npm run test` (Vitest), uploads coverage to Codecov.
> `test-integration`: runs with `services: {qdrant: ..., ollama: ...}`, runs `go test -tags integration ./...`.
> `build`: builds the Docker image, runs `docker scout` for CVE scanning.
> `e2e`: runs Playwright tests against the built Docker image.
> All jobs run on `push` to any branch. Only `build` and `e2e` run on PRs to `main`.
