# Implementation Trace — Low Level

> **Current architecture:** this trace covers Phases 1–3. For the full flow through detection, incidents, AI investigation, response and users, read [ARCHITECTURE.md](ARCHITECTURE.md).

> **Living document.** Line numbers drift — when you touch a file listed here,
> fix its entry and add a row to the [Update Log](#update-log). For the
> boxes-and-arrows view read
> [IMPLEMENTATION_TRACE_HIGH_LEVEL.md](IMPLEMENTATION_TRACE_HIGH_LEVEL.md) first.
> Line refs verified against the working tree on 2026-07-13.

## Backend entry points

| Where | What |
|---|---|
| `siemagent/cmd/siemagent/main.go:30` | `main()` — loads config, branches CLI vs server |
| `main.go:164` | `runCLI` — one-shot file classification, progress bar, summary table |
| `main.go:81` | `runServer` — wires embedder, Qdrant, agent registry, WS hub, HTTP server |
| `main.go:147` | `buildRegistry` — which agent tools are registered |
| `main.go:127` | `buildHub` — WS hub construction |
| `main.go:133` | `qdrantSearchAdapter.Search` — adapts Qdrant store to the agent tool interface |

## Route table (the index for every request flow)

`siemagent/internal/api/server.go:117-141`

| Route | Handler | File |
|---|---|---|
| `GET /health`, `/health/ready` | `handleHealth` / `handleReady` | `internal/api/health.go` |
| `GET /metrics` | Prometheus | `internal/metrics/metrics.go` |
| `POST /api/classify` | `handleClassify` | `internal/api/server.go` |
| `POST /api/classify/stream` | `handleClassifyStream` (SSE) | `internal/api/server.go` |
| `POST /api/ingest` | `handleIngest` | `internal/api/handlers_phase2.go:18` |
| `GET /api/search` | `handleSearch` | `internal/api/handlers_phase2.go:105` |
| `GET /api/analytics/summary` | `handleAnalyticsSummary` | `internal/api/handlers_phase2.go:180` |
| `GET /ws/alerts` | `handleAlertStream` | `internal/api/ws_handler.go:20` |
| `GET /docs`, `/docs/openapi.yaml` | swagger UI + spec | `internal/api/swagger.go` |

## Flow 1 — Classify (trace hop by hop)

1. `handleClassify` (server.go) — decode request body, pick format.
2. **Parse** — `internal/parser/parser.go`
   - `ParseLine:29` → auto-detect; `ParseLineWithFormat:35` → forced format
   - `parseRFC5424:69` · `parseRFC3164:94` · `parseJSON:117` · `ParseRaw:152` (fallback)
   - Output: `models.LogEvent` (`internal/models/models.go`)
3. **Classify** — `internal/classifier/classifier.go`
   - `New:67` (client setup) · `Classify:99` · `ClassifyStream:105` (SSE variant)
   - `buildUserMessage:198` — the prompt sent to the LLM
   - `unmarshalLLM:222` — tolerant JSON extraction from the LLM reply
   - `buildClassifiedEvent:255` — MITRE technique mapping + severity + IOCs
   - `indexEvent:160` — async: embed (`pkg/ollama/embeddings.go`) → upsert
     (`pkg/qdrant/client.go`, adapter in `pkg/qdrant/adapter.go`)
4. Response: `models.ClassifiedEvent` JSON.

## Flow 2 — Ingest / pipeline / store

- `handleIngest` (`handlers_phase2.go:18`) — parse each line, submit to pool.
- `internal/pipeline/pool.go` — `NewWorkerPool:22` · `Start:33` (returns results
  channel) · `Submit:58` · `Close:63`. Bounded concurrency; no raw goroutines
  in handlers (project rule).
- `internal/store/events.go` — `Add:23` · `Recent:34` · `Summary:86` (drives
  analytics) · `higherSeverity:76`.

## Flow 3 — Search

- Query side: `handleSearch` (`handlers_phase2.go:105`) — embed query via
  `pkg/ollama/embeddings.go`, vector search via `pkg/qdrant/client.go`
  (collection `siem_events`, dim 768), optional severity filter.
- Index side: `classifier.indexEvent:160` (see Flow 1 step 3).

## Flow 4 — Agent (Phase 3)

`siemagent/internal/agent/`

| File | Key functions |
|---|---|
| `agent.go` | `seedMessages:31` (initial prompt from event) · `RunIncident:50` (blocking tool loop) · `runToolCalls:85` (dispatch) |
| `stream.go` | `RunIncidentStream:24` (streaming variant, emits `AgentEvent`s) · `dispatchStream:57` · `synthesize:78` (final verdict) · `failStream:114` |
| `tools.go` | `Registry` — name → tool lookup, OpenAI tool schemas |
| `tools/mitre.go` | MITRE ATT&CK technique lookup |
| `tools/abuseipdb.go` | IP reputation |
| `tools/otx.go` | AlienVault OTX threat intel |
| `tools/similar_events.go` | Qdrant recall of past similar events (wired only when Qdrant is up — `main.go:96`) |

Each tool has a sibling `_test.go` demonstrating its contract.

## Flow 5 — Live incidents (WS)

Backend:
- `internal/api/ws_handler.go:20` — `handleAlertStream`: upgrade, register client.
- `internal/api/hub.go` — `NewHub:31` · `Register:36` · `Unregister:48` ·
  `Broadcast:62` · `Send:71` · `wsClient.enqueue:81` (bounded per-client queue) ·
  `writePump:90`.
- `internal/api/sanitize.go` — `stripControl:16` · `sanitizeEvent:32` — scrubs
  payloads before the wire. Tests: `hub_test.go`, `sanitize_test.go`.

Frontend:
- `web/src/hooks/useAlertStream.ts` — `AgentEvent:4` · `Incident:19` ·
  `apply:37` (pure reducer: event stream → incident map; unit-tested) ·
  `useAlertStream:74` (WS connect/reconnect + state).
- `web/src/components/AlertTicker.tsx` — global ticker strip.
- `web/src/pages/Incident.tsx` — detail overlay (78 lines).
- Wiring: `web/src/App.tsx:12` — `LiveIncidents` keeps the stream app-global,
  outside `Dashboard`.

## Frontend map

| File | Role |
|---|---|
| `web/src/main.tsx` → `App.tsx` | Entry; no router — `Dashboard` + `LiveIncidents` |
| `web/src/lib/api.ts` | All REST calls: `classifyLog:68` · `getHealth:73` · `searchEvents:106` · `getAnalytics:113` · `ingestLogs:118` · `classifyLogStream:125` (SSE). 1:1 with the Go route table. |
| `web/src/pages/Dashboard.tsx` | Main page (480 lines): DropZone → classify → EventCard; AnalyticsPanel, MITREHeatmap, ThreatIntelPanel. TanStack Query v5. |
| `web/src/pages/Search.tsx` | Semantic search UI → `/api/search` |
| `web/src/pages/Docs.tsx` | API docs page |
| `web/src/components/` | Presentational: EventCard, SeverityBadge, MITREBadge, IOCList, SimilarEvents, DropZone, AlertTicker, MITREHeatmap, ThreatIntelPanel, AnalyticsPanel |
| `web/src/__tests__/` | Vitest + RTL — one per component/hook (Incident.tsx test currently missing) |
| `web/e2e/classify.spec.ts` | Playwright end-to-end classify flow |

## Cross-cutting

- **Config**: `internal/config/config.go` — env → `Config`. Keys in `siemagent/.env`
  (never committed; `.env.example` has placeholders).
- **Models**: `internal/models/models.go` — `LogEvent`, `LLMAnalysis`,
  `ClassifiedEvent`, severity enum. Read this early; every flow speaks these types.
- **Metrics**: `internal/metrics/metrics.go` — all Prometheus counters/histograms
  live here (project rule).
- **Logging**: `log/slog` everywhere; no `fmt.Println` in production paths.

## Verify-while-learning commands

```bash
make dev                        # backend + Vite hot reload
make seed                       # POST 10 sample events
go test -race ./...             # backend contracts (run from siemagent/)
npx vitest run                  # frontend contracts (run from siemagent/web/)
websocat ws://localhost:8080/ws/alerts   # watch the live stream raw
```

---

## Update Log

| Date | Author | Change |
|---|---|---|
| 2026-07-13 | Claude (initial) | Created doc; line refs verified against working tree (Phases 1–3) |
| 2026-10-03 | Claude | Not yet traced: `internal/detection`, `incident`, `response`, `auth`, `logsafe`; line references for `internal/api` predate them. See [ARCHITECTURE.md](ARCHITECTURE.md) for the current flow |
