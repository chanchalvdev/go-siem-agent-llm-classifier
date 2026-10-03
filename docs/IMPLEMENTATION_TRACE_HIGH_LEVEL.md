# Implementation Trace — High Level

> **Current architecture:** this trace covers Phases 1–3. For the full flow through detection, incidents, AI investigation, response and users, read [ARCHITECTURE.md](ARCHITECTURE.md).

> **Living document.** Update the [Update Log](#update-log) whenever architecture changes
> (new phase, new route, new page, new external service). Keep this file at the
> "boxes and arrows" altitude — file/function detail lives in
> [IMPLEMENTATION_TRACE_LOW_LEVEL.md](IMPLEMENTATION_TRACE_LOW_LEVEL.md).

## What the system is

A Go CLI + HTTP server that ingests syslog/JSON log events, classifies them with an
OpenAI-compatible LLM, maps results to MITRE ATT&CK, stores embeddings in Qdrant for
semantic search, investigates high-severity events with an autonomous tool-calling
agent, and streams live incidents to a React dashboard over WebSocket.

## System map

```
                        ┌─────────────────────────────────────────────┐
                        │                Go binary                    │
  log file ──► CLI ─────┤                                             │
                        │  parser ──► classifier ──► MITRE mapping    │
  HTTP POST ──► API ────┤     │           │                           │
  /api/classify         │     │           ├──► Ollama embed ──► Qdrant│
  /api/ingest           │  worker pool    │                           │
                        │                 └──► agent (tool loop) ──┐  │
  GET /api/search ──────┤◄── Qdrant semantic search               │  │
  GET /api/analytics ───┤◄── in-memory event store                │  │
                        │                                          ▼  │
  WS /ws/alerts ◄───────┤◄──────────────── hub broadcast ◄── sanitize │
                        └─────────────────────────────────────────────┘
                                   ▲
        React dashboard (Vite) ────┘  REST via lib/api.ts · live via useAlertStream
```

## The five flows (learn in this order)

| # | Flow | One-line description | Learned? |
|---|------|----------------------|----------|
| 1 | **Classify** | One log line → parse → LLM → MITRE + severity → JSON response | ☐ |
| 2 | **Ingest** | Batch of lines → worker pool → classify each → in-memory store → analytics | ☐ |
| 3 | **Search** | Query text → embed (Ollama) → Qdrant vector search → ranked hits | ☐ |
| 4 | **Agent** | High-severity event → LLM tool loop (MITRE / AbuseIPDB / OTX / similar events) → verdict | ☐ |
| 5 | **Live stream** | Agent progress events → sanitize → WS hub broadcast → ticker + incident overlay | ☐ |

### Flow 1 — Classify (the spine)
`POST /api/classify` → route table → handler → `parser` → `classifier.Classify`
(prompt build → LLM call → JSON unmarshal → MITRE map) → response. Also invoked by
the CLI path and by every other flow. **Understand this one first; everything
branches off it.**

### Flow 2 — Ingest
`POST /api/ingest` → parse lines → `pipeline.WorkerPool` (bounded concurrency,
backpressure) → classify each → `store.EventStore` (ring of recent events) →
feeds `GET /api/analytics/summary`.

### Flow 3 — Semantic search
Indexing side: after each classification, event text is embedded (nomic-embed-text,
768-dim, via Ollama) and upserted into Qdrant collection `siem_events`.
Query side: `GET /api/search` embeds the query and does vector search, optional
severity filter.

### Flow 4 — Agent (Phase 3)
For events that warrant investigation, `agent.RunIncident[Stream]` runs a
chat-completion loop: the LLM asks for tools, the registry dispatches them
(MITRE lookup, AbuseIPDB IP reputation, OTX threat intel, Qdrant similar-events),
results are fed back until the LLM synthesizes a final verdict.

### Flow 5 — Live incidents
Agent progress is emitted as `AgentEvent`s → sanitized (control chars stripped) →
broadcast through the WS `Hub` (per-client send queues) → frontend `useAlertStream`
reduces events into `Incident` state → `AlertTicker` (global) → click → `Incident`
overlay page.

## Frontend at a glance

- **No router.** `App.tsx` renders `Dashboard` + an app-global `LiveIncidents`
  wrapper (WS ticker + incident overlay).
- **All REST calls** live in `web/src/lib/api.ts` — 1:1 with the Go route table.
- **Server state** via TanStack Query v5; **live state** via the `useAlertStream` hook.
- Pages: Dashboard (main), Search, Docs, Incident (overlay). Components are
  presentational; data flows down from pages/hooks.

## External dependencies

| Service | Role | Local dev |
|---|---|---|
| Kimchi / OpenAI-compatible LLM | Classification + agent reasoning | `.env` keys |
| Ollama (`nomic-embed-text`) | 768-dim embeddings | `make docker-up` |
| Qdrant | Vector store, collection `siem_events` | `make docker-up` |
| AbuseIPDB / OTX | Agent threat-intel tools | API keys optional |

## Phase history

| Phase | Scope | Status |
|---|---|---|
| 1 | CLI + classify endpoint + parser + MITRE mapping | ✅ done |
| 2 | Ingest pipeline, Qdrant search, analytics, dashboard | ✅ done |
| 3 | Agent tool loop, WS live stream, ticker/incident UI, e2e tests | ✅ done |

## How to learn this codebase (suggested path)

1. Read this file top to bottom (15 min).
2. Trace Flow 1 statically using the low-level doc (1 hr).
3. Run it live: `make dev`, drop a line from `siemagent/sample.log`, watch the
   Network tab + backend `slog` output (30 min).
4. Trace Flows 2–5, one per sitting, checking the boxes above.
5. Read the tests for each unit last — they document the contracts.

---

## Update Log

| Date | Author | Change |
|---|---|---|
| 2026-07-13 | Claude (initial) | Created doc covering Phases 1–3 as implemented |
| 2026-10-03 | Claude | Phases 4–9 (Postgres, auth, Sigma + threshold rules, incidents, AI incident investigation, response playbooks, users/roles/audit) are described in [ARCHITECTURE.md](ARCHITECTURE.md); this trace still covers Phases 1–3 in detail |
