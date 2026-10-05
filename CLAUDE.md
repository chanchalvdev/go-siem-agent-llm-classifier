# Go SIEM Agent — LLM Classifier — Harness Engineering Master Document

## Project Overview

A Go CLI + HTTP server that ingests syslog/JSON log events, classifies them via an
OpenAI-compatible LLM (Kimchi/local Ollama), maps results to MITRE ATT&CK, and stores
embeddings in Qdrant for semantic similarity search. Ships a React (Vite) dashboard.

```
go-siem-agent-llm-classifier/
├── CLAUDE.md                        ← This file (harness bible)
├── Makefile                         ← Root task runner (delegates to siemagent/)
├── scripts/                         ← Harness automation
│   ├── quality-gate.sh
│   ├── test-run.sh
│   ├── build-check.sh
│   ├── health-check.sh
│   ├── lint-fix.sh
│   ├── self-improve.sh
│   ├── metrics-capture.sh
│   └── metrics/                     ← JSON snapshots (git-ignored)
├── .github/workflows/
│   ├── ci.yml
│   └── self-improve.yml
├── siemagent/                       ← Core Go + React application
│   ├── cmd/siemagent/main.go
│   ├── internal/
│   │   ├── api/          server.go · handlers_phase2.go · health.go · swagger.go
│   │   ├── classifier/   classifier.go (LLM + MITRE + Qdrant indexing)
│   │   ├── config/       config.go
│   │   ├── metrics/      metrics.go (Prometheus)
│   │   ├── models/       models.go
│   │   ├── parser/       parser.go (syslog + JSON)
│   │   ├── pipeline/     pool.go (worker pool)
│   │   └── store/        events.go (in-memory event store)
│   ├── pkg/
│   │   ├── ollama/       embeddings.go (vector embedding)
│   │   └── qdrant/       client.go · adapter.go (vector search)
│   ├── web/              Vite + React + TypeScript dashboard
│   │   ├── src/
│   │   │   ├── components/
│   │   │   ├── pages/
│   │   │   ├── lib/api.ts
│   │   │   └── __tests__/
│   │   ├── vite.config.ts
│   │   └── vitest.config.ts
│   ├── Makefile                     ← siemagent-specific tasks (existing)
│   ├── docker-compose.yml           ← Qdrant + Ollama + Postgres
│   └── .env.example
└── siemagent/sample.log             ← Test log events
```

---

## Harness Principles

### 1. Quality Gate — must pass before any commit
```
Go:   go vet ./...  →  golangci-lint ./...  →  go test -race ./...  →  go build
Web:  tsc -b        →  oxlint              →  vitest run          →  vite build
```

### 2. Self-Improvement Loop
- Every `scripts/metrics-capture.sh` run records: TS errors, lint warnings, test pass
  rate, Go coverage, LLM response latency (from Prometheus if running), build times.
- `scripts/self-improve.sh` detects ≥ 3 consecutive failures on any metric and writes
  an actionable report to `scripts/metrics/improvement-report-YYYY-MM-DD.md`.
- GitHub Actions runs this weekly (Sunday 03:30 UTC).

### 3. Fail Fast, Fail Loud
- CI fails immediately on first error — no `continue-on-error` for quality checks.
- `go test` always runs with `-race` — data races are treated as failures.
- Integration tests tagged `//go:build integration` require Qdrant; run separately.

### 4. Security Non-Negotiables
- `KIMCHI_API_KEY` / `OPENAI_API_KEY` must NEVER appear in source files.
- `.env` is git-ignored — only `.env.example` (with placeholders) is committed.
- `siemagent/.env` ALREADY EXISTS with real keys — never stage it.
- The `check-env` Make target guards against running without keys.
- Qdrant and Ollama endpoints are local — never expose them publicly without auth.

### 5. Agent Contract
- Only touch files in `siemagent/` — never modify harness scripts without instruction.
- Run `make quality-gate` before declaring any task done.
- Keep the existing `siemagent/Makefile` intact; the root `Makefile` delegates to it.
- All new Go packages must have at least one `_test.go` file.
- All new React components must have a matching `__tests__/*.test.tsx`.

---

## Technology Constraints

### Go (siemagent/)
- Module: `github.com/chverma/siemagent`  
- Go 1.25 — use `min()` built-in (available since 1.21), not a hand-rolled helper
- Logging: `log/slog` (stdlib) — not zerolog, not logrus
- HTTP: `go-chi/chi/v5`
- LLM client: `sashabaranov/go-openai` (OpenAI-compatible — works with Kimchi/Ollama)
- Metrics: `prometheus/client_golang` — all new counters/histograms go in `internal/metrics/`
- No `fmt.Println` in production paths — use `slog.Info/Warn/Error`
- Worker concurrency via `internal/pipeline.WorkerPool` — don't spawn raw goroutines in handlers

### React / Web (siemagent/web/)
- Vite 8 + React 19 + TypeScript 6
- State: TanStack Query v5 for server state — no custom fetch hooks
- Linter: oxlint (not ESLint) — `npm run lint` runs `oxlint`
- Tests: Vitest + @testing-library/react — test files in `src/__tests__/`
- Tailwind CSS v3 — config in `tailwind.config.js`
- No `console.log` in production components — use dev-only conditional logging

### Docker / Infrastructure
- `siemagent/docker-compose.yml` manages: Qdrant (vector DB), Ollama (local LLM), Postgres
- `make docker-up` before running integration tests
- Qdrant collection name: `siem_events`, vector dim: 768 (nomic-embed-text)
- Ollama model: `nomic-embed-text` (~274 MB)

---

## Performance Targets

| Operation | Target | Alert Threshold |
|---|---|---|
| LLM classification P95 | < 3s | > 8s |
| API `/classify` P95 | < 5s | > 10s |
| API `/search` P95 | < 200ms | > 1s |
| Worker pool throughput | > 50 events/min | < 20 events/min |
| Go build time | < 15s | > 45s |
| Vite build time | < 30s | > 60s |
| Go test suite | < 60s | > 120s |
| Vitest suite | < 30s | > 60s |

---

## Metrics Tracked by Self-Improvement Loop

| Metric | Source | Target | Alert |
|---|---|---|---|
| Go test coverage | `go test -cover` | > 60% | < 40% |
| Go vet issues | `go vet` | 0 | > 0 |
| golangci-lint warnings | `golangci-lint` | 0 | > 5 |
| TS compile errors | `tsc -b` | 0 | > 0 |
| oxlint warnings | `oxlint` | 0 | > 3 |
| Vitest pass rate | `vitest run` | 100% | < 100% |
| Go build success | `go build` | pass | fail |
| Vite build success | `vite build` | pass | fail |

---

## Environment Variables (siemagent/.env)

```bash
# LLM (required)
KIMCHI_API_KEY=<your-key>          # or set OPENAI_API_KEY
KIMCHI_BASE_URL=https://...        # OpenAI-compatible endpoint
KIMCHI_MODEL=...                   # model name

# Infrastructure (optional — defaults work with docker-compose)
CONDUCTOR_PORT=8080
QDRANT_ADDR=localhost:6334
OLLAMA_URL=http://localhost:11434
```

Copy `.env.example` to `.env` before running. The existing `.env` has real keys — never commit it.

---

## Makefile Quick Reference

```bash
make quality-gate        # Full gate: Go + Web quality checks
make test                # All tests (unit only, no Docker needed)
make test-integration    # Integration tests (requires docker-up)
make lint                # go vet + golangci-lint + oxlint
make lint-fix            # gofmt -w + golangci-lint --fix + oxlint --fix
make build               # Go binary
make build-all           # Frontend + embed into Go binary
make dev                 # Go backend + Vite hot-reload (parallel)
make health              # Runtime health probe
make metrics             # Capture snapshot
make improve             # Self-improvement analysis
make docker-up           # Start Qdrant + Ollama + Postgres
make docker-down         # Stop Docker services
make seed                # POST 10 sample events to /classify
```

---

## Known Issues / Decisions Log

| Date | Decision | Reason |
|---|---|---|
| Project start | Kimchi API (OpenAI-compatible) | Easy swap to local Ollama or GPT-4 |
| Project start | Qdrant over Pinecone | Self-hosted, free, gRPC native in Go |
| Project start | nomic-embed-text 768-dim | Best quality/size ratio for security logs |
| Project start | oxlint over ESLint | 50–100x faster, sufficient for this codebase |
| Project start | Worker pool in `pipeline/` | Backpressure, goroutine lifecycle, testability |
| Project start | Integration tests separate build tag | CI can run unit-only without Docker |
| 2026-10 | Gemini default LLM; `LLM_PROVIDER` selects gemini / ollama / openai | Ollama keeps logs on-host; one OpenAI-compatible client for all |
| 2026-10 | Postgres event store behind `store.Store`, memory fallback | Durable history; unreachable configured DB is fatal, not a silent downgrade |
| 2026-10 | API keys via `SIEM_API_KEYS` (SHA-256 + constant-time compare) | Minimal auth before RBAC/SSO; `?api_key=` only on WebSocket upgrades |
| 2026-10 | Dropped `middleware.RealIP` | Trusted client X-Forwarded-For, letting anyone spoof past the rate limiter |
| 2026-10 | Syslog listener sheds load (`TrySubmit`) instead of blocking | A slow LLM must never stall senders; drops are counted in metrics |
| 2026-10 | MIT license; platform roadmap in ROADMAP.md | Open-source release as an AI SOC platform, rules-first then AI |
| 2026-10 | Trunk-based flow: `<type>/<name>` branches, PR title = branch name, protected `master` | See docs/BRANCHING.md; enforced by the PR checks workflow and git hooks |
| 2026-10 | Releases from semver tags: binaries + GHCR images with provenance/SBOM | Reproducible, verifiable artifacts; CI reused as the release gate |
| 2026-10 | Go toolchain pinned to the latest 1.25 patch | `go 1.25.0` alone builds with an unpatched standard library |
| 2026-10 | Sigma engine in-house (`internal/detection`), rules-first by default | Rule matches skip the LLM; LLM outage falls back to rule verdicts; no heavy Sigma dependency |
| 2026-10 | Built-in rules carry `samples` replayed by tests | Detection-as-code: every rule change is tested against real parser output |
| 2026-10 | Threshold rules use arrival time, capped group state | Log timestamps are forgeable; attacker-chosen group keys must not grow memory unbounded |
| 2026-10 | Incidents correlate on shared IP/user/host within a window | One story per attack; one AI investigation per incident instead of per alert |
| 2026-10 | Response actions need approval by default; containment goes through one webhook | Humans approve actions; integrate with existing automation instead of shipping connectors |
| 2026-10 | Local accounts (bcrypt), hashed session tokens, SameSite=Strict + X-Requested-With | Roles and audit before SSO; CSRF-safe cookies without a token round-trip |
| 2026-10 | Versioned SQL migrations in `internal/migrate`, no third-party tool | Embedded, checksummed, advisory-locked; edited or newer-than-binary schemas fail start-up |
| 2026-10 | Retention off by default; purges only resolved incidents, in batches | Never delete data nobody asked to delete; open cases are evidence |
| 2026-10 | Suppressed events are stored, not dropped; hit counts in memory | Keeps the record for hunting; a noisy source must not cost a database write per event |
| 2026-10 | `LLM_PROVIDER=none` rules-only mode; demo seeds from `SEED_LOG_FILE` | A first look must not need an API key; the demo is smoke-tested in CI so it cannot rot |
| 2026-10 | IOC matching in-process (hash maps + per-prefix maps), feeds in memory | Constant-time lookups on every event with no extra service; a failed feed download keeps the last good list |
| 2026-10 | MTTD from the log time of the opening alert, only when within 24h; MTTA on first assign/status change | Replays and forged timestamps must not distort metrics; a comment is not taking ownership |
| 2026-10 | Normalised fields are an ECS subset in `LogEvent.Fields`, parser values first | One schema for rules, correlation and hunting; ECS names are what analysts and Sigma users already know |
