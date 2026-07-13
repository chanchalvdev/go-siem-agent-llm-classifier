# Engineering Instructions — ALWAYS FOLLOW

> These rules apply to **every** spec and every file produced under `specs/`.
> They sit above the per-feature instructions. If a feature spec conflicts with
> these, these win.

## Non-negotiable rules

1. **File size** — no source file may exceed **150 lines of code**. If a unit
   grows past that, split it by responsibility (a new file, a new type).
2. **KISS** — the simplest design that satisfies the acceptance criteria wins.
   No speculative abstraction, no config flags nobody asked for.
3. **DRY** — reuse existing packages (`internal/models`, `internal/config`,
   `pkg/ollama`, `pkg/qdrant`, the classifier's `openai.Client`). Never copy a
   helper that already exists; import it.
4. **Modular & single-responsibility** — one file = one clear job. Tools,
   registry, loop, and transport (WebSocket) stay in separate files.
5. **Interfaces at boundaries** — anything that hits network or an LLM is behind
   a small interface so tests inject a mock (mirror `classifier.Interface`,
   `api.Searcher`, `api.Embedder`).
6. **Standard idioms** — Go 1.25 stdlib first, `log/slog` for logs (never
   `fmt.Println` in prod paths), `context.Context` as first arg, wrap errors
   with `fmt.Errorf("...: %w", err)`.
7. **Every package ships a `_test.go`.** Network is mocked with
   `httptest.NewServer`; the LLM is mocked with an OpenAI-compatible test server.
   Tests must pass under `go test -race`.
8. **Security** — no API keys in source; read from env via `config`. Validate
   any IOC (IP/domain) extracted from a log before using it in an outbound
   request (prevent SSRF). Never log secrets.
9. **Definition of done** — `make quality-gate` passes: `go vet` → lint →
   `go test -race` → `go build`. A feature is not done until its acceptance
   criteria are demonstrably met.

## Spec file contract

Every feature spec in this directory MUST contain these five sections:

- **Title** — the feature name.
- **Description** — what it does and why, in 2–4 sentences.
- **Instructions** — the concrete build steps (files, signatures, behaviour).
- **Validation test** — the exact tests that prove it works.
- **Acceptance criteria** — a checklist that is objectively pass/fail.
