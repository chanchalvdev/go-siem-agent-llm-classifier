# Spec 3-06 — Security Hardening + E2E

## Title
Log-injection defence (response sanitisation) and a Playwright end-to-end suite.

## Description
Cross-cutting closers for Phase 3. Log content is attacker-controlled, so any of
it echoed back in an API response is sanitised to stop terminal/log-viewer
injection. A small Playwright suite exercises the dashboard end-to-end with the
API mocked in the browser, so it runs without a backend or live LLM.

## Instructions
### Backend — response sanitisation
- File: `internal/api/sanitize.go` (≤150 LOC).
- `stripControl(string) string` — remove ANSI/VT100 escape sequences and C0
  control chars (keep `\t`, `\n`).
- `sanitizeEvent(models.ClassifiedEvent) models.ClassifiedEvent` — clean the
  log-derived and LLM string fields (raw, message, hostname, app name, summary,
  attack type, remediation, IOCs).
- Apply it to the `/classify` response and every `/ingest` result before writing.
- IOC IP validation for SSRF already lives in the tools (`net.ParseIP` in
  spec 02); CSP/CORS/security headers already exist in `server.go`.

### Web — Playwright E2E
- `web/playwright.config.ts` — `baseURL` 5173, `webServer` runs `npm run dev`.
- `web/e2e/classify.spec.ts` — stub `/api/classify`, `/api/health`,
  `/api/analytics/summary` via `page.route`, then:
  1. classify a log line → event card shows severity + attack type + technique;
  2. the detail panel shows the recommended action text;
  3. the MITRE heatmap renders.
- Add `@playwright/test`; scripts `e2e` and `e2e:install`; exclude `e2e/**` from
  vitest; gitignore `test-results/` and `playwright-report/`.

## Validation test
- `internal/api/sanitize_test.go`: ANSI + `\x00`/`\x07` stripped while `root`
  and `\t` survive; `sanitizeEvent` cleans every targeted field.
- `npx playwright test` → all three specs green (needs `npm run e2e:install` once).

## Acceptance criteria
- [ ] Crafted ANSI/control chars never appear in `/classify` or `/ingest` output.
- [ ] `sanitize.go` ≤150 LOC; `go test -race ./internal/api/` passes.
- [ ] Playwright suite passes against a fresh Vite server.
- [ ] E2E artifacts git-ignored; vitest does not pick up `e2e/**`.
