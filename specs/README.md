# SIEMAgent — Phase 3 Specs (Agentic Incident Responder)

Phases 1 (Core Classifier) and 2 (RAG Pipeline) are **complete**. Phase 3 adds an
autonomous tool-use agent that enriches high-severity events with threat intel,
generates an incident playbook, and streams the investigation live to the UI.

**Read [`00-INSTRUCTIONS.md`](00-INSTRUCTIONS.md) first — those rules bind every spec below.**

## Build order

| # | Spec | Layer | Status |
|---|---|---|---|
| 01 | [Tool system](phase3-01-tool-system.md) | backend | ✅ implemented |
| 02 | [Threat-intel tools](phase3-02-threat-intel-tools.md) | backend | ✅ abuseipdb + otx + mitre + similar-events |
| 03 | [Agent loop](phase3-03-agent-loop.md) | backend | ✅ implemented |
| 04 | [WebSocket hub + auto-trigger](phase3-04-websocket-hub.md) | backend | ✅ implemented |
| 05 | [Frontend live incident UI](phase3-05-frontend.md) | web | ✅ hook + ticker + incident + intel + heatmap |
| 06 | [Hardening + E2E](phase3-06-hardening-e2e.md) | cross-cutting | ✅ log-sanitisation + Playwright E2E |

**Phase 3 is complete — every playbook feature is now implemented and tested.**
Each spec is self-contained and follows the five-section contract
(Title · Description · Instructions · Validation test · Acceptance criteria).

### Deliberate KISS deviations from the original playbook

- **MITRE tool** uses a small embedded ATT&CK subset instead of downloading the
  STIX bundle — offline, deterministic, testable (spec 02).
- **Incident page** is prop-driven, not routed by URL param: the app renders
  `Dashboard` directly with no active router, so a global overlay avoids a router
  migration (spec 05).
- **Playbook rendering** uses pre-wrapped text, not `react-markdown` — no new
  runtime dependency for an already-readable Markdown string (spec 05).
- **E2E tests** mock the API at the browser level (`page.route`) instead of
  booting the Go backend + a mock LLM, so the suite is deterministic and needs
  only Vite + Chromium. The app has no client router, so the playbook's
  "navigate to /search" is replaced by asserting the heatmap render (spec 06).

## Dependency graph

```
01 tool-system ──► 02 tools ──► 03 agent-loop ──► 04 ws-hub + auto-trigger ──► 05 frontend
```

Nothing in 01–03 needs Docker or real API keys — all networked pieces are behind
interfaces and covered by `httptest` mocks. 04 needs `gorilla/websocket`; 05 needs
the web toolchain.
