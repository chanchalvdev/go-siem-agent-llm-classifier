# Spec 3-05 — Frontend Live Incident UI (pending)

## Title
Real-time incident dashboard: alert stream hook, ticker, incident detail, intel cards.

## Description
Surfaces the streaming agent in the React app. A single WebSocket hook feeds a
top-of-app alert ticker and a per-incident detail page that renders the agent's
tool timeline and streaming playbook as it arrives.

## Instructions
Each component ≤150 LOC with a matching `src/__tests__/*.test.tsx`. Reuse existing
`SeverityBadge`, `MITREBadge`, and `lib/api.ts` types (DRY).
- `web/src/hooks/useAlertStream.ts`: opens `ws://<host>/ws/alerts`; exponential
  backoff reconnect (1→2→4…max 30s); returns `{ connected, incidents:
  Map<string, Incident>, latestEvent }`; `clearIncident(id)`. `Incident`
  accumulates events by `incident_id`, assembling the playbook from `chunk`s.
- `web/src/components/AlertTicker.tsx`: fixed banner of active P1/P2 incidents;
  P1 badge pulses; "Investigating…" spinner → "Playbook ready" ✓ on `done`;
  click routes to detail; auto-dismiss non-critical after 10s.
- `web/src/pages/Incident.tsx`: left 40% original event, right 60% collapsible
  tool-call timeline + streaming playbook via `react-markdown`; "Copy Playbook";
  status chip Investigating/Enriching/Synthesizing/Complete/Failed.
- `web/src/components/ThreatIntelPanel.tsx`: cards from `check_abuseipdb` /
  `check_otx` results (abuse-score gauge, country, ISP, pulse count); placeholder
  when none.

## Validation test
Vitest + Testing Library: mock a WebSocket, push a scripted event sequence
(`tool_call` → `tool_result` → `chunk`×N → `done`) and assert the ticker shows
"Playbook ready", the timeline lists the tool call, and the playbook text is the
concatenated chunks. Component tests for `ThreatIntelPanel` cover the empty state.

## Acceptance criteria
- [ ] `npm run lint` (oxlint) and `tsc -b` clean; `vitest run` green.
- [ ] Hook reconnects after a dropped socket (fake-timer test).
- [ ] No `console.log` in production paths; TanStack Query for any REST calls.
- [ ] Ticker and detail update live from a single shared hook instance.
