# Spec 3-04 — WebSocket Hub + Auto-Trigger (pending)

## Title
Live incident streaming: WebSocket hub, streaming agent, P1/P2 auto-trigger.

## Description
Bridges the agent to the browser. A hub fans agent events out to connected
dashboards; a streaming variant of the loop emits tool-call / result / chunk /
done events; and every P1/P2 classification auto-launches an investigation whose
progress is broadcast in real time.

## Instructions
- `internal/api/hub.go` (≤150 LOC): `Hub` with `map[string]*websocket.Conn` under
  `sync.RWMutex`. `Register(conn) (id string)`, `Unregister(id)`,
  `Broadcast([]byte)`, `Send(id, []byte)`. Per-conn buffered `chan []byte` (256);
  non-blocking send drops on full buffer. Add `gorilla/websocket` to `go.mod`.
- `internal/api/ws_handler.go`: `handleAlertStream` upgrades, registers, and
  unregisters on disconnect. Route `GET /ws/alerts`.
- `internal/agent/stream.go` (≤150 LOC): `RunIncidentStream(..., send func(Event))`.
  `Event{Type, Data string}`; types `tool_call`, `tool_result`, `chunk`, `done`,
  `error`. Use `CreateChatCompletionStream` only for the final synthesis.
- Auto-trigger in `server.go`: after a successful `/classify`, if severity is
  P1/P2 spawn a goroutine running the stream, wrapping each event as
  `{incident_id, event_id, type, data}` and calling `hub.Broadcast`. Inject `Hub`
  and a `*Registry` into `Server` via a `ServerOption` (keep it nil-safe).

## Validation test
`internal/api/hub_test.go`: start `httptest.NewServer` with the WS route; connect
3 clients; `Broadcast` reaches all 3 within 1s; disconnect one, broadcast again,
other two still receive and no panic; `Send` reaches only the target id.

## Acceptance criteria
- [ ] Hub is race-clean under `-race` with concurrent register/broadcast/unregister.
- [ ] Full write buffer drops messages instead of blocking the broadcast.
- [ ] P1/P2 classify triggers exactly one investigation; P3–P5 trigger none.
- [ ] Auto-trigger is nil-safe when no hub/registry is wired.
