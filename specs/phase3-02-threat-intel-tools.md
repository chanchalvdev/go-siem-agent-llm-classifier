# Spec 3-02 — Threat-Intel Tools

## Title
Concrete tools: AbuseIPDB reputation, MITRE ATT&CK lookup, (later) AlienVault OTX.

## Description
Each tool implements the `Tool` interface from spec 01. They enrich an incident
with external context. Networked tools guard against SSRF (validate the IP/domain
first) and degrade gracefully when their API key is absent, so the agent still
runs in dev without every key configured.

## Instructions
Package `internal/agent/tools`. One file per tool, each ≤150 LOC, each with a test.

### `abuseipdb.go` — `AbuseIPDB`
- Name `check_abuseipdb`; schema `{"ip": string (required, IPv4/IPv6)}`.
- Constructor `NewAbuseIPDB(apiKey string, httpClient *http.Client)` — `baseURL`
  field defaults to the real endpoint but is overridable (test injects httptest).
- Behaviour:
  - Parse `ip` with `net.ParseIP`; invalid → error (SSRF guard).
  - RFC1918 / loopback / link-local → return
    `{"ip":"...","note":"private IP, skipping lookup"}` with **no** HTTP call.
  - Missing key → return `{"ip":"...","note":"ABUSEIPDB_KEY not set"}`, no call.
  - Else `GET {baseURL}?ipAddress={ip}&maxAgeInDays=90` with header `Key`,
    `Accept: application/json`. Non-2xx → wrapped error. Return compact JSON:
    `{"ip","abuse_score","country","isp","total_reports","last_reported"}`.
  - Track calls in an atomic counter; refuse past a 3000/day budget.

### `mitre.go` — `MITRELookup`
- Name `lookup_mitre`; schema `{"technique_id": string (e.g. T1110.001)}`.
- **KISS deviation from playbook:** ship a small embedded map of the ~20 techniques
  this SIEM actually classifies (id → name, tactic, detection). No network/STIX
  download — keeps the tool offline, deterministic, and testable. Unknown id →
  `{"technique_id":"...","note":"not in local ATT&CK subset"}`.
- Return `{"technique_id","technique","tactic","detection"}`.

### `otx.go` — `OTX` (pending, spec'd for later)
- Name `check_otx`; schema `{"indicator": string, "type": ip|domain|hash}`.
- Same graceful-degradation + injectable baseURL pattern as AbuseIPDB.

## Validation test
`abuseipdb_test.go` (uses `httptest.NewServer`):
1. Valid public IP → returned JSON has `abuse_score`, `country`, `total_reports`.
2. `10.0.0.1` → note returned, mock server records **zero** requests.
3. Upstream 429 → error returned and wrapped.
4. Malformed JSON body → error returned.
`mitre_test.go`: known id returns technique+tactic; unknown id returns the note.

## Acceptance criteria
- [ ] Each tool file ≤150 LOC with a matching `_test.go`.
- [ ] Private-IP path makes zero outbound requests (asserted).
- [ ] Missing-key path returns a note, never a panic or 500.
- [ ] `go test -race ./internal/agent/tools/` passes.
- [ ] No secrets in source; key read from env by the caller and passed in.
