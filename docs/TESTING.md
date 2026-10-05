# Testing SIEMAgent

Two kinds of testing: **automated** (what CI runs) and a **hands-on
walkthrough** that exercises every feature with a prepared attack scenario.

## Automated tests

From the repository root:

```bash
make quality-gate        # gofmt, vet, golangci-lint, Go race tests, build,
                         # oxlint, TypeScript, Vitest, Vite build
make docker-up           # Postgres, Qdrant, Ollama
make test-integration    # store, incident, response and auth contracts on Postgres; Qdrant client
```

| Area | Where the tests live |
|---|---|
| Detection rules (every rule replays its own `samples`) | `siemagent/internal/detection/*_test.go` |
| Incidents, reports, AI briefs | `siemagent/internal/incident/*_test.go` |
| Playbooks, approvals, safety guards, webhook executor | `siemagent/internal/response/*_test.go` |
| Users, sessions, lockout, roles, audit | `siemagent/internal/auth/*_test.go` |
| HTTP API end to end (stub LLM, fake webhooks) | `siemagent/internal/api/*_test.go` |
| Dashboard pages and components | `siemagent/web/src/__tests__/` |

## Hands-on walkthrough

**Quickest path:** `make demo` starts Postgres, the API, the dashboard and a
stand-in containment webhook in Docker, replays the attack scenario below on
first start, and needs no API key (rules-only mode). Sign in at
http://localhost:3000 as `admin` / `siemagent-demo` and jump to step 4.
`make demo-test` checks a fresh demo end to end (CI runs it on every pull
request). In rules-only mode the lines no rule matches are stored as
*Unclassified* (P5) and there is no AI investigation; everything else below
behaves the same.

The steps below run the platform from source instead.

### 1. Start the platform

In `siemagent/.env` set an LLM (e.g. `GEMINI_API_KEY`, or `LLM_PROVIDER=ollama`)
and, to test logins, a first admin:

```env
SIEM_ADMIN_USER=admin
SIEM_ADMIN_PASSWORD=choose-12-or-more-chars
```

To see response actions really execute, point the containment webhook at
anything that accepts a POST, for example a throwaway listener:

```bash
# terminal 1: prints every action SIEMAgent sends
python3 -c "
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        print(self.rfile.read(int(self.headers['Content-Length'])).decode(), flush=True)
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
HTTPServer(('127.0.0.1', 9998), H).serve_forever()"
```

```env
RESPONSE_WEBHOOK_URL=http://127.0.0.1:9998/contain
```

Then:

```bash
cd siemagent
make docker-up
make dev        # backend :8080 + dashboard :5173
```

Wait for `SIEMAgent HTTP server starting` in the terminal and open
http://localhost:5173. If the dashboard says it cannot reach the backend,
read the terminal for a line starting with `error:` (a short
`SIEM_ADMIN_PASSWORD` is the usual one).

### 2. Sign in

Sign in with the admin from `.env`. The sidebar shows your name and role.

### 3. Replay the attack scenario

Click **Upload** and choose `siemagent/demo/attack-scenario.log`, or:

```bash
cd siemagent
python3 -c "import json;print(json.dumps({'logs':[l for l in open('demo/attack-scenario.log').read().splitlines() if l and not l.startswith('#')]}))" > /tmp/demo.json
curl -s -X POST localhost:8080/api/ingest -H 'Content-Type: application/json' \
  -H "X-API-Key: $KEY" -d @/tmp/demo.json | tail -1   # with SIEM_API_KEYS set
```

It contains three attacks plus background noise:

| Story | Lines | What should happen |
|---|---|---|
| SSH brute force → login → root shell on `web01` from `185.220.101.77` | 12 | 9 low (P4) failures, then the 10th fires the **SSH Brute Force** threshold rule (P2). The login and `sudo` root shell join the **same incident** |
| Port scan from `203.0.113.50` (10 ports) | 10 | **Port Scan From One Source** threshold rule fires on the 10th port |
| Shadow copies deleted on `app02` | 1 | **Shadow Copies Deleted** (P1) opens its own incident |
| Cron, a normal key-based login | 2 | Benign / low |

Rule matches are deterministic. Lines no rule matches are labelled by your
LLM, so their exact attack names and severities can vary.

### 4. Check every feature

**Events**: 25 events. Rule verdicts carry a **Rule** badge; the brute-force
crossing event lists the threshold detection with `10 events from
src_ip=185.220.101.77`.

**Rules** (admin): 16 rules, 4 of them threshold rules. Hit counts went up.
Turn a rule off and on again; it stays that way after a restart.

**Incidents**:
- `SSH Brute Force from 185.220.101.77`: kill chain shows **Credential
  Access** and **Privilege Escalation**; entities `ip`, `user:root`,
  `host:web01`; timeline with the threshold alert, the login and the root
  shell.
- `Shadow Copies Deleted on app02`: P1, tactic **Impact**.
- Set status **Investigating**, assign yourself, add a comment, then
  **Resolved** with resolution **True positive**. Each change appears in the
  timeline. Click `ip:185.220.101.77` to see every incident with that IP.
- With an LLM configured, an **AI investigation** appears in the timeline of
  the P1/P2 incidents (it streams live in the ticker). Click **Investigate with
  AI** to run it again; rate it **Helpful / Not helpful**.
- **Report** → preview and **Download .md**.

**Response**:
- Awaiting approval: `Block IP 185.220.101.77` (Contain brute-force source),
  `Isolate host app02` and a notify (Ransomware isolation).
- Recent actions: a **Dry run** notify for the P1 (Notify on critical incidents).
- **Approve and run** the block: the listener from step 1 prints the JSON
  (`"action":"block_ip","target":"185.220.101.77","approved_by":"admin"`) and
  the action shows **Succeeded**. **Reject** the isolation with a reason.
- Both decisions also appear in the incident timeline.

**Suppressions**: in the `SSH Brute Force` incident click **Snooze**, pick
`ip:185.220.101.77`, 24 hours, reason *testing*. The timeline notes it. Upload
the scenario again: the brute-force lines appear in **Events** with a
*Suppressed* badge, and the incident's alert count stays the same. The
**Suppressions** page shows the hits; **Lift** it and the IP alerts again.

**Users** (admin): add `viewer1` as **viewer** and `analyst1` as **analyst**.
Sign out, sign in as `viewer1`: incidents are read-only, no Upload, Classify,
Approve or Users/Audit. Back as admin, disable `viewer1`: their session ends
at once.

**Audit** (admin): logins (including failed ones and lockouts after 5 bad
passwords), user changes and every state-changing call, with user and IP.

**Analytics**: attack types, event-rate timeline and MITRE tactics include
the scenario.

### 5. Test ingestion over syslog

```env
SYSLOG_UDP_ADDR=:5514
```

```bash
logger -n 127.0.0.1 -P 5514 -d "Failed password for root from 203.0.113.9 port 22 ssh2"
```

The event appears in **Events** within a few seconds.

### 6. Start over

```bash
make docker-down
docker volume ls | grep siemagent   # remove the Postgres volume to wipe all data
```

Without `POSTGRES_DSN` everything lives in memory, so a restart is a clean
slate.
