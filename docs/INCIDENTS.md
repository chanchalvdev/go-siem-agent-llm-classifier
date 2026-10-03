# Incidents and case management

Analysts work incidents, not log lines. SIEMAgent groups related alerts into
**incidents** automatically, and gives each one a case: status, owner,
resolution, comments and a full history.

## How alerts become incidents

Every classified event at or above `INCIDENT_MIN_SEVERITY` (default **P3**)
is an alert. For each alert SIEMAgent extracts its **entities**:

| Entity | From |
|---|---|
| `ip` | the source IP (`from <ip>`, `SRC=`, `ip=`, client IP of access logs, JSON `source.ip`…) |
| `user` | the account (`for <user> from`, `user=`, JSON `user.name`…) |
| `host` | the host that logged the event |

If an **open** incident shares any entity with the alert and was active within
`INCIDENT_WINDOW` (default **1h**), the alert joins it; otherwise a new
incident opens. Alerts with no entity at all are grouped by attack type.

A typical intrusion therefore reads as one incident:

```
10:00  SSH Brute Force from 185.220.101.77        (threshold rule, P2)  → opens INC-2EA4C98D
10:05  Accepted password for root from 185.220.101.77  (same IP)        → joins
10:06  sudo to a root shell on web01                    (same host/user) → joins, escalates
```

As alerts join, the incident keeps:

- **Severity**: the highest alert severity. When an alert raises it, the
  incident is retitled after that alert and an `escalated` entry is recorded.
- **Kill chain**: the ATT&CK tactics reached, in matrix order, so you can see
  how far the attacker progressed.
- **Entities, techniques and alert count**. The first 500 alert snapshots are
  stored per incident; the count keeps going after that.

Resolved incidents never absorb new alerts: activity after resolution opens a
new incident, so a re-attack is never hidden inside a closed case.

## AI investigation of the whole incident

With an LLM configured, the investigation agent runs automatically when an
incident **opens as P1/P2** or **escalates into P1/P2**, not for every alert,
so a 500-event brute force costs one investigation, not 500. Click
**Investigate with AI** (or `POST /api/incidents/{id}/investigate`) to run it
again at any time, for example after more alerts arrived or you added context
in a comment. Only one investigation per incident runs at a time, and at most
four run at once overall.

The agent receives the **whole incident**: title, severity, entities, kill
chain, the alerts (the first and most recent 40, each raw line capped at 600
bytes) numbered `A1`, `A2`, … and the latest analyst comments. It can call its
tools (AbuseIPDB, OTX, similar past events, MITRE lookup) and then writes:

- **Executive Summary**: what happened, how bad, what to do now
- **Timeline**: citing alerts as `[A1]`, `[A3]`
- **Impact** and **Root Cause**: based only on the evidence
- **Recommended Actions**: numbered, most urgent first
- **Evidence**: the facts and tool results it relied on

Log lines are attacker-controlled, so the prompt tells the model to treat
alerts and comments strictly as evidence and never follow instructions inside
them. The write-up streams live to the dashboard and is saved in the timeline
as an `investigation` entry by `ai-agent`.

### Rating investigations

Under the latest AI investigation, mark it **Helpful** or **Not helpful**
(`POST /api/incidents/{id}/feedback` with `{"helpful": true, "note": "..."}`).
Ratings are recorded in the case history and counted in
`ai_investigation_feedback_total{rating}`, so you can track AI quality over
time.

## Incident report

**Report** (or `GET /api/incidents/{id}/report`, add `?download=1` for a file)
produces a self-contained Markdown report for hand-off or post-incident
review:

1. Case facts: severity, status, resolution, assignee, times, time to resolve, entities
2. The latest AI investigation (or a factual summary if none ran)
3. Kill chain checklist and techniques
4. Every stored alert in a table numbered `A1…`, so the AI's citations can be
   checked, followed by the raw log lines
5. The full case history: comments, status changes, investigations

Text from logs, comments and the LLM is escaped so it cannot inject HTML,
links or remote images into the rendered report.

## Working a case

In the dashboard open **Incidents**:

- Filter by status (Open, New, Investigating, Resolved, All). Click an entity
  chip in an incident to see every incident involving that IP, user or host.
- Set the **status** (new → investigating → resolved), **assignee** and, once
  resolved, the **resolution**: true positive, false positive, benign or
  duplicate. Reopening a resolved incident clears its resolution.
- Add **comments** with findings and actions taken.
- The **timeline** shows alerts, comments, AI investigations and every change,
  newest first. History is append-only.

The queue header shows open incidents, open P1/P2, resolved count and **mean
time to resolve** (creation to resolution).

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/incidents?status=&severity=&assignee=&entity=ip:1.2.3.4&limit=100` | List, most recently active first |
| `GET` | `/api/incidents/stats` | Open/resolved counts, open by severity, false positives, MTTR |
| `GET` | `/api/incidents/{id}` | Incident with alerts and history |
| `PATCH` | `/api/incidents/{id}` | `{"status","assignee","severity","resolution"}` (any subset) |
| `POST` | `/api/incidents/{id}/comments` | `{"body": "..."}` |
| `POST` | `/api/incidents/{id}/investigate` | Start an AI investigation (202; 409 if one is running; 503 without an LLM) |
| `GET` | `/api/incidents/{id}/report` | Markdown report (`?download=1` for an attachment) |
| `POST` | `/api/incidents/{id}/feedback` | `{"helpful": true, "note": "..."}` on the latest investigation |

```bash
curl -X PATCH -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"status":"resolved","resolution":"false_positive"}' \
  http://localhost:8080/api/incidents/INC-2EA4C98D
```

Until user accounts exist, changes are recorded as `analyst`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `INCIDENT_WINDOW` | `1h` | How long an incident keeps absorbing alerts after its last one (1m–168h) |
| `INCIDENT_MIN_SEVERITY` | `P3` | Least severe alert that opens or joins an incident |

Incidents are stored in Postgres (`incidents`, `incident_entities`,
`incident_alerts`, `incident_activity`) when `POSTGRES_DSN` is set, otherwise
in memory.

## Limits

- Correlation is serialised inside one process. Several API replicas sharing
  one database could open duplicate incidents for simultaneous alerts.
- Host is a correlation key, so on a busy host unrelated alerts inside the
  window share an incident. Lower `INCIDENT_WINDOW` if that is too coarse.

## Metrics

| Metric | Meaning |
|---|---|
| `incidents_created_total{severity}` | Incidents opened |
| `incident_alerts_correlated_total` | Alerts that joined an existing incident |
| `incidents_resolved_total{resolution}` | Incidents resolved |
| `ai_investigation_feedback_total{rating}` | Analyst ratings of AI investigations |
