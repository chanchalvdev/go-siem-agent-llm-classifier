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

## AI investigation, once per incident

With an LLM configured, the investigation agent runs when an incident **opens
as P1/P2** or **escalates into P1/P2** — not for every alert, so a
500-event brute force costs one investigation, not 500. The write-up streams
live to the dashboard and is saved in the incident timeline as an
`investigation` entry by `ai-agent`.

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
