# Roadmap — from SIEM agent to open-source AI SOC platform

## Vision

An open-source platform that takes a security team from raw logs to a resolved
incident:

```
Ingest  →  Detect  →  Correlate  →  Investigate (AI)  →  Respond  →  Report
```

Open-source SIEMs (Wazuh, Security Onion, Elastic) already collect and search
logs well. What none of them do well is the analyst's work *after* an alert
fires — triage, enrichment, investigation, write-up. That is where this
project's LLM agent stands out, so the platform is built around it.

## Principles

1. **Rules first, AI where it adds value.** Deterministic detections catch the
   known threats cheaply; the LLM triages, correlates and explains. Sending
   every log line to an LLM does not scale in cost or latency.
2. **Integrate, don't rebuild.** Mature open-source tools exist for endpoint
   telemetry, network monitoring and scanning. We ingest their output instead
   of writing our own agents and scanners.
3. **Local-first and private by default.** Every AI feature must work with a
   local model (Ollama) so logs never have to leave the network.
4. **Humans approve actions.** Automated response proposes; a person approves,
   until a playbook is explicitly trusted to run on its own.
5. **Measured, not assumed.** AI output quality is tracked with an evaluation
   set, the same way code quality is tracked with tests.

## Status

| Phase | Theme | Status |
|---|---|---|
| 1 | Core classifier: parsing, LLM classification, MITRE mapping | ✅ Done |
| 2 | RAG: embeddings, Qdrant semantic search, analytics | ✅ Done |
| 3 | Investigation agent: threat-intel tools, live incident stream | ✅ Done |
| 4 | Platform foundations | ✅ Done |
| 5 | Detection engine | 🚧 In progress |
| 6 | Incidents and case management | Planned |
| 7 | AI investigation 2.0 | Planned |
| 8 | Response and automation | Planned |
| 9 | Multi-user, RBAC and multi-tenancy | Planned |
| 10 | Advanced analytics and hunting | Planned |
| — | Integrations (ongoing track) | Planned |
| — | AI quality and cost (ongoing track) | Planned |
| — | Operations and distribution (ongoing track) | Planned |

---

## Phase 4 — Platform foundations ✅

What had to exist before the platform could be used, trusted and open-sourced.

- [x] PostgreSQL event persistence with in-memory fallback; `GET /api/events`
- [x] API key authentication on API, WebSocket and metrics
- [x] Local LLM option (`LLM_PROVIDER=ollama`) alongside Gemini and OpenAI-compatible APIs
- [x] Syslog UDP/TCP listener with back-pressure and drop metrics
- [x] CI on every pull request (Go, web, Postgres + Qdrant integration tests)
- [x] Open-source basics: license, contributing guide, security policy, templates

## Phase 5 — Detection engine

Catch known-bad activity with rules, so the LLM is reserved for what rules miss.

- [x] **Sigma rule engine** — load community [Sigma](https://github.com/SigmaHQ/sigma)
      rules (3,000+) and evaluate them against every event (single-event
      rules; aggregations still to come — see [docs/DETECTION.md](docs/DETECTION.md))
- [ ] **Field normalisation** — map parsed logs onto a common schema
      (ECS or OCSF) so one rule works across log sources
- [x] **Rule-first pipeline** — rule matches create alerts directly; only
      unmatched or ambiguous events go to the LLM (big cost/latency reduction)
- [x] **Detection-as-code** — custom rules in git, with tests that replay
      sample logs against them
- [ ] **Aggregation rules** — `count() by` thresholds over time windows
      (e.g. 20 failed logins from one IP in 5 minutes)
- [ ] **Rule management UI** — enable/disable, tune thresholds, see hit counts
      and false-positive rates
- [ ] **IOC watchlists** — match IPs, domains and hashes from threat feeds
      (MISP, OTX, abuse.ch) in real time

## Phase 6 — Incidents and case management

Analysts work incidents, not log lines.

- [ ] **Correlation engine** — group related alerts into one incident by
      entity (host, user, IP) and time window, e.g. brute force → successful
      login → privilege escalation
- [ ] **Kill-chain view** — place an incident's alerts on the MITRE ATT&CK
      chain to show how far an attacker progressed
- [ ] **Case management** — assign, status (new / investigating / resolved),
      severity, comments, evidence attachments, full audit history
- [ ] **Deduplication and suppression** — collapse repeats, snooze noisy
      sources, alert fatigue metrics
- [ ] **Entity pages** — everything known about a host, user or IP in one place
- [ ] **Incident timeline** — chronological view across all related events

## Phase 7 — AI investigation 2.0

Turn the existing agent into an analyst that works on whole incidents.

- [ ] **Incident-level investigation** — the agent investigates the
      correlated incident, not just a single event
- [ ] **Natural-language hunting** — "failed logins from new countries this
      week" becomes a query over stored events, with the generated query shown
- [ ] **Investigation reports** — executive summary, timeline, impact, root
      cause and recommended actions, exportable as Markdown/PDF
- [ ] **Analyst feedback loop** — mark a verdict right or wrong; feedback
      tunes prompts and suppressions and feeds the evaluation set
- [ ] **More enrichment tools** — VirusTotal, Shodan, GreyNoise, WHOIS,
      passive DNS, internal asset inventory lookups
- [ ] **Explainability** — every AI verdict cites the events and tool results
      it relied on

## Phase 8 — Response and automation (SOAR)

From finding to fixing.

- [ ] **Playbook engine** — declarative playbooks (YAML) triggered by
      detections or incident types
- [ ] **Response actions** — block IP (firewall / cloud security group),
      disable user (Active Directory / Okta / Entra ID), isolate host,
      revoke sessions, quarantine file
- [ ] **Human-in-the-loop approvals** — actions are proposed with the AI's
      reasoning; one click approves, everything is audited
- [ ] **Notifications and ticketing** — Slack, Microsoft Teams, email,
      PagerDuty, Jira, ServiceNow
- [ ] **Dry-run mode** — show what a playbook would have done, before trusting it

## Phase 9 — Multi-user, RBAC and multi-tenancy

Required before teams or MSSPs can share one deployment.

- [ ] **User accounts and SSO** — OIDC/SAML (Okta, Entra ID, Google)
- [ ] **Roles** — admin, analyst, read-only; per-action permissions
- [ ] **Audit log** — who saw, changed or approved what, and when
- [ ] **Multi-tenancy** — isolated data per tenant (Postgres schemas, Qdrant
      collections) for managed security providers
- [ ] **Retention policies** — per-tenant TTLs and archival to object storage

## Phase 10 — Advanced analytics and hunting

- [ ] **UEBA / anomaly detection** — baselines per user and host; flag
      unusual logins, data volumes and process activity
- [ ] **Threat-hunting workbench** — saved hunts, notebooks, pivoting between
      entities
- [ ] **Compliance reporting** — evidence mapped to SOC 2, ISO 27001, PCI DSS,
      HIPAA controls
- [ ] **Deception** — lightweight honeypots and honeytokens whose any touch is
      a high-confidence alert
- [ ] **Dashboards** — SOC metrics: MTTD, MTTR, alert volume, analyst workload

---

## Integrations (ongoing track)

Each integration is a connector that turns another tool's output into events.
One connector per release keeps quality high. Good first targets:

| Category | Source | What it adds |
|---|---|---|
| Network | Suricata (EVE JSON), Zeek | Network intrusion detection, connection metadata |
| Endpoint | osquery, Wazuh agent, Sysmon via Windows Event Forwarding | Process, file and login telemetry |
| Cloud | AWS CloudTrail, GuardDuty; Azure Activity; GCP Audit Logs | Cloud control-plane activity |
| Containers | Falco, Kubernetes audit logs | Runtime threats in clusters |
| Identity | Okta, Entra ID sign-in logs | Account takeover, impossible travel |
| Vulnerabilities | Trivy, Nuclei | Asset risk context for prioritisation |
| Cloud posture | Prowler | Misconfiguration findings |
| Transport | Webhooks (generic JSON), Kafka / NATS, Fluent Bit / Vector | Ingest from any pipeline |

## AI quality and cost (ongoing track)

- [ ] **Evaluation set** — labelled log samples with expected attack type,
      severity and MITRE technique; accuracy tracked in CI per model
- [ ] **Model comparison** — run the eval across Gemini, OpenAI-compatible
      and local models to pick defaults with data
- [ ] **Caching** — identical or near-identical events reuse a verdict
- [ ] **Budgets** — per-tenant token limits and cost metrics
- [ ] **Prompt-injection defences** — logs are attacker-controlled input; keep
      hardening how they reach the LLM and the agent's tools

## Operations and distribution (ongoing track)

- [ ] **One-command demo** — `docker compose up` with sample attack data
      preloaded, so a new user sees an investigated incident within minutes
- [ ] **Container images** published on every release; Helm chart for Kubernetes
- [ ] **Versioned releases** with changelog and signed binaries
- [ ] **Versioned schema migrations** (replace the start-up schema file)
- [ ] **OpenTelemetry tracing** across ingest → classify → investigate
- [ ] **Documentation site** — install, configuration, writing rules,
      writing connectors, API reference
- [ ] **Project name** — "siemagent" undersells a SOC platform; choose a name
      before the first public release

## Deliberately not building

| Not building | Instead |
|---|---|
| Our own endpoint agent (EDR) | Ingest osquery, Wazuh agent, Sysmon |
| Our own vulnerability scanner | Ingest Trivy and Nuclei |
| Our own cloud posture scanner | Ingest Prowler |
| A general log analytics/search engine | Store what detection and investigation need; integrate with existing log stores |

## How to help

Pick an unchecked item, open an issue to discuss the approach, then follow
[CONTRIBUTING.md](CONTRIBUTING.md). Integrations and Sigma-rule test content
are the easiest places to start.
