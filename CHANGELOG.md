# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Releases are cut by pushing a
`vX.Y.Z` tag, which builds the binaries and container images
(see `.github/workflows/release.yml`).

## [Unreleased]

### Added
- IOC watchlists: IPs, ranges, domains and file hashes from threat feeds
  (refreshed on a schedule), list files (`IOC_WATCHLIST_DIR`) or analysts.
  A match adds a detection, raises the severity and can open an incident.
  Includes a Watchlists page, indicator lookup and the demo flags the
  brute-force source as a Tor exit.

## [0.1.0] - unreleased

First public release: an open-source AI security operations platform, from
raw log line to resolved incident.

### Added

**Get started**
- One-command demo: `make demo` runs Postgres, the API, the dashboard and a
  stand-in containment webhook in Docker. It needs no API key and replays an
  attack scenario on first start. CI smoke-tests it on every pull request.
- Rules-only mode (`LLM_PROVIDER=none`): detection without any LLM. Events no
  rule matches are stored as *Unclassified*.
- `SEED_LOG_FILE` replays a log file through the pipeline on first start.

**Ingest and detect**
- Syslog listener (UDP/TCP) with back-pressure. HTTP classify, streaming
  classify and bulk ingest (up to 500 lines). Dashboard file upload.
- Parsers for RFC 5424, RFC 3164 (with or without `<PRI>`), rsyslog ISO
  timestamps, JSON, and a raw fallback.
- In-house Sigma engine with a built-in rule pack; SigmaHQ rules load from
  `SIGMA_RULES_DIR`. Rules-first by default, so rule matches skip the LLM.
- Threshold rules (`count() by` over a time window): SSH brute force, password
  spraying, web content discovery, port scan.
- Rule management: enable or disable a rule (persisted) and see hit counts.

**Classify and investigate**
- LLM classification through Gemini, local Ollama or any OpenAI-compatible
  API. Output covers attack type, severity P1–P5, MITRE ATT&CK, IOCs and
  remediation. If the LLM fails, the rule verdict is used instead.
- Incidents: alerts correlated by shared IP, user or host within a time
  window. Includes a kill-chain view, case management (status, assignee,
  resolution, comments), an entity view and an append-only timeline.
- AI investigation of whole incidents: a tool-calling agent (AbuseIPDB, OTX,
  MITRE, similar events) writes a cited report. It runs once when an incident
  opens as or escalates to P1/P2, or on demand. Analysts rate it.
- Markdown incident reports.
- Semantic search over event embeddings (Ollama + Qdrant).
- Suppressions: snooze a noisy entity, rule or attack type for a while.
  Matching events are stored but open no incident.

**Respond**
- YAML response playbooks. They propose `block_ip`, `disable_user`,
  `isolate_host`, `notify` (Slack) and `webhook` actions, and support approval,
  dry-run and auto modes. Safety guards prevent blocking private IPs or
  disabling built-in accounts. Containment goes through one webhook to your
  own automation.

**Operate**
- Local user accounts with roles (viewer, analyst, admin), bcrypt, hashed
  session tokens, lockout and CSRF protection. API keys for machine access.
- Audit log of logins and every change.
- PostgreSQL storage with an in-memory fallback.
- Versioned, checksummed schema migrations. `siemagent --migrate` runs them
  as a separate deploy step.
- Data retention for events, resolved incidents and the audit log (off by
  default).
- Prometheus metrics, `/health` and `/health/ready` probes, an OpenAPI
  reference at `/docs`.
- Responsive React dashboard with light and dark themes.

**Project**
- MIT license, contributing guide, security policy, code of conduct.
- Branch and PR conventions with git hooks.
- CI covering Go, web, Postgres/Qdrant integration, CodeQL, govulncheck,
  npm audit, secret scanning and the demo.
- Release workflow: binaries, plus GHCR images with provenance and SBOM.

### Security
- Untrusted log text is stripped of control characters before logging and in
  API responses. AI prompts fence log text as evidence (prompt-injection
  defence).
- API keys are compared with HMAC-SHA256 under a per-process key.
- Webhook URLs are never returned by the API or stored with actions.

[Unreleased]: https://github.com/chanchalvdev/go-siem-agent-llm-classifier/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/chanchalvdev/go-siem-agent-llm-classifier/releases/tag/v0.1.0
