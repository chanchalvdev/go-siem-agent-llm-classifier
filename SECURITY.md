# Security Policy

This project processes security logs, so we take vulnerabilities in it seriously.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub:
open the repository's **Security** tab and choose **Report a vulnerability**.

Include what you can of:

- the affected component (API, agent, syslog listener, dashboard…) and version or commit
- steps to reproduce, or a proof of concept
- the impact you expect (data exposure, auth bypass, injection…)

We aim to acknowledge reports within 3 working days and to agree on a fix and
disclosure timeline with you. Reporters are credited unless they ask not to be.

## Supported versions

Only the latest `master` receives security fixes until versioned releases begin.

## Deploying safely

- Create user accounts (`SIEM_ADMIN_USER` / `SIEM_ADMIN_PASSWORD`, then the
  Users page) and/or set `SIEM_API_KEYS`. With neither, the API, WebSocket
  and metrics are open to anyone who can reach the server.
- Serve the dashboard over HTTPS and set `SIEM_COOKIE_SECURE=true` so the
  session cookie is never sent in clear text.
- Prefer user logins over `VITE_SIEM_API_KEY` for people: that key is compiled
  into the dashboard bundle, is visible to every dashboard user and acts as an
  admin. Keep API keys for scripts and integrations.
- Give people the least role they need (viewer, analyst, admin) and review
  the audit log.
- `RESPONSE_WEBHOOK_URL` and `SLACK_WEBHOOK_URL` carry secrets; keep them in
  `.env` only.
- Keep Qdrant, Ollama and Postgres on a private network; they have no auth in
  the default `docker-compose.yml`.
- Logs sent to a hosted LLM (Gemini, OpenAI-compatible) leave your network.
  Use `LLM_PROVIDER=ollama` when that is not acceptable.
- The syslog listener is unauthenticated, like syslog itself. Bind it to a
  trusted interface or firewall it to known senders.
