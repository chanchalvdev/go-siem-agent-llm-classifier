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

- Set `SIEM_API_KEYS`. Without it the API, WebSocket and metrics are open to
  anyone who can reach the server.
- `VITE_SIEM_API_KEY` is compiled into the dashboard bundle. Treat it as visible
  to every dashboard user, and put a shared deployment behind SSO or a VPN.
- Keep Qdrant, Ollama and Postgres on a private network; they have no auth in
  the default `docker-compose.yml`.
- Logs sent to a hosted LLM (Gemini, OpenAI-compatible) leave your network.
  Use `LLM_PROVIDER=ollama` when that is not acceptable.
- The syslog listener is unauthenticated, like syslog itself. Bind it to a
  trusted interface or firewall it to known senders.
