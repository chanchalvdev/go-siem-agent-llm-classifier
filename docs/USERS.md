# Users, roles and the audit log

SIEMAgent supports named user accounts with roles, browser login sessions and
an audit log of who did what. API keys keep working for machines.

## Roles

| Role | Can |
|---|---|
| **viewer** | Read everything: events, incidents, reports, rules, playbooks, actions |
| **analyst** | Viewer, plus classify and upload logs, work incidents (status, assignee, comments), run AI investigations, rate them, run playbooks, approve and reject response actions |
| **admin** | Analyst, plus enable and disable detection rules, manage users, read the audit log |

The server enforces roles on every route. The dashboard also hides what a
role can't do; for example, viewers see incidents read-only.

## How authentication works

| Caller | Credential | Identity in history and audit |
|---|---|---|
| A person in the dashboard | Username and password → session cookie | their username |
| A script or integration | API key (`SIEM_API_KEYS`) | `api-key-N` (its position in `SIEM_API_KEYS`), acts as admin |
| Nobody configured | none: **open mode**, everything allowed | `analyst` |

Open mode only applies when there are **no API keys and no user accounts**.
It exists for local development; the server logs a warning at start.

## First admin

Set these in `siemagent/.env` and start the server once:

```env
SIEM_ADMIN_USER=admin
SIEM_ADMIN_PASSWORD=<12+ characters>
```

The admin is created only if no user exists yet, so the variables are
harmless afterwards, but remove the password from the environment once you've
logged in. Add everyone else from **Users** in the dashboard.

## Managing users

Admins can, from **Users** or `/api/users`:

- add a user with a role and an initial password
- change a role (applies to existing sessions immediately)
- disable or enable an account (disabling ends its sessions at once)
- reset a password (ends the user's sessions)

Accounts are never deleted, so the audit history always resolves to a person.
The **last active admin cannot be demoted or disabled**, so a deployment can't
lock itself out. Users change their own password with
`POST /api/auth/password`.

## Security details

- **Passwords** are bcrypt hashes (cost 12), 12–72 characters
  ([NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) length
  guidance; no composition rules).
- **Login failures** return the same error for unknown users, wrong passwords
  and disabled accounts, and take the same time. After **5 failures in 15
  minutes** a username is locked for the rest of the window (HTTP 429). The
  login endpoint is also rate-limited per IP.
- **Sessions** are 256-bit random tokens. The database stores only their
  SHA-256 hash. The cookie is `HttpOnly` and `SameSite=Strict`, and `Secure`
  over HTTPS or with `SIEM_COOKIE_SECURE=true` (set it behind a TLS proxy).
  Sessions last `SIEM_SESSION_TTL` (default 12h).
- **CSRF**: state-changing requests authenticated by the cookie must send
  `X-Requested-With`. Other sites can't add that header without a CORS
  preflight, which only `ALLOWED_ORIGIN` passes. The dashboard sends it
  automatically.
- **WebSocket** `/ws/alerts` authenticates with the session cookie (same
  origin) or `?api_key=` for API-key clients.

## Audit log

**Audit** (admin) lists, newest first:

- logins, failed logins, lockouts and logouts, with the client IP
- every state-changing API call: user, method and route, resource path and
  HTTP status (high-volume ingestion routes such as `/api/classify` and
  `/api/ingest` are left out)
- account changes, described (e.g. `vic: role viewer→analyst, disabled`)

Incident-specific history (status changes, comments, approvals) stays in
each incident's timeline as well. The audit log is stored in Postgres
(`audit_log`) or, without a database, the last 10,000 entries in memory.

## API

| Method | Path | Who | Purpose |
|---|---|---|---|
| `POST` | `/api/auth/login` | anyone | `{"username","password"}` → session cookie |
| `POST` | `/api/auth/logout` | signed in | End the session |
| `GET` | `/api/auth/me` | signed in | Username, role, auth kind, permissions |
| `POST` | `/api/auth/password` | signed in | `{"current_password","new_password"}` |
| `GET` | `/api/users` | admin | List accounts |
| `POST` | `/api/users` | admin | `{"username","password","role","display_name"}` |
| `PATCH` | `/api/users/{id}` | admin | `{"role","disabled","password","display_name"}` |
| `GET` | `/api/audit?actor=&limit=200` | admin | Audit log, newest first |

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SIEM_ADMIN_USER` / `SIEM_ADMIN_PASSWORD` | — | Bootstrap the first admin (both or neither) |
| `SIEM_SESSION_TTL` | `12h` | Login lifetime (5m–720h) |
| `SIEM_COOKIE_SECURE` | `false` | Mark the session cookie `Secure` |
| `SIEM_API_KEYS` | — | Machine access (admin) |

## Not yet

Single sign-on (OIDC/SAML), multi-factor authentication and multi-tenancy
are on the [roadmap](../ROADMAP.md).
