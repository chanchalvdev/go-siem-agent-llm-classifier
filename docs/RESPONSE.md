# Response playbooks

Finding an attack is half the job. Playbooks turn an incident into concrete
response actions (block the attacker's IP, disable a compromised account,
isolate a host, tell the team) while keeping a person in charge.

## Principles

- **Humans approve actions.** By default a playbook only *proposes*; an
  analyst approves each action before it runs.
- **Dry run first.** A `dry_run` playbook records what it would have done, so
  you can watch it on real incidents before trusting it.
- **Everything is audited.** Each proposal, approval, rejection and result is
  written to the incident timeline with who did it.
- **Safe by default.** `block_ip` never targets private, loopback or reserved
  addresses (your own network), and `disable_user` never targets built-in
  accounts such as `root` or `Administrator`, unless a playbook opts in
  (`allow_private_ips: true`) for IPs.

## How it works

```
alert ──▶ incident (opened / joined) ──▶ playbooks whose trigger matches
                                              │
               ┌──────────────────────────────┼──────────────────────┐
               ▼                              ▼                      ▼
        mode: approval                 mode: dry_run            mode: auto
     action is "pending" ──▶       recorded, never run       runs immediately
     analyst approves / rejects
               │
               ▼
        executor ──▶ RESPONSE_WEBHOOK_URL / Slack / webhook ──▶ result recorded
```

Each playbook step is proposed once per incident and target, so a long attack
doesn't flood the approval queue.

## Approving actions

- **Response** tab: every action awaiting approval across incidents, recent
  results, and the loaded playbooks with their triggers.
- **Incident → Response**: that incident's actions, plus **Run playbook** to
  apply any playbook to it by hand (its mode still applies).

**Approve and run** executes immediately and shows the result; **Reject**
takes an optional reason. Only pending actions can be decided; a second
click on an already-decided action is refused.

## Built-in playbooks

| Playbook | When | Then | Mode |
|---|---|---|---|
| Contain brute-force source | P2+ with technique T1110 (brute force, spraying) | block_ip | approval |
| Contain compromised account | P1 with Privilege Escalation or Lateral Movement | disable_user, isolate_host | approval |
| Ransomware isolation | P1 with tactic Impact | isolate_host, notify | approval |
| Notify on critical incidents | any P1 | notify | dry_run |

## Writing a playbook

Put `.yml` files in `PLAYBOOKS_DIR`. IDs must be unique (built-ins load
first and win).

```yaml
id: block-web-scanners
name: Block web scanners
description: Block clients running directory brute-force tools.
mode: approval            # approval (default) | dry_run | auto
enabled: true
trigger:                  # every set field must match; lists match any element
  min_severity: P3        # incident severity or worse
  tactics: [Reconnaissance]
  techniques: [T1595]     # T1595 also matches T1595.003
  attack_types: [scan]    # substring of the alert's attack type or rule title
actions:
  - type: block_ip        # one action per IP entity in the incident
  - type: notify
    message: "Blocked scanner on {{entities}} for {{title}} ({{id}}, {{severity}})"
```

| Action | Acts on | Sent to |
|---|---|---|
| `block_ip` | each `ip` entity | `RESPONSE_WEBHOOK_URL` |
| `disable_user` | each `user` entity | `RESPONSE_WEBHOOK_URL` |
| `isolate_host` | each `host` entity | `RESPONSE_WEBHOOK_URL` |
| `notify` | the incident | `SLACK_WEBHOOK_URL` (`{"text": message}`) |
| `webhook` | the incident | the action's own `url` (incident JSON) |

`message` placeholders: `{{title}}`, `{{severity}}`, `{{id}}`, `{{entities}}`,
`{{status}}`.

## Connecting your tools

SIEMAgent doesn't ship firewall, IdP or EDR integrations of its own. Approved
containment actions are POSTed as JSON to `RESPONSE_WEBHOOK_URL`, and your
automation does the work: an n8n, Tines or Shuffle workflow, an Ansible AWX
job template, a cloud function calling your firewall or Okta or Entra ID, and
so on.

```json
{
  "action": "block_ip",
  "target": "185.220.101.77",
  "action_id": "ACT-ED461BC5",
  "incident_id": "INC-DC69CE84",
  "incident_title": "SSH Brute Force from 185.220.101.77",
  "severity": "P2",
  "playbook": "contain-brute-force-source",
  "approved_by": "alice"
}
```

Any 2xx answer counts as success, and the first 512 bytes of the body are
recorded as the result. Other statuses, timeouts (10 s) and connection errors
mark the action **failed** with the reason. Redirects are not followed, and
webhook URLs (which may contain tokens) are never stored with actions,
returned by the API or written to errors.

## Configuration

| Variable | Purpose |
|---|---|
| `PLAYBOOKS_DIR` | Extra playbooks (`.yml`, searched recursively) |
| `RESPONSE_WEBHOOK_URL` | Receives approved `block_ip` / `disable_user` / `isolate_host` |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook for `notify` |

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/playbooks` | Loaded playbooks |
| `GET` | `/api/response/actions?status=pending&incident=INC-…&limit=200` | Actions, newest first |
| `POST` | `/api/response/actions/{id}/approve` | Approve and run (returns the final state) |
| `POST` | `/api/response/actions/{id}/reject` | `{"reason": "..."}` (optional) |
| `POST` | `/api/incidents/{id}/playbooks/{playbook}/run` | Propose a playbook's actions for an incident |

## Limits

- Approvals are serialised within one process; with several API replicas,
  run a single instance for approvals until a shared lock exists.
- Until user accounts exist, approvals are recorded as `analyst`.

## Metrics

`response_actions_total{type,status}` counts every state change: proposed
(`pending`, `dry_run`, `running`), `succeeded`, `failed` and `rejected`.
