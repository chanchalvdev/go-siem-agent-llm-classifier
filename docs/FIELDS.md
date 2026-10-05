# Normalised fields

Every event carries a `fields` map that puts what the log says under one set
of names, a subset of the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)
(ECS). A failed SSH login, a failed login in a JSON application log and a
Windows logon failure all end up with `event.category: authentication`,
`event.outcome: failure`, `user.name` and `source.ip`. So one detection rule,
one watchlist and one incident correlation key work across every log source.

```json
"event": {
  "raw": "<38>Oct  5 10:00:01 web01 sshd[4211]: Failed password for root from 203.0.113.7 port 52344 ssh2",
  "fields": {
    "event.category": "authentication", "event.action": "ssh_login", "event.outcome": "failure",
    "event.dataset": "sshd", "network.protocol": "ssh",
    "user.name": "root", "source.ip": "203.0.113.7", "source.port": "52344",
    "host.name": "web01", "process.name": "sshd", "process.pid": "4211"
  }
}
```

The dashboard shows them under **Fields** in the event detail.

## Schema

| Field | Meaning |
|---|---|
| `event.category` | authentication, network, process, web, dns, file, intrusion_detection, iam, configuration |
| `event.action` | What happened, e.g. `ssh_login`, `sudo`, `connection_denied`, `http_request` |
| `event.outcome` | `success`, `failure` or `unknown` |
| `event.code` | The source's event ID (e.g. Windows 4625) |
| `event.dataset` | The log source, e.g. `sshd`, `web.access`, `firewall` |
| `source.ip` / `source.port` | Client or attacker |
| `destination.ip` / `destination.port` | Server or target |
| `network.transport` / `network.protocol` | `tcp`/`udp`/`icmp`; `ssh`, `http`, `dns`… |
| `user.name` | The account acting |
| `user.target.name` | The account acted on (sudo target, account changed) |
| `host.name` | The host that logged the event (lower-case) |
| `process.name` / `process.pid` | Program and process ID |
| `process.executable` / `process.command_line` / `process.parent.executable` | Process details |
| `url.original`, `http.request.method`, `http.response.status_code`, `user_agent.original` | Web requests |
| `dns.question.name` | Queried domain |
| `file.path`, `file.hash.sha256`, `file.hash.md5` | Files |
| `rule.name` | The signature or rule that fired at the source (IDS, firewall) |
| `observer.product` | The product that produced the log |

Values are checked: IPs must be valid addresses (IPv4-mapped IPv6 is
unwrapped), ports must be 0–65535, outcomes are reduced to success/failure/unknown,
and HTTP methods are upper-cased. A value that fails these checks is dropped, not
guessed.

## Where values come from

First match wins, in this order:

1. **The parser.** Source-specific parsers set fields directly.
2. **Structured JSON.** Keys that already are schema names (`source.ip`, or
   nested `{"source":{"ip":…}}`) and common aliases, matched
   case-insensitively: `src_ip`, `client_ip`, `remote_addr`, `sourceIPAddress`
   → `source.ip`; `user`, `username`, `SubjectUserName` → `user.name`;
   `Image`/`exe` → `process.executable`; `CommandLine`/`cmdline` →
   `process.command_line`; `EventID` → `event.code`; and others.
3. **Text formats**:

   | Format | Example | Fields |
   |---|---|---|
   | OpenSSH | `Failed password for invalid user admin from 1.2.3.4 port 5 ssh2` | authentication, outcome, user, source IP/port |
   | sudo | `deploy : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash` | user, target user, command line |
   | iptables / ufw | `[UFW BLOCK] SRC=… DST=… PROTO=TCP SPT=… DPT=…` | network, allowed/denied, addresses, ports |
   | Web access (nginx, Apache combined) | `1.2.3.4 - - [ts] "GET /x HTTP/1.1" 404 … "UA"` | web, method, URL, status, user agent |
   | `key=value` pairs | `user=bob src=1.2.3.4 dst_port=8443` | Any key that is an alias |
4. **The syslog header**: `host.name`, `process.name`, `process.pid`.

## Using fields in detection rules

Sigma rules can name the schema fields directly:

```yaml
detection:
  sel:
    event.category: authentication
    event.outcome: failure
    user.name: [root, admin]
  condition: sel
```

Rules written for other pipelines keep working. Each field is also exposed
under the names Sigma rules commonly use: `source.ip` as `SourceIp`,
`IpAddress` and `src_ip`; `process.command_line` as `CommandLine`;
`process.executable` as `Image`; `user.name` as `User`, `SubjectUserName`;
`url.original` as `cs-uri`; and so on (`normalize.SigmaAliases`). Original JSON
keys stay available too.

Incident correlation uses `source.ip`, `user.name` and `host.name` from these
fields when present.

## Adding a format

Add an extractor in `siemagent/internal/normalize/normalize.go`, or set
`Fields` in a new parser, then add a case to `normalize_test.go`. A test fails
if any field set is missing from `Schema`, so the schema stays the one
reference.
