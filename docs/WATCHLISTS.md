# IOC watchlists

A watchlist is a set of indicators of compromise: IP addresses, IP ranges,
domains and file hashes (MD5, SHA-1, SHA-256). Every event is checked against
the enabled watchlists. When one matches:

- a detection `Threat intel match: <value> on watchlist <name>` is added to the
  event (rule ID `ioc:<watchlist-id>`, tags `ioc`, `ioc.<type>`),
- the value is added to the event's IOCs,
- the event's severity rises to the watchlist's severity if that is higher. The
  event is then labelled *Known Malicious Indicator*, and P1–P3 matches open or
  join incidents and trigger playbooks like any other alert.

A watchlist never lowers a severity or relabels a more serious verdict.
Matching works in rules-only mode too: it needs no LLM.

## Kinds of watchlist

| Source | Where the indicators come from | Who edits it |
|---|---|---|
| **Manual** | Added by analysts in the dashboard or API, stored in Postgres | Analysts add and remove indicators; admins manage the list |
| **Feed** | Downloaded from a URL, refreshed on a schedule (default every 6 h, at least every 15 min) | Read-only; admins add, refresh, re-grade or delete the feed |
| **File** | `*.txt`, `*.csv` or `*.list` files in `IOC_WATCHLIST_DIR`, read at start | Read-only; change the file and restart. Admins can disable or re-grade it until the next restart |

File lists suit detection-as-code: keep them in git next to your rules. The
file name is the list name; a `p1-` … `p4-` prefix sets the severity
(`p1-ransomware-c2.txt`). Without a prefix the severity is P2.

## List format

Feeds and files use the formats threat feeds already publish:

```text
# comments start with #, ; or //
203.0.113.9
198.51.100.0/24              ranges down to /8 (IPv4) or /32 (IPv6)
evil.example                 also matches every subdomain (cdn.evil.example)
0.0.0.0 phish.example        hosts-file lines
"203.0.113.10","botnet",...  CSV: the first column
hxxp://bad[.]example/x       URLs and defanged values: the host is used
d41d8cd98f00b204e9800998ecf8427e
```

Values that are none of these are counted as *skipped* and shown on the list.
`0.0.0.0`, loopback addresses and ranges broader than /8 are refused, so a typo
cannot flag every event. A list holds at most 1,000,000 indicators (feeds and
files) or 100,000 (manual).

Good free feeds to start with:

| Feed | URL | Contains |
|---|---|---|
| abuse.ch Feodo Tracker | `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` | Botnet C2 IPs |
| abuse.ch URLhaus | `https://urlhaus.abuse.ch/downloads/hostfile/` | Malware distribution hosts |
| abuse.ch ThreatFox | `https://threatfox.abuse.ch/export/csv/ip-port/recent/` | Recent IOCs |
| Tor Project | `https://check.torproject.org/torbulkexitlist` | Tor exit nodes |

Check each feed's terms before using it commercially. Feeds are downloaded
from the SIEMAgent server, so it needs outbound HTTPS to them. A failed download
keeps the previous indicators in use and shows the error on the list.

## Dashboard

**Watchlists** shows every list with its indicator count, matches since start,
last download and errors. Use **Check an indicator** to see whether a value is
listed and on which list. Click a list to see its indicators. On manual lists,
analysts paste indicators (one per line) with a note, such as the case they came
from, and remove them again.

## API

| Method | Path | Role | Purpose |
|---|---|---|---|
| `GET` | `/api/watchlists` | viewer | Lists with counts, hits and feed status |
| `GET` | `/api/watchlists/{id}/indicators?limit=200` | viewer | Indicators of a list and the total |
| `GET` | `/api/ioc/lookup?value=…` | viewer | Which enabled lists contain a value |
| `POST` | `/api/watchlists/{id}/indicators` | analyst | `{"values":["203.0.113.9"],"note":"INC-…"}` on a manual list; returns added and rejected values |
| `DELETE` | `/api/watchlists/{id}/indicators?value=…` | analyst | Remove one value (query string, because ranges contain `/`) |
| `POST` | `/api/watchlists` | admin | `{"name","source":"manual"\|"feed","url","severity":"P1"–"P4","refresh_seconds"}` |
| `PATCH` | `/api/watchlists/{id}` | admin | `{"name","enabled","severity"}` |
| `DELETE` | `/api/watchlists/{id}` | admin | Delete a manual list or feed |
| `POST` | `/api/watchlists/{id}/refresh` | admin | Download a feed now |

A new feed is downloaded within a minute of being added, or straight away with
`/refresh`.

## Configuration and metrics

| Variable | Meaning |
|---|---|
| `IOC_WATCHLIST_DIR` | Directory of read-only list files loaded at start |

| Metric | Meaning |
|---|---|
| `ioc_matches_total{type}` | Watchlist matches by indicator type |
| `ioc_feed_errors_total` | Failed feed downloads |

## Limits

- Matching looks at up to 64 distinct candidate values per event (IPs,
  domains, hashes found in the raw line), so one hostile log line cannot
  cost unbounded work.
- Hit counts are per server process and reset on restart.
- Feed and file indicators live in memory. A million indicators take roughly
  100–200 MB.
