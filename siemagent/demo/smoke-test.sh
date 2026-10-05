#!/usr/bin/env bash
# Smoke-tests a running demo (make demo): sign in through the dashboard's
# proxy, check the seeded incidents, approve the IP block and confirm the
# webhook received it. Needs a fresh demo (it approves the seeded action).
# Used by CI and by `make demo-test`.
set -euo pipefail

BASE=${BASE:-http://localhost:3000}
COMPOSE=${COMPOSE:-docker compose -f siemagent/demo/compose.yml}
JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT
H=(-H "X-Requested-With: siemagent" -H "Content-Type: application/json")

fail() { echo "FAIL: $*" >&2; exit 1; }

for _ in $(seq 1 60); do
  curl -sf "$BASE/health/ready" >/dev/null && break
  sleep 2
done
curl -sf "$BASE/health/ready" >/dev/null || fail "API not ready: $(curl -s "$BASE/health/ready")"

curl -sf -c "$JAR" "${H[@]}" -X POST "$BASE/api/auth/login" \
  -d '{"username":"admin","password":"siemagent-demo"}' >/dev/null || fail "login"

# Seeding runs in the background right after start; give it a moment.
for _ in $(seq 1 30); do
  n=$(curl -sf -b "$JAR" "$BASE/api/incidents" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
  [ "$n" -ge 3 ] && break
  sleep 2
done

curl -sf -b "$JAR" "$BASE/api/incidents" | python3 -c '
import json, sys
titles = {i["title"]: i for i in json.load(sys.stdin)}
want = ["SSH Brute Force from 185.220.101.77", "Shadow Copies Deleted on app02", "Port Scan From One Source from 203.0.113.50"]
missing = [t for t in want if t not in titles]
if missing:
    sys.exit(f"missing incidents {missing}; got {list(titles)}")
tactics = set(titles[want[0]]["tactics"])
if tactics != {"Credential Access", "Privilege Escalation"}:
    sys.exit(f"brute-force kill chain: {sorted(tactics)}")
print("incidents ok:", ", ".join(want))
' || fail "incidents"

curl -sf -b "$JAR" "$BASE/api/watchlists" | python3 -c '
import json, sys
lists = {w["name"]: w for w in json.load(sys.stdin)}
tor = lists.get("tor-exit-nodes")
if not tor or tor["hits"] < 1:
    sys.exit(f"tor-exit-nodes watchlist did not match: {lists}")
print("watchlist ok:", tor["hits"], "matches")
' || fail "watchlists"

action=$(curl -sf -b "$JAR" "$BASE/api/response/actions?status=pending" | python3 -c '
import json, sys
for a in json.load(sys.stdin):
    if a.get("type") == "block_ip" and a.get("target") == "185.220.101.77":
        print(a["id"]); break
')
[ -n "$action" ] || fail "no pending block_ip action for 185.220.101.77"

status=$(curl -sf -b "$JAR" "${H[@]}" -X POST "$BASE/api/response/actions/$action/approve" -d '{}' |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')
[ "$status" = "succeeded" ] || fail "approve $action: status $status"

sleep 1
$COMPOSE logs webhook 2>/dev/null | grep -q '"action":"block_ip","target":"185.220.101.77"' || fail "webhook did not receive the block"

echo "demo smoke test passed"
