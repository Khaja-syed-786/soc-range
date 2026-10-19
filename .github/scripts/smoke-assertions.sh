#!/usr/bin/env bash
# Smoke assertions against a running `docker compose` stack (run from the repo root, stack already up).
# Shared by docker.yml (after the README quickstart) and release.yml (against the image being released).
# Usage: smoke-assertions.sh api|port|hardening
set -euo pipefail

tmp=${RUNNER_TEMP:-$(mktemp -d)}

api() {
  gen=$(curl -fsS --max-time 5 http://127.0.0.1:5000/api/generator)
  echo "GET /api/generator -> $gen"
  jq -e '.running == true and (.rate | type == "number") and (.autoScenarios | type == "boolean")' <<<"$gen"

  total=$(curl -fsS --max-time 5 'http://127.0.0.1:5000/api/events?size=1' | jq -e '.total')
  echo "seeded events: $total"
  test "$total" -gt 1000

  curl -fsS --max-time 5 -D "$tmp/headers.txt" -o "$tmp/index.html" http://127.0.0.1:5000/
  grep -qi '^content-type: text/html' "$tmp/headers.txt"
  grep -q '<title>SOC Simulator</title>' "$tmp/index.html"

  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:5000/api/generator)
  echo "POST without X-SocSim -> $code"
  test "$code" = 403
}

port() {
  published=$(docker compose port soc-range 5000)
  echo "docker compose port: $published"
  test "$published" = "127.0.0.1:5000"

  cid=$(docker compose ps -q soc-range)
  docker inspect --format '{{json .HostConfig.PortBindings}}' "$cid" | tee "$tmp/bindings.json"
  jq -e '[.[][] | .HostIp] | length > 0 and all(. == "127.0.0.1")' "$tmp/bindings.json"

  echo "Host listeners on :5000:"; ss -Hltn 'sport = :5000' | tee "$tmp/listeners.txt"
  if awk '{print $4}' "$tmp/listeners.txt" | grep -qv '^127\.0\.0\.1:5000$'; then
    echo "::error::something listens on :5000 beyond 127.0.0.1"; exit 1
  fi

  ip=$(hostname -I | awk '{print $1}')
  test -n "$ip"
  if curl -s -o /dev/null --max-time 3 "http://$ip:5000/"; then
    echo "::error::app is reachable on the runner's network address $ip"; exit 1
  fi
  echo "not reachable on $ip:5000, as expected"
}

hardening() {
  cid=$(docker compose ps -q soc-range)
  docker inspect "$cid" | jq '.[0] | {User: .Config.User, ReadonlyRootfs: .HostConfig.ReadonlyRootfs,
    CapDrop: .HostConfig.CapDrop, SecurityOpt: .HostConfig.SecurityOpt, Health: .State.Health.Status}'
  docker inspect "$cid" | jq -e '.[0] | .Config.User == "1000:1000"
    and .HostConfig.ReadonlyRootfs == true
    and .HostConfig.CapDrop == ["ALL"]
    and any(.HostConfig.SecurityOpt[]; . == "no-new-privileges:true")
    and .State.Health.Status == "healthy"'

  uid=$(docker compose exec -T soc-range id -u)
  echo "uid inside container: $uid"
  test "$uid" = 1000

  if docker compose exec -T soc-range touch /app/probe 2>/dev/null; then
    echo "::error::/app is writable"; exit 1
  fi
  # Volumes must come up writable by the app user; the app code must stay root-owned
  owners=$(docker compose exec -T soc-range stat -c '%u:%g %n' /data /app/rules /app/src /app)
  echo "$owners"
  test "$owners" = "$(printf '%s\n' '1000:1000 /data' '1000:1000 /app/rules' '0:0 /app/src' '0:0 /app')"
  docker compose exec -T soc-range test -f /data/state.json
  docker compose exec -T soc-range test -w /app/rules/rules.json
  docker compose logs soc-range | grep -q 'WARNING: listening on 0.0.0.0'
}

case "${1:-}" in
  api) api ;;
  port) port ;;
  hardening) hardening ;;
  *) echo "usage: $0 api|port|hardening" >&2; exit 2 ;;
esac
