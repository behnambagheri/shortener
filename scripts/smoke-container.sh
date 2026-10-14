#!/usr/bin/env bash
# Smoke-tests a built image: public flow, admin token sign-in, and persistence across restarts.
set -euo pipefail
image="${1:-shortener:test}"
token="smoke-admin-token-$(openssl rand -hex 8)"
volume="shortener-smoke-$RANDOM"
docker volume create "$volume" >/dev/null
start() {
  docker run -d --read-only --cap-drop ALL --security-opt no-new-privileges -v "$volume:/var/lib/shortener" \
    -e ADMIN_TOKEN="$token" -e APPROVED_DOMAINS=example.com -p 127.0.0.1::8080 "$image"
}
wait_ready() {
  port="$(docker port "$container" 8080/tcp | head -1 | awk -F: '{print $NF}')"
  origin="http://127.0.0.1:$port"
  for _ in $(seq 1 30); do curl -fsS "$origin/.well-known/health" >/dev/null 2>&1 && return; sleep 1; done
  echo "Container did not become healthy." >&2; return 1
}
container="$(start)"
trap 'docker logs "$container" || true; docker rm -f "$container" >/dev/null 2>&1 || true; docker volume rm "$volume" >/dev/null' EXIT
wait_ready
curl -fsS "$origin/.well-known/health" | jq -e '.status == "ok" and .approved_domains_count == 1'
curl -fsS "$origin/" | grep -Fq 'Short links'
curl -fsS "$origin/admin" | grep -Fq 'Admin sign-in'
curl -fsS -X POST -H 'Content-Type: application/json' -d '{"original":"https://www.example.com/x","shortened":"smoke"}' "$origin/api/links" | jq -e '.shortened == "smoke"'
test "$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"original":"https://not-approved.test/"}' "$origin/api/links")" = 403
test "$(curl -sS -o /dev/null -w '%{http_code}' "$origin/admin/api/overview")" = 401
curl -fsS -H "Authorization: Bearer $token" "$origin/admin/api/overview" | jq -e '.stats.links == 1 and .auth.token == true'
cookie="$(curl -sS -o /dev/null -D - -d "token=$token" "$origin/admin/login" | awk -F'[ ;]' 'tolower($1) == "set-cookie:" {print $2}')"
test -n "$cookie"
curl -fsS -X PUT -H "Cookie: $cookie" -H 'Content-Type: application/json' -d '{"link_creation":"admin"}' "$origin/admin/api/settings" | jq -e '.link_creation == "admin"'
test "$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"original":"https://example.com/"}' "$origin/api/links")" = 403
docker restart "$container" >/dev/null
wait_ready
test "$(curl -sS -o /dev/null -w '%{redirect_url}' "$origin/smoke")" = "https://www.example.com/x"
curl -fsS "$origin/api/config" | jq -e '.link_creation == "admin"'
docker exec "$container" sh -c 'test "$(id -u)" = 10001 && test -f /var/lib/shortener/shortener.sqlite3'
echo "Container smoke checks passed."
