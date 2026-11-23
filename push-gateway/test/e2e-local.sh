#!/usr/bin/env bash
# Local end-to-end check: wrangler dev (workerd) -> fake APNs on 127.0.0.1.
# Talks to nothing but localhost; needs node, openssl and curl.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

TOPIC="com.example.skwod"
KEY_ID="E2EKEYID01"
TEAM_ID="E2ETEAMID1"

if [[ -e .dev.vars ]]; then
  echo "refusing to run: .dev.vars already exists (this script writes and deletes its own)" >&2
  exit 1
fi
had_wrangler_dir=0
[[ -d .wrangler ]] && had_wrangler_dir=1

tmp="$(mktemp -d)"
fake_pid=""
wrangler_pid=""

kill_tree() {
  local pid="$1" child
  for child in $(pgrep -P "$pid" 2>/dev/null || true); do
    kill_tree "$child"
  done
  kill "$pid" 2>/dev/null || true
}

cleanup() {
  local status=$?
  [[ -n "$wrangler_pid" ]] && kill_tree "$wrangler_pid"
  [[ -n "$fake_pid" ]] && kill_tree "$fake_pid"
  wait 2>/dev/null || true
  if [[ $status -ne 0 && -f "$tmp/wrangler.log" ]]; then
    echo "--- wrangler dev log (tail) ---" >&2
    tail -n 30 "$tmp/wrangler.log" >&2
  fi
  rm -f .dev.vars
  [[ $had_wrangler_dir -eq 0 ]] && rm -rf .wrangler
  rm -rf "$tmp"
  if [[ $status -eq 0 ]]; then echo "e2e: PASS"; else echo "e2e: FAIL" >&2; fi
}
trap cleanup EXIT

pass() { echo "ok   - $1"; }
die() {
  echo "FAIL - $1" >&2
  exit 1
}

# --- throwaway key, ports, config -------------------------------------------
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/key.p8" 2>/dev/null
grep -q -- "-----BEGIN PRIVATE KEY-----" "$tmp/key.p8" || die "openssl did not produce a PKCS#8 key"
openssl pkey -in "$tmp/key.p8" -pubout -out "$tmp/pub.pem" 2>/dev/null

read -r PROD_PORT SANDBOX_PORT GATEWAY_PORT INSPECTOR_PORT < <(node -e '
  const net = require("node:net");
  const servers = [0, 1, 2, 3].map(() => net.createServer().listen(0, "127.0.0.1"));
  Promise.all(servers.map((s) => new Promise((r) => s.on("listening", () => r(s.address().port))))).then((ports) => {
    console.log(ports.join(" "));
    servers.forEach((s) => s.close());
  });
')

# Single line with literal \n escapes: the form the gateway must also accept.
escaped_key="$(awk 'BEGIN { ORS = "\\n" } { print }' "$tmp/key.p8")"
(
  umask 077
  cat >.dev.vars <<VARS
APNS_KEY_P8="${escaped_key}"
APNS_KEY_ID="${KEY_ID}"
APNS_TEAM_ID="${TEAM_ID}"
APNS_HOST="http://127.0.0.1:${PROD_PORT}"
APNS_SANDBOX_HOST="http://127.0.0.1:${SANDBOX_PORT}"
ALLOWED_TOPICS="${TOPIC}"
RATE_KEY_SALT="e2e-local-rate-key-salt-not-a-secret"
VARS
)

# --- start fake APNs and the worker -----------------------------------------
node test/fake-apns.mjs "$PROD_PORT" "$SANDBOX_PORT" "$tmp/requests.json" >"$tmp/fake.log" 2>&1 &
fake_pid=$!

WRANGLER_SEND_METRICS=false ./node_modules/.bin/wrangler dev --local \
  --ip 127.0.0.1 --port "$GATEWAY_PORT" --inspector-port "$INSPECTOR_PORT" \
  --persist-to "$tmp/state" --show-interactive-dev-session=false \
  >"$tmp/wrangler.log" 2>&1 &
wrangler_pid=$!

BASE="http://127.0.0.1:${GATEWAY_PORT}"
for _ in $(seq 1 120); do
  if curl -fsS -o /dev/null "$BASE/health" 2>/dev/null; then break; fi
  kill -0 "$wrangler_pid" 2>/dev/null || die "wrangler dev exited early"
  sleep 0.5
done
curl -fsS -o /dev/null "$BASE/health" || die "wrangler dev did not come up"

# --- helpers ----------------------------------------------------------------
# post <json-body> -> sets STATUS; body in $tmp/body, headers in $tmp/headers
post() {
  STATUS="$(curl -sS -o "$tmp/body" -D "$tmp/headers" -w '%{http_code}' \
    -X POST -H 'content-type: application/json' --data-binary "$1" "$BASE/v1/wake")"
}
expect() { # expect <name> <status> <exact-body>
  [[ "$STATUS" == "$2" ]] || die "$1: expected HTTP $2, got $STATUS ($(cat "$tmp/body"))"
  [[ "$(cat "$tmp/body")" == "$3" ]] || die "$1: unexpected body $(cat "$tmp/body")"
  pass "$1 -> $2 $3"
}
recorded() { node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).length)' "$tmp/requests.json"; }

TOKEN="$(openssl rand -hex 32)"
DEV_TOKEN="0000$(openssl rand -hex 30)"

# --- checks -----------------------------------------------------------------
[[ "$(curl -sS "$BASE/health")" == '{"status":"ok"}' ]] || die "/health body"
pass 'GET /health -> 200 {"status":"ok"}'

post "{\"token\":\"$TOKEN\",\"kind\":\"message\",\"topic\":\"$TOPIC\"}"
expect "wake message" 202 '{"ok":true}'

post "{\"token\":\"$TOKEN\",\"kind\":\"call\",\"topic\":\"$TOPIC\"}"
expect "wake call" 202 '{"ok":true}'

post "{\"token\":\"$TOKEN\",\"kind\":\"message\",\"topic\":\"$TOPIC\"}"
expect "rapid repeat message" 429 '{"ok":false,"error":"rate_limited"}'
grep -qi '^retry-after: [0-9][0-9]*' "$tmp/headers" || die "429 without retry-after"
pass "429 carries retry-after"
if grep -qi '^access-control-' "$tmp/headers"; then die "CORS header present"; fi

post "{\"token\":\"$(openssl rand -hex 32)\",\"kind\":\"message\",\"topic\":\"com.attacker.app\"}"
expect "topic not allowlisted" 403 '{"ok":false,"error":"forbidden"}'

post "{\"token\":\"$(openssl rand -hex 32)\",\"kind\":\"message\",\"topic\":\"$TOPIC\",\"sender\":\"alice\"}"
expect "unknown key" 400 '{"ok":false,"error":"bad_request"}'

[[ "$(recorded)" == "2" ]] || die "expected exactly 2 APNs requests so far, fake saw $(recorded)"
pass "refused requests never reached APNs"

post "{\"token\":\"$DEV_TOKEN\",\"kind\":\"message\",\"topic\":\"$TOPIC\"}"
expect "sandbox retry after BadDeviceToken" 202 '{"ok":true}'

# --- assert exactly what the fake APNs received ------------------------------
TOKEN="$TOKEN" DEV_TOKEN="$DEV_TOKEN" TOPIC="$TOPIC" KEY_ID="$KEY_ID" TEAM_ID="$TEAM_ID" \
  node --input-type=module - "$tmp/requests.json" "$tmp/pub.pem" <<'NODE'
import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";

const [requestsFile, pubFile] = process.argv.slice(2);
const { TOKEN, DEV_TOKEN, TOPIC, KEY_ID, TEAM_ID } = process.env;
const reqs = JSON.parse(readFileSync(requestsFile, "utf8"));
const pub = createPublicKey(readFileSync(pubFile));
const now = Math.floor(Date.now() / 1000);
const APNS_HEADERS = ["apns-expiration", "apns-priority", "apns-push-type", "apns-topic", "authorization", "content-type"];

function checkJwt(authorization) {
  assert.match(authorization, /^bearer [\w-]+\.[\w-]+\.[\w-]+$/);
  const [h, c, s] = authorization.slice(7).split(".");
  assert.deepEqual(JSON.parse(Buffer.from(h, "base64url")), { alg: "ES256", kid: KEY_ID });
  const claims = JSON.parse(Buffer.from(c, "base64url"));
  assert.deepEqual(Object.keys(claims).sort(), ["iat", "iss"]);
  assert.equal(claims.iss, TEAM_ID);
  assert.ok(claims.iat <= now && claims.iat > now - 300, "iat is recent");
  const ok = verify("sha256", Buffer.from(`${h}.${c}`), { key: pub, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url"));
  assert.ok(ok, "ES256 signature verifies against the throwaway key");
}

function check(req, { role, token, headers, body }) {
  assert.equal(req.role, role);
  assert.equal(req.method, "POST");
  assert.equal(req.path, `/3/device/${token}`);
  for (const [name, value] of Object.entries(headers)) assert.equal(req.headers[name], value, name);
  // Nothing identifying is forwarded: the only apns-*/auth headers are the expected ones.
  const sent = Object.keys(req.headers).filter((n) => n.startsWith("apns-") || n === "authorization" || n === "content-type");
  assert.deepEqual(sent.sort(), APNS_HEADERS);
  // The runtime adds its own headers (e.g. cf-worker); none may describe the caller.
  for (const n of Object.keys(req.headers)) assert.ok(!/^(x-forwarded|x-real-ip|forwarded|cf-connecting|true-client|cookie|user-agent)/.test(n), `unexpected header ${n}`);
  assert.equal(req.body, body);
  checkJwt(req.headers.authorization);
}

const alert = {
  headers: { "apns-push-type": "alert", "apns-topic": TOPIC, "apns-priority": "10", "content-type": "application/json" },
  body: '{"aps":{"alert":{"body":"New message"},"sound":"default","mutable-content":1}}',
};
const voip = {
  headers: { "apns-push-type": "voip", "apns-topic": `${TOPIC}.voip`, "apns-priority": "10", "apns-expiration": "0", "content-type": "application/json" },
  body: '{"aps":{},"kind":"call"}',
};

assert.equal(reqs.length, 4, "fake APNs saw exactly 4 requests");
check(reqs[0], { role: "production", token: TOKEN, ...alert });
const exp = Number(reqs[0].headers["apns-expiration"]);
assert.ok(exp > now + 3300 && exp <= now + 3600, "alert expiration is about now + 1h");
console.log("ok   - APNs saw the exact alert request (path, headers, body, valid ES256 JWT)");

check(reqs[1], { role: "production", token: TOKEN, ...voip });
console.log("ok   - APNs saw the exact VoIP request (path, headers, body, valid ES256 JWT)");

assert.equal(reqs[0].headers.authorization, reqs[1].headers.authorization);
console.log("ok   - provider JWT reused across wakes");

check(reqs[2], { role: "production", token: DEV_TOKEN, ...alert });
check(reqs[3], { role: "sandbox", token: DEV_TOKEN, ...alert });
console.log("ok   - BadDeviceToken from production was retried once on the sandbox host");
NODE

# --- nothing sensitive in the worker's own output -----------------------------
if grep -q -e "$TOKEN" -e "$DEV_TOKEN" "$tmp/wrangler.log" "$tmp/fake.log"; then
  die "a device token appeared in process output"
fi
pass "no device token in wrangler dev or fake APNs output"
