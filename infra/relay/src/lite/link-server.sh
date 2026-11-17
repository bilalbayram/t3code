#!/usr/bin/env bash
# Points a running T3 server at your relay and turns on publishing agent activity, over the
# server's own HTTP API, so the server keeps running. Run it on the machine the server runs on.
#
#   RELAY_ENVIRONMENT_CREDENTIAL=... ./link-server.sh https://relay.example.com [server-origin]
#
# The server origin defaults to the one in T3's server-runtime.json. Undo with:
#   curl -X POST -H "authorization: Bearer <relay:write token>" <origin>/api/connect/unlink
set -euo pipefail

relay_url="${1:?usage: link-server.sh <relay-url> [server-origin]}"
credential="${RELAY_ENVIRONMENT_CREDENTIAL:?set RELAY_ENVIRONMENT_CREDENTIAL to the relay secret}"
t3="${T3CODE_CLI_PATH:-t3}"
origin="${2:-}"
if [ -z "$origin" ]; then
  origin="$(python3 -c 'import json, os; home = os.path.expanduser(os.environ.get("T3CODE_HOME", "~/.t3")); print(json.load(open(home + "/userdata/server-runtime.json"))["origin"])')"
fi

# A short-lived session that may only change relay settings, revoked once done.
session="$("$t3" auth session issue --scope relay:write --ttl 5m --label "self-hosted relay link" --json)"
token="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' <<<"$session")"
session_id="$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("sessionId") or d.get("id") or "")' <<<"$session")"
trap '[ -n "$session_id" ] && "$t3" auth session revoke "$session_id" >/dev/null 2>&1 || true' EXIT

# The server insists on a key for minting T3 Connect credentials. Whoever holds the private half
# could mint them, so it's made here and thrown away: nobody can.
mint_key="$(openssl genpkey -algorithm ed25519 | openssl pkey -pubout)"

body="$(RELAY_URL="$relay_url" CREDENTIAL="$credential" MINT="$mint_key" python3 -c '
import json, os
print(json.dumps({
  "relayUrl": os.environ["RELAY_URL"],
  # Fixed: the server refuses a later config for a different user.
  "cloudUserId": "self-hosted",
  "environmentCredential": os.environ["CREDENTIAL"],
  "cloudMintPublicKey": os.environ["MINT"],
  "endpointRuntime": None,
}))')"

post() {
  curl -sS --fail-with-body -X POST "$origin$1" \
    -H "authorization: Bearer $token" -H "content-type: application/json" -d "$2"
  echo
}

echo "Relay config → $origin"
post /api/connect/relay-config "$body"
echo "Publishing agent activity"
post /api/connect/preferences '{"publishAgentActivity":true}'
