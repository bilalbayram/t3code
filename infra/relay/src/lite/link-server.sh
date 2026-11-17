#!/usr/bin/env bash
# Links a running T3 server to your relay, over the server's own HTTP API so it keeps running:
# publishing agent activity, and, like T3 Connect, being listed in the app and reachable through
# its tunnel with credentials the relay asks it for. Run it on the machine the server runs on.
#
#   RELAY_ENVIRONMENT_CREDENTIAL=... ./link-server.sh \
#     --relay https://relay.example.com --tunnel https://desk.example.com \
#     [--label Desk] [--lan http://desk.local:3773/] [--origin http://127.0.0.1:3773] \
#     [--connector-token TOKEN --tunnel-id ID --tunnel-name NAME]
#
# --tunnel is the https address the app reaches the server at through the relay. With
# --connector-token the server runs that Cloudflare Tunnel itself (cloudflared on its PATH);
# without it, something else must. --lan defaults to this Mac's Bonjour name (.local) on macOS.
# Undo with: curl -X POST -H "authorization: Bearer <relay:write token>" <origin>/api/connect/unlink
set -euo pipefail

relay_url="" tunnel_url="" label="" lan_url="" origin="" connector_token="" tunnel_id="" tunnel_name=""
while [ $# -gt 0 ]; do
  case "$1" in
    --relay) relay_url="$2"; shift 2 ;;
    --tunnel) tunnel_url="$2"; shift 2 ;;
    --label) label="$2"; shift 2 ;;
    --lan) lan_url="$2"; shift 2 ;;
    --origin) origin="$2"; shift 2 ;;
    --connector-token) connector_token="$2"; shift 2 ;;
    --tunnel-id) tunnel_id="$2"; shift 2 ;;
    --tunnel-name) tunnel_name="$2"; shift 2 ;;
    *) echo "Unknown option $1" >&2; exit 64 ;;
  esac
done
[ -n "$relay_url" ] && [ -n "$tunnel_url" ] || { echo "usage: link-server.sh --relay <url> --tunnel <https url> [options]" >&2; exit 64; }
credential="${RELAY_ENVIRONMENT_CREDENTIAL:?set RELAY_ENVIRONMENT_CREDENTIAL to the relay secret}"
t3="${T3CODE_CLI_PATH:-t3}"
relay_url="${relay_url%/}"

if [ -z "$origin" ]; then
  origin="$(python3 -c 'import json, os; home = os.path.expanduser(os.environ.get("T3CODE_HOME", "~/.t3")); print(json.load(open(home + "/userdata/server-runtime.json"))["origin"])')"
fi
origin="${origin%/}"

descriptor="$(curl -sS --fail "$origin/.well-known/t3/environment")"
environment_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["environmentId"])' <<<"$descriptor")"
[ -n "$label" ] || label="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["label"])' <<<"$descriptor")"
if [ -z "$lan_url" ] && command -v scutil >/dev/null; then
  port="$(python3 -c 'import sys, urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]).port or 80)' "$origin")"
  lan_url="http://$(scutil --get LocalHostName | tr '[:upper:]' '[:lower:]').local:$port/"
fi

# The relay signs mint requests with its key; the server verifies them with this public half.
mint_key="$(curl -sS --fail "$relay_url/v1/mint-public-key" | python3 -c 'import json,sys; print(json.load(sys.stdin)["publicKey"])')"

# A short-lived session that may only change relay settings, revoked once done.
session="$("$t3" auth session issue --scope relay:write --ttl 5m --label "self-hosted relay link" --json)"
token="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' <<<"$session")"
session_id="$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("sessionId") or d.get("id") or "")' <<<"$session")"
trap '[ -n "$session_id" ] && "$t3" auth session revoke "$session_id" >/dev/null 2>&1 || true' EXIT

config="$(RELAY_URL="$relay_url" CREDENTIAL="$credential" MINT="$mint_key" CONNECTOR="$connector_token" \
  TUNNEL_ID="$tunnel_id" TUNNEL_NAME="$tunnel_name" python3 -c '
import json, os
runtime = None
if os.environ["CONNECTOR"]:
    runtime = {"providerKind": "cloudflare_tunnel", "connectorToken": os.environ["CONNECTOR"]}
    if os.environ["TUNNEL_ID"]: runtime["tunnelId"] = os.environ["TUNNEL_ID"]
    if os.environ["TUNNEL_NAME"]: runtime["tunnelName"] = os.environ["TUNNEL_NAME"]
print(json.dumps({
  "relayUrl": os.environ["RELAY_URL"],
  # Fixed: the server refuses a later config for a different user, and the relay signs as it.
  "cloudUserId": "self-hosted",
  "environmentCredential": os.environ["CREDENTIAL"],
  "cloudMintPublicKey": os.environ["MINT"],
  "endpointRuntime": runtime,
}))')"

registration="$(LABEL="$label" TUNNEL="$tunnel_url" LAN="$lan_url" CONFIG="$config" python3 -c '
import json, os
body = {"label": os.environ["LABEL"], "httpBaseUrl": os.environ["TUNNEL"]}
if os.environ["LAN"]: body["lanUrl"] = os.environ["LAN"]
# Kept so the relay can hand the tunnel back when the server asks to recover it.
runtime = json.loads(os.environ["CONFIG"])["endpointRuntime"]
if runtime: body["endpointRuntime"] = runtime
print(json.dumps(body))')"

post() {
  curl -sS --fail-with-body -X POST "$1" -H "authorization: Bearer $2" -H "content-type: application/json" -d "$3"
  echo
}

# The relay first: applying the config makes the server register its tunnel there.
echo "$label ($environment_id): registering with the relay: $tunnel_url${lan_url:+, LAN $lan_url}"
post "$relay_url/v1/environments/$environment_id/registration" "$credential" "$registration"
echo "Relay config → $origin"
post "$origin/api/connect/relay-config" "$token" "$config" | sed -E 's/"connectorToken":"[^"]*"/"connectorToken":"…"/g'
echo "Publishing agent activity"
post "$origin/api/connect/preferences" "$token" '{"publishAgentActivity":true}' >/dev/null
