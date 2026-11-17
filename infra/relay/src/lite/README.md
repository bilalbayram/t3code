# Relay lite

The agent-awareness half of the managed relay, for one person: a Cloudflare Worker and one D1
database that send your phone notifications and Live Activity updates. Your phone runs your own
build of the app, and nothing goes through T3 Connect or needs a Clerk account.

It reuses the managed relay's own code for the aggregate, the alert transitions and the payload
limits (`../agentActivity`), so a rebase brings their changes along.

|                                 | Managed relay                            | Relay lite                                                     |
| ------------------------------- | ---------------------------------------- | -------------------------------------------------------------- |
| Auth for the app                | Clerk sign-in → DPoP token               | `RELAY_CLIENT_SECRET`, built into your app → short-lived token |
| Auth for the server             | Link flow; Ed25519 publish proof checked | `RELAY_ENVIRONMENT_CREDENTIAL`; proof not checked              |
| Storage                         | PlanetScale, queues, Durable Objects     | One D1 database                                                |
| Delivers to                     | Each account's devices                   | Every registered device (they're all yours)                    |
| Android (FCM), tunnels, T3 Chat | Yes                                      | No                                                             |

## Set up

1. **Apple.** For your bundle id `<bundle>`, register three App IDs: `<bundle>`, `<bundle>.widgets`
   and `<bundle>.sharing`. Give all three Push Notifications and the App Group `group.<bundle>`.
   Make an APNs key (`.p8`) for the team.
2. **Relay.**
   ```sh
   cp wrangler.example.jsonc wrangler.jsonc          # gitignored; set your hostname, team and key id
   wrangler d1 create t3-relay-lite                  # put the id in wrangler.jsonc
   wrangler d1 execute t3-relay-lite --remote --file schema.sql
   wrangler secret put RELAY_CLIENT_SECRET           # openssl rand -hex 32
   wrangler secret put RELAY_ENVIRONMENT_CREDENTIAL  # openssl rand -hex 32, a different one
   wrangler secret put APNS_PRIVATE_KEY < AuthKey_XXXXXXXXXX.p8
   wrangler deploy
   curl https://<relay-host>/health
   ```
3. **Each T3 server.** On the machine it runs on:
   ```sh
   RELAY_ENVIRONMENT_CREDENTIAL=... ./link-server.sh https://<relay-host>
   ```
   This sets the server's relay config through its API, so the server keeps running. The server
   then counts as linked to T3 Connect. Undo with `POST /api/connect/unlink`.
4. **The app.** In the repo root's `.env.local` (gitignored):
   ```sh
   T3CODE_IOS_BUNDLE_ID=<bundle>
   T3CODE_IOS_TEAM_ID=<team id>
   T3CODE_RELAY_URL=https://<relay-host>
   T3CODE_RELAY_SELF_HOSTED_TOKEN=<RELAY_CLIENT_SECRET>
   ```
   Leave the Clerk keys unset, then build the `production` or `preview` variant signed for
   distribution (TestFlight or ad hoc). A `development` build registers sandbox tokens.
   In the app, Settings → Notifications turns on notifications and Live Activity updates.

## What to expect

- A thread that needs approval or input, finishes, or fails sends a notification. Tapping it
  opens the thread. While a Live Activity is running, the alert rides inside its update instead.
- Live Activities start on the phone only, when you send from the app or open it while agents are
  working. The managed relay works the same way. From then on the card updates from the relay.
- The secret is built into your app. It lets someone register a device and read thread titles, so
  keep the build to yourself and change the secret if a build leaks.
