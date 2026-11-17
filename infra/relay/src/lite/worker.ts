// @effect-diagnostics globalDate:off globalConsole:off -- A plain Worker outside the relay's Effect runtime.
// A relay for one person: the agent-awareness half of the managed relay (infra/relay), with a shared
// secret in place of Clerk and one D1 database in place of Postgres, queues and Axiom.
//
// - The T3 server publishes thread states with `Bearer RELAY_ENVIRONMENT_CREDENTIAL`, the credential
//   written into its relay config. The publish proof it signs is not checked: the credential is the trust.
// - The mobile app trades RELAY_CLIENT_SECRET (built into the app as its token) for a short-lived
//   access token at /v1/client/dpop-token, then registers devices and Live Activities with it. The
//   DPoP proofs it sends are accepted without checking; the token alone authorises.
// - Every registered device is the owner's, so every publish goes to every device.

import type {
  RelayAgentActivityAggregateState,
  RelayAgentActivityState,
  RelayAgentAwarenessPreferences,
  RelayDeliveryResult,
} from "@t3tools/contracts/relay";

import {
  makeAggregateState,
  TERMINAL_AGENT_ACTIVITY_DISPLAY_TTL_MS,
} from "../agentActivity/agentActivityAggregate.ts";
import {
  isExpiredAgentActivityState,
  isTerminalPhase,
} from "../agentActivity/agentActivityPayloads.ts";
import * as Apns from "./apns.ts";
import { chooseDelivery, type Delivery, type Target } from "./deliver.ts";

export interface Env {
  readonly DB: D1Database;
  readonly RELAY_CLIENT_SECRET: string;
  readonly RELAY_ENVIRONMENT_CREDENTIAL: string;
  readonly APNS_TEAM_ID: string;
  readonly APNS_KEY_ID: string;
  readonly APNS_PRIVATE_KEY: string;
}

const ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
const MOBILE_SCOPES = new Set(["mobile:registration"]);
const PHASES = new Set([
  "starting",
  "running",
  "waiting_for_approval",
  "waiting_for_input",
  "completed",
  "failed",
  "stale",
]);

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

const unauthorized = () => json({ _tag: "RelayUnauthorizedError", message: "Unauthorized." }, 401);
const badRequest = (message: string) => json({ _tag: "RelayBadRequestError", message }, 400);

const encoder = new TextEncoder();

async function sameSecret(a: string, b: string): Promise<boolean> {
  if (!a || !b) return false;
  // Compare digests so the comparison takes the same time whatever the lengths.
  const [x, y] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(a)),
    crypto.subtle.digest("SHA-256", encoder.encode(b)),
  ]);
  // Workers add timingSafeEqual to SubtleCrypto; the WebWorker lib doesn't know it.
  return (
    crypto.subtle as SubtleCrypto & {
      timingSafeEqual(a: ArrayBuffer, b: ArrayBuffer): boolean;
    }
  ).timingSafeEqual(x, y);
}

async function hmac(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(message)));
  return Array.from(signature, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** An access token is `t3l.<expiry>.<hmac>`, so the relay keeps no session table. */
async function issueAccessToken(env: Env, nowSeconds: number): Promise<string> {
  const expires = nowSeconds + ACCESS_TOKEN_TTL_SECONDS;
  return `t3l.${expires}.${await hmac(env.RELAY_CLIENT_SECRET, `access:${expires}`)}`;
}

async function verifyAccessToken(
  env: Env,
  header: string | null,
  nowSeconds: number,
): Promise<boolean> {
  const token = header?.replace(/^(DPoP|Bearer)\s+/i, "").trim() ?? "";
  const [prefix, expires, signature] = token.split(".");
  if (prefix !== "t3l" || !expires || !signature || Number(expires) < nowSeconds) return false;
  return sameSecret(signature, await hmac(env.RELAY_CLIENT_SECRET, `access:${expires}`));
}

function bearer(request: Request): string {
  return (
    request.headers
      .get("authorization")
      ?.replace(/^Bearer\s+/i, "")
      .trim() ?? ""
  );
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

/** The published state, checked loosely: a newer server may add fields this relay doesn't know. */
function parseState(
  value: unknown,
  environmentId: string,
  threadId: string,
): RelayAgentActivityState | null | "invalid" {
  if (value === null) return null;
  if (typeof value !== "object") return "invalid";
  const state = value as Record<string, unknown>;
  const required = [
    "projectTitle",
    "threadTitle",
    "headline",
    "modelTitle",
    "updatedAt",
    "deepLink",
  ];
  if (
    state.environmentId !== environmentId ||
    state.threadId !== threadId ||
    typeof state.phase !== "string" ||
    !PHASES.has(state.phase) ||
    !required.every((field) => nonEmpty(state[field]))
  ) {
    return "invalid";
  }
  return state as unknown as RelayAgentActivityState;
}

function parseJson<T>(text: string | null): T | null {
  if (text === null) return null;
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

async function activeStates(env: Env): Promise<RelayAgentActivityState[]> {
  const { results } = await env.DB.prepare("SELECT state_json FROM activity_rows").all<{
    state_json: string;
  }>();
  return results.flatMap((row) => {
    const state = parseJson<RelayAgentActivityState>(row.state_json);
    return state ? [state] : [];
  });
}

interface TargetRow {
  device_id: string;
  bundle_id: string | null;
  aps_environment: string | null;
  push_token: string | null;
  preferences_json: string;
  activity_push_token: string | null;
  armed_at: string | null;
  last_aggregate_json: string | null;
  last_delivery_at: string | null;
}

async function targets(env: Env, deviceId?: string): Promise<TargetRow[]> {
  const sql = `SELECT d.device_id, d.bundle_id, d.aps_environment, d.push_token, d.preferences_json,
      l.activity_push_token, l.armed_at, l.last_aggregate_json, l.last_delivery_at
    FROM devices d LEFT JOIN live_activities l ON l.device_id = d.device_id
    WHERE d.platform = 'ios'${deviceId ? " AND d.device_id = ?1" : ""}`;
  const statement = deviceId ? env.DB.prepare(sql).bind(deviceId) : env.DB.prepare(sql);
  return (await statement.all<TargetRow>()).results;
}

function toTarget(row: TargetRow): Target {
  return {
    deviceId: row.device_id,
    pushToken: row.push_token,
    preferences: parseJson<RelayAgentAwarenessPreferences>(row.preferences_json),
    activityPushToken: row.activity_push_token,
    armedAt: row.armed_at,
    lastAggregate: parseJson<RelayAgentActivityAggregateState>(row.last_aggregate_json),
    lastDeliveryAt: row.last_delivery_at,
  };
}

function credentials(env: Env): Apns.ApnsCredentials {
  return { teamId: env.APNS_TEAM_ID, keyId: env.APNS_KEY_ID, privateKeyPem: env.APNS_PRIVATE_KEY };
}

async function deliver(
  env: Env,
  row: TargetRow,
  delivery: Delivery,
  now: Date,
): Promise<RelayDeliveryResult> {
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const request =
    delivery.kind === "push_notification"
      ? Apns.notificationRequest(delivery.notification)
      : delivery.kind === "live_activity_update"
        ? Apns.liveActivityRequest({
            event: "update",
            state: delivery.aggregate,
            alert: delivery.alert,
            nowSeconds,
          })
        : Apns.liveActivityRequest({ event: "end", state: null, alert: null, nowSeconds });
  const result = await Apns.send(
    credentials(env),
    {
      token: delivery.token,
      bundleId: row.bundle_id ?? "",
      environment: row.aps_environment === "sandbox" ? "sandbox" : "production",
    },
    request,
    nowSeconds,
  );
  const at = now.toISOString();
  if (result.ok && delivery.kind === "live_activity_update") {
    await env.DB.prepare(
      "UPDATE live_activities SET last_aggregate_json = ?2, last_delivery_at = ?3 WHERE device_id = ?1",
    )
      .bind(row.device_id, JSON.stringify(delivery.aggregate), at)
      .run();
  } else if (
    delivery.kind !== "push_notification" &&
    (result.ok || Apns.isPermanentTokenFailure(result))
  ) {
    await env.DB.prepare(
      "UPDATE live_activities SET activity_push_token = NULL, last_aggregate_json = NULL, last_delivery_at = ?2, ended_at = ?2 WHERE device_id = ?1",
    )
      .bind(row.device_id, at)
      .run();
  } else if (delivery.kind === "push_notification" && Apns.isPermanentTokenFailure(result)) {
    await env.DB.prepare("UPDATE devices SET push_token = NULL WHERE device_id = ?1")
      .bind(row.device_id)
      .run();
  }
  if (!result.ok) {
    console.error("APNs delivery failed", {
      deviceId: row.device_id,
      kind: delivery.kind,
      status: result.status,
      reason: result.reason,
    });
  }
  return {
    deviceId: row.device_id,
    kind: delivery.kind,
    ok: result.ok,
    apnsStatus: result.status === 0 ? null : result.status,
    apnsReason: result.reason,
    apnsId: result.apnsId,
  };
}

/** Sends each target what it should get for `state` (null for a replay or a removed thread). */
async function fanOut(
  env: Env,
  rows: TargetRow[],
  state: RelayAgentActivityState | null,
  replay: boolean,
): Promise<RelayDeliveryResult[]> {
  const now = new Date();
  const nowMs = now.getTime();
  const aggregate = makeAggregateState({
    activeStates: await activeStates(env),
    terminalState: state && isTerminalPhase(state) ? state : null,
    nowMs,
  });
  const results = await Promise.all(
    rows.map((row) => {
      const delivery = chooseDelivery({ target: toTarget(row), aggregate, state, nowMs, replay });
      return delivery ? deliver(env, row, delivery, now) : null;
    }),
  );
  return results.filter((result): result is RelayDeliveryResult => result !== null);
}

async function publish(
  request: Request,
  env: Env,
  environmentId: string,
  threadId: string,
): Promise<Response> {
  if (!(await sameSecret(bearer(request), env.RELAY_ENVIRONMENT_CREDENTIAL))) return unauthorized();
  const body = parseJson<{ state?: unknown }>(await request.text());
  // `state: null` removes the thread, so a body without `state` must not read as one.
  if (body === null || typeof body !== "object" || !("state" in body)) {
    console.error("Rejected a publish without a state", { environmentId, threadId });
    return badRequest("A publish needs a state, or null to remove the thread.");
  }
  const state = parseState(body.state, environmentId, threadId);
  if (state === "invalid") {
    console.error("Rejected a publish the relay couldn't read", { environmentId, threadId });
    return badRequest("The agent activity state isn't one this relay can read.");
  }
  if (state) {
    await env.DB.prepare(
      `INSERT INTO activity_rows (environment_id, thread_id, state_json, updated_at) VALUES (?1, ?2, ?3, ?4)
       ON CONFLICT (environment_id, thread_id) DO UPDATE SET state_json = ?3, updated_at = ?4`,
    )
      .bind(environmentId, threadId, JSON.stringify(state), state.updatedAt)
      .run();
  } else {
    await env.DB.prepare("DELETE FROM activity_rows WHERE environment_id = ?1 AND thread_id = ?2")
      .bind(environmentId, threadId)
      .run();
  }
  const deliveries = await fanOut(env, await targets(env), state, false);
  return json({ ok: true, deliveries });
}

async function exchangeToken(request: Request, env: Env): Promise<Response> {
  const form = new URLSearchParams(await request.text());
  if (!(await sameSecret(form.get("subject_token") ?? "", env.RELAY_CLIENT_SECRET)))
    return unauthorized();
  const scope = (form.get("scope") ?? "").trim();
  const scopes = scope.split(/\s+/).filter(Boolean);
  if (scopes.length === 0 || !scopes.every((name) => MOBILE_SCOPES.has(name))) {
    return json(
      { _tag: "RelayForbiddenError", message: "This relay grants mobile:registration only." },
      403,
    );
  }
  return json({
    access_token: await issueAccessToken(env, Math.floor(Date.now() / 1000)),
    issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
    token_type: "DPoP",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    scope,
  });
}

async function registerDevice(request: Request, env: Env): Promise<Response> {
  const body = parseJson<Record<string, unknown>>(await request.text());
  if (!body || !nonEmpty(body.deviceId) || !nonEmpty(body.label) || !nonEmpty(body.platform)) {
    return badRequest("A device needs an id, a label and a platform.");
  }
  const optional = (value: unknown) => (nonEmpty(value) ? value.trim() : null);
  await env.DB.prepare(
    `INSERT INTO devices (device_id, label, platform, bundle_id, aps_environment, push_token, preferences_json, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
     ON CONFLICT (device_id) DO UPDATE SET label = ?2, platform = ?3, bundle_id = ?4, aps_environment = ?5,
       push_token = ?6, preferences_json = ?7, updated_at = ?8`,
  )
    .bind(
      body.deviceId.trim(),
      body.label.trim(),
      body.platform.trim(),
      optional(body.bundleId),
      optional(body.apsEnvironment),
      optional(body.pushToken),
      JSON.stringify(body.preferences ?? null),
      new Date().toISOString(),
    )
    .run();
  return json({ ok: true });
}

async function registerLiveActivity(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  const body = parseJson<Record<string, unknown>>(await request.text());
  if (!body || !nonEmpty(body.deviceId) || !nonEmpty(body.activityPushToken)) {
    return badRequest("A Live Activity needs a device id and a push token.");
  }
  const deviceId = body.deviceId.trim();
  const token = body.activityPushToken.trim();
  // A new token is a new card: what the old one showed doesn't carry over.
  await env.DB.prepare(
    `INSERT INTO live_activities (device_id, activity_push_token, armed_at) VALUES (?1, ?2, ?3)
     ON CONFLICT (device_id) DO UPDATE SET
       armed_at = CASE WHEN activity_push_token IS ?2 THEN coalesce(armed_at, ?3) ELSE ?3 END,
       last_aggregate_json = CASE WHEN activity_push_token IS ?2 THEN last_aggregate_json ELSE NULL END,
       last_delivery_at = CASE WHEN activity_push_token IS ?2 THEN last_delivery_at ELSE NULL END,
       activity_push_token = ?2, ended_at = NULL`,
  )
    .bind(deviceId, token, new Date().toISOString())
    .run();
  // Paint the new card with what's happening now.
  ctx.waitUntil(targets(env, deviceId).then((rows) => fanOut(env, rows, null, true)));
  return json({ ok: true });
}

async function snapshot(env: Env): Promise<Response> {
  const aggregate = makeAggregateState({
    activeStates: await activeStates(env),
    terminalState: null,
    nowMs: Date.now(),
  });
  return json({ aggregate });
}

async function unregisterDevice(env: Env, deviceId: string): Promise<Response> {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM live_activities WHERE device_id = ?1").bind(deviceId),
    env.DB.prepare("DELETE FROM devices WHERE device_id = ?1").bind(deviceId),
  ]);
  return json({ ok: true });
}

/** Every 5 minutes: forget expired and long-finished threads, and end cards with nothing left to show. */
async function sweep(env: Env): Promise<void> {
  const nowMs = Date.now();
  const { results } = await env.DB.prepare(
    "SELECT environment_id, thread_id, state_json FROM activity_rows",
  ).all<{
    environment_id: string;
    thread_id: string;
    state_json: string;
  }>();
  const stale = results.filter((row) => {
    const state = parseJson<RelayAgentActivityState>(row.state_json);
    if (!state || isExpiredAgentActivityState(state, nowMs)) return true;
    return (
      isTerminalPhase(state) &&
      nowMs - Date.parse(state.updatedAt) > TERMINAL_AGENT_ACTIVITY_DISPLAY_TTL_MS
    );
  });
  if (stale.length > 0) {
    await env.DB.batch(
      stale.map((row) =>
        env.DB.prepare(
          "DELETE FROM activity_rows WHERE environment_id = ?1 AND thread_id = ?2",
        ).bind(row.environment_id, row.thread_id),
      ),
    );
  }
  // An idle card gets no more publishes to clear its finished rows, so end it here.
  const idleBefore = new Date(nowMs - TERMINAL_AGENT_ACTIVITY_DISPLAY_TTL_MS).toISOString();
  const idle = (await targets(env)).filter(
    (row) => row.activity_push_token && (row.last_delivery_at ?? row.armed_at ?? "") < idleBefore,
  );
  if (idle.length === 0) return;
  const aggregate = makeAggregateState({
    activeStates: await activeStates(env),
    terminalState: null,
    nowMs,
  });
  if (aggregate === null) await fanOut(env, idle, null, true);
}

const PUBLISH = /^\/v1\/environments\/([^/]+)\/threads\/([^/]+)\/agent-activity$/;
const WAKE = /^\/v1\/environments\/[^/]+\/hooks\/wake$/;
const DEVICE = /^\/v1\/mobile\/devices\/([^/]+)$/;

export async function handle(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const nowSeconds = Math.floor(Date.now() / 1000);

  if (path === "/health") return json({ ok: true });

  const published = PUBLISH.exec(path);
  if (published && method === "POST") {
    return publish(
      request,
      env,
      decodeURIComponent(published[1]!),
      decodeURIComponent(published[2]!),
    );
  }
  // Only tunnels hold webhooks, and this relay runs none.
  if (WAKE.test(path) && method === "POST") {
    return (await sameSecret(bearer(request), env.RELAY_ENVIRONMENT_CREDENTIAL))
      ? json({ pending: false })
      : unauthorized();
  }
  if (path === "/v1/client/dpop-token" && method === "POST") return exchangeToken(request, env);
  // The app's telemetry goes to the relay's origin; there's nowhere to keep it, so it's dropped.
  if (path === "/v1/mobile/observe") return new Response(null, { status: 204 });

  if (path.startsWith("/v1/mobile/")) {
    if (!(await verifyAccessToken(env, request.headers.get("authorization"), nowSeconds)))
      return unauthorized();
    if (path === "/v1/mobile/devices" && method === "POST") return registerDevice(request, env);
    if (path === "/v1/mobile/live-activities" && method === "POST")
      return registerLiveActivity(request, env, ctx);
    if (path === "/v1/mobile/agent-activity" && method === "GET") return snapshot(env);
    const device = DEVICE.exec(path);
    if (device && method === "DELETE") return unregisterDevice(env, decodeURIComponent(device[1]!));
  }
  return json({ _tag: "RelayNotFoundError", message: "Not found." }, 404);
}

export default {
  fetch: (request, env, ctx) =>
    handle(request, env, ctx).catch((error: unknown) => {
      console.error("Relay request failed", error instanceof Error ? error.stack : String(error));
      return json({ _tag: "RelayInternalError", message: "The relay failed." }, 500);
    }),
  scheduled: (_controller, env, ctx) => {
    ctx.waitUntil(sweep(env));
  },
} satisfies ExportedHandler<Env>;
