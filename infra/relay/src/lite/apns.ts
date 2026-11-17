// @effect-diagnostics globalFetch:off -- A plain Worker outside the relay's Effect runtime.
// APNs requests, built the same way as the managed relay's ApnsClient (infra/relay), so the app's
// notification handler and Live Activity widget read them unchanged.

import type { RelayAgentActivityAggregateState } from "@t3tools/contracts/relay";

import { MAX_SUMMARY_TEXT_LENGTH, truncateText } from "../agentActivity/agentActivityPayloads.ts";
import type { ApnsNotificationPayload } from "../agentActivity/apnsDeliveryJobs.ts";

const LIVE_ACTIVITY_NAME = "AgentActivity";
const STALE_AFTER_SECONDS = 10 * 60;
const DISMISS_AFTER_SECONDS = 5 * 60;
const CONTENTLESS_DISMISS_AFTER_SECONDS = 15;
const MAX_LIVE_ACTIVITY_PAYLOAD_BYTES = 4096;
const MIN_FITTED_TEXT_LENGTH = 8;
// Apple accepts provider tokens for an hour and rejects refreshing more than every 20 minutes.
const PROVIDER_TOKEN_TTL_SECONDS = 45 * 60;

export interface ApnsAlert {
  readonly title: string;
  readonly body: string;
}

export interface ApnsCredentials {
  readonly teamId: string;
  readonly keyId: string;
  readonly privateKeyPem: string;
}

export interface ApnsTarget {
  readonly token: string;
  readonly bundleId: string;
  readonly environment: "sandbox" | "production";
}

export interface ApnsRequest {
  readonly pushType: "alert" | "liveactivity";
  readonly priority: "5" | "10";
  readonly payload: unknown;
}

export interface ApnsResult {
  readonly ok: boolean;
  readonly status: number;
  readonly reason: string | null;
  readonly apnsId: string | null;
}

function contentState(state: RelayAgentActivityAggregateState) {
  return { name: LIVE_ACTIVITY_NAME, props: JSON.stringify(state) };
}

function alertPayload(alert: ApnsAlert) {
  return { alert: { title: alert.title, body: alert.body, sound: "default" } };
}

type LiveActivityInput =
  | {
      readonly event: "end";
      readonly state: RelayAgentActivityAggregateState | null;
      readonly alert: ApnsAlert | null;
      readonly nowSeconds: number;
    }
  | {
      readonly event: "update";
      readonly state: RelayAgentActivityAggregateState;
      readonly alert: ApnsAlert | null;
      readonly nowSeconds: number;
    };

function buildLiveActivityRequest(input: LiveActivityInput): ApnsRequest {
  const timestamp = input.nowSeconds;
  if (input.event === "end") {
    return {
      pushType: "liveactivity",
      priority: "10",
      payload: {
        aps: {
          timestamp,
          event: "end",
          ...(input.state ? { "content-state": contentState(input.state) } : {}),
          ...(input.alert ? alertPayload(input.alert) : {}),
          "dismissal-date":
            timestamp + (input.state ? DISMISS_AFTER_SECONDS : CONTENTLESS_DISMISS_AFTER_SECONDS),
        },
      },
    };
  }
  return {
    pushType: "liveactivity",
    priority: input.alert ? "10" : "5",
    payload: {
      aps: {
        timestamp,
        event: "update",
        ...(input.alert ? alertPayload(input.alert) : {}),
        "content-state": contentState(input.state),
        "stale-date": timestamp + STALE_AFTER_SECONDS,
      },
    },
  };
}

function fits(request: ApnsRequest): boolean {
  return (
    new TextEncoder().encode(JSON.stringify(request.payload)).byteLength <=
    MAX_LIVE_ACTIVITY_PAYLOAD_BYTES
  );
}

// Text caps count characters, so multibyte titles can overflow APNs' 4 KB limit: shorten the text,
// then drop the lowest rows, until the payload fits.
export function liveActivityRequest(input: LiveActivityInput): ApnsRequest {
  let request = buildLiveActivityRequest(input);
  const state = input.state;
  if (state === null) return request;
  let rowCount = state.activities.length;
  let maxTextLength = MAX_SUMMARY_TEXT_LENGTH;
  while (!fits(request) && (rowCount > 0 || maxTextLength > MIN_FITTED_TEXT_LENGTH)) {
    if (maxTextLength > MIN_FITTED_TEXT_LENGTH) {
      maxTextLength = Math.floor(maxTextLength * 0.8);
    } else {
      rowCount -= 1;
      maxTextLength = MAX_SUMMARY_TEXT_LENGTH;
    }
    const length = maxTextLength;
    request = buildLiveActivityRequest({
      ...input,
      state: {
        ...state,
        activities: state.activities.slice(0, rowCount).map((row) => ({
          ...row,
          projectTitle: truncateText(row.projectTitle, length),
          threadTitle: truncateText(row.threadTitle, length),
          modelTitle: truncateText(row.modelTitle, length),
        })),
      },
      alert: input.alert
        ? {
            title: truncateText(input.alert.title, length),
            body: truncateText(input.alert.body, length),
          }
        : null,
    } as LiveActivityInput);
  }
  return request;
}

export function notificationRequest(notification: ApnsNotificationPayload): ApnsRequest {
  return {
    pushType: "alert",
    priority: "10",
    payload: {
      aps: {
        alert: { title: notification.title, body: notification.body },
        sound: "default",
        "thread-id":
          notification.threadId.length > 0
            ? `${notification.environmentId}/${notification.threadId}`
            : "t3-agent-alerts",
      },
      // Expo iOS exposes userInfo.body as notification.content.data for remote pushes.
      body: {
        environmentId: notification.environmentId,
        threadId: notification.threadId,
        deepLink: notification.deepLink,
      },
    },
  };
}

function base64url(bytes: ArrayBuffer | Uint8Array): string {
  const array = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const byte of array) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemToDer(pem: string): Uint8Array<ArrayBuffer> {
  const body = pem.replace(/-----(BEGIN|END) [A-Z ]+-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(body), (char) => char.charCodeAt(0));
}

let cachedProviderToken: {
  readonly keyId: string;
  readonly token: string;
  readonly issuedAt: number;
} | null = null;

/** The ES256 provider token APNs takes in place of a certificate, kept for 45 minutes. */
export async function providerToken(
  credentials: ApnsCredentials,
  nowSeconds: number,
): Promise<string> {
  if (
    cachedProviderToken &&
    cachedProviderToken.keyId === credentials.keyId &&
    nowSeconds - cachedProviderToken.issuedAt < PROVIDER_TOKEN_TTL_SECONDS
  ) {
    return cachedProviderToken.token;
  }
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(credentials.privateKeyPem),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const encoder = new TextEncoder();
  const header = base64url(
    encoder.encode(JSON.stringify({ alg: "ES256", kid: credentials.keyId })),
  );
  const claims = base64url(
    encoder.encode(JSON.stringify({ iss: credentials.teamId, iat: nowSeconds })),
  );
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    encoder.encode(`${header}.${claims}`),
  );
  const token = `${header}.${claims}.${base64url(signature)}`;
  cachedProviderToken = { keyId: credentials.keyId, token, issuedAt: nowSeconds };
  return token;
}

export async function send(
  credentials: ApnsCredentials,
  target: ApnsTarget,
  request: ApnsRequest,
  nowSeconds: number,
): Promise<ApnsResult> {
  const host =
    target.environment === "sandbox" ? "api.sandbox.push.apple.com" : "api.push.apple.com";
  try {
    const response = await fetch(`https://${host}/3/device/${target.token}`, {
      method: "POST",
      headers: {
        authorization: `bearer ${await providerToken(credentials, nowSeconds)}`,
        "apns-push-type": request.pushType,
        "apns-topic":
          request.pushType === "liveactivity"
            ? `${target.bundleId}.push-type.liveactivity`
            : target.bundleId,
        "apns-priority": request.priority,
        "content-type": "application/json",
      },
      body: JSON.stringify(request.payload),
    });
    const text = await response.text();
    let reason: string | null = null;
    if (text.trim().length > 0) {
      try {
        reason = (JSON.parse(text) as { reason?: string }).reason ?? null;
      } catch {
        reason = text.slice(0, 200);
      }
    }
    return {
      ok: response.ok,
      status: response.status,
      reason,
      apnsId: response.headers.get("apns-id"),
    };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      reason: error instanceof Error ? error.message : String(error),
      apnsId: null,
    };
  }
}

const PERMANENT_TOKEN_REASONS = new Set([
  "BadDeviceToken",
  "DeviceTokenNotForTopic",
  "Unregistered",
]);

/** Whether APNs said the token will never work again, so it should be forgotten. */
export function isPermanentTokenFailure(result: ApnsResult): boolean {
  return (
    !result.ok &&
    (result.status === 410 ||
      (result.status === 400 &&
        result.reason !== null &&
        PERMANENT_TOKEN_REASONS.has(result.reason)))
  );
}
