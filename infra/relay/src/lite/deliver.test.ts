// @effect-diagnostics globalDate:off -- Fixed instants for the plain functions under test.
import { describe, expect, it } from "@effect/vitest";
import { EnvironmentId, ThreadId } from "@t3tools/contracts";
import type { RelayAgentActivityState } from "@t3tools/contracts/relay";

import { makeAggregateState } from "../agentActivity/agentActivityAggregate.ts";
import { liveActivityRequest, notificationRequest } from "./apns.ts";
import { chooseDelivery, type Target } from "./deliver.ts";

const NOW = Date.parse("2026-11-17T12:00:00.000Z");
const at = (offsetMs: number) => new Date(NOW + offsetMs).toISOString();

const running: RelayAgentActivityState = {
  environmentId: EnvironmentId.make("env"),
  threadId: ThreadId.make("thread"),
  projectTitle: "bayram.io",
  threadTitle: "Agent notifications",
  modelTitle: "Opus",
  headline: "Working",
  phase: "running",
  updatedAt: at(-1_000),
  deepLink: "/threads/env/thread",
};
const preferences = {
  notificationsEnabled: true,
  liveActivitiesEnabled: true,
  notifyOnApproval: true,
  notifyOnInput: true,
  notifyOnCompletion: true,
  notifyOnFailure: true,
};
const phone: Target = {
  deviceId: "phone",
  pushToken: "push-token",
  preferences,
  activityPushToken: null,
  armedAt: null,
  lastAggregate: null,
  lastDeliveryAt: null,
};
const aggregateOf = (
  states: RelayAgentActivityState[],
  terminal: RelayAgentActivityState | null = null,
) => makeAggregateState({ activeStates: states, terminalState: terminal, nowMs: NOW });

describe("relay-lite deliveries", () => {
  it("sends a phone without a Live Activity a notification that opens the thread when approval is needed", () => {
    const waiting = { ...running, phase: "waiting_for_approval" as const };
    const delivery = chooseDelivery({
      target: phone,
      aggregate: aggregateOf([waiting]),
      state: waiting,
      nowMs: NOW,
      replay: false,
    });
    expect(delivery).toMatchObject({
      kind: "push_notification",
      token: "push-token",
      notification: {
        title: "Agent notifications",
        body: "Approval: bayram.io",
        deepLink: "/threads/env/thread",
      },
    });
    if (delivery?.kind !== "push_notification") throw new Error("expected a notification");
    expect(notificationRequest(delivery.notification).payload).toMatchObject({
      aps: { "thread-id": "env/thread" },
      body: { environmentId: "env", threadId: "thread", deepLink: "/threads/env/thread" },
    });
  });

  it("stays quiet about a thread that is just running", () => {
    expect(
      chooseDelivery({
        target: phone,
        aggregate: aggregateOf([running]),
        state: running,
        nowMs: NOW,
        replay: false,
      }),
    ).toBeNull();
  });

  it("carries the alert inside the Live Activity update instead of a separate notification", () => {
    const card: Target = {
      ...phone,
      activityPushToken: "activity-token",
      armedAt: at(-60_000),
      lastAggregate: aggregateOf([running]),
      lastDeliveryAt: at(-30_000),
    };
    const done = { ...running, phase: "completed" as const, updatedAt: at(-500) };
    const delivery = chooseDelivery({
      target: card,
      aggregate: aggregateOf([done], done),
      state: done,
      nowMs: NOW,
      replay: false,
    });
    expect(delivery).toMatchObject({
      kind: "live_activity_update",
      token: "activity-token",
      alert: { title: "Agent notifications", body: "Done: bayram.io" },
    });
  });

  it("doesn't resend an unchanged card, and doesn't fall back to a notification", () => {
    const aggregate = aggregateOf([running]);
    const card: Target = {
      ...phone,
      activityPushToken: "activity-token",
      lastAggregate: aggregate,
      lastDeliveryAt: at(-1_000),
    };
    expect(
      chooseDelivery({ target: card, aggregate, state: running, nowMs: NOW, replay: false }),
    ).toBeNull();
  });

  it("keeps a freshly armed card with nothing to show, and ends one that has gone idle", () => {
    const armed: Target = { ...phone, activityPushToken: "activity-token", armedAt: at(-30_000) };
    expect(
      chooseDelivery({ target: armed, aggregate: null, state: null, nowMs: NOW, replay: true }),
    ).toBeNull();
    expect(
      chooseDelivery({
        target: { ...armed, armedAt: at(-10 * 60_000) },
        aggregate: null,
        state: null,
        nowMs: NOW,
        replay: true,
      }),
    ).toEqual({ kind: "live_activity_end", token: "activity-token" });
  });

  it("fits a Live Activity update of long multibyte titles into APNs' 4 KB", () => {
    const long = "çğışöü🙂".repeat(40);
    const states = Array.from({ length: 5 }, (_, index) => ({
      ...running,
      threadId: ThreadId.make(`thread-${index}`),
      threadTitle: long,
      projectTitle: long,
      modelTitle: long,
    }));
    const request = liveActivityRequest({
      event: "update",
      state: aggregateOf(states)!,
      alert: { title: long, body: long },
      nowSeconds: NOW / 1000,
    });
    expect(
      new TextEncoder().encode(JSON.stringify(request.payload)).byteLength,
    ).toBeLessThanOrEqual(4096);
    expect(request.payload).toMatchObject({
      aps: { event: "update", "content-state": { name: "AgentActivity" } },
    });
  });
});
