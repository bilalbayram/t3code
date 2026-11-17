// What a device gets for a publish, decided as the managed relay's ApnsDeliveries decides it: a
// running Live Activity gets an update (carrying the alert when one is due) or an end, and only a
// device without one gets an ordinary notification. Plain functions, tested in deliver.test.ts.

import type {
  RelayAgentActivityAggregateState,
  RelayAgentActivityState,
  RelayAgentAwarenessPreferences,
} from "@t3tools/contracts/relay";

import { statusForPhase } from "../agentActivity/agentActivityAggregate.ts";
import {
  alertForAttentionTransition,
  alertForNewlyTerminal,
  rowPhasesChanged,
  shouldAlertForActivity,
} from "../agentActivity/agentActivityAlerts.ts";
import {
  isExpiredAgentActivityState,
  notificationForActivity,
} from "../agentActivity/agentActivityPayloads.ts";
import type { ApnsNotificationPayload } from "../agentActivity/apnsDeliveryJobs.ts";
import type { ApnsAlert } from "./apns.ts";

const MIN_LIVE_ACTIVITY_UPDATE_INTERVAL_MS = 15_000;
const FRESHLY_ARMED_GRACE_MS = 2 * 60 * 1_000;

/** A device and its Live Activity, as stored. */
export interface Target {
  readonly deviceId: string;
  readonly pushToken: string | null;
  readonly preferences: RelayAgentAwarenessPreferences | null;
  readonly activityPushToken: string | null;
  readonly armedAt: string | null;
  readonly lastAggregate: RelayAgentActivityAggregateState | null;
  readonly lastDeliveryAt: string | null;
}

export type Delivery =
  | {
      readonly kind: "live_activity_update";
      readonly token: string;
      readonly aggregate: RelayAgentActivityAggregateState;
      readonly alert: ApnsAlert | null;
    }
  | { readonly kind: "live_activity_end"; readonly token: string }
  | {
      readonly kind: "push_notification";
      readonly token: string;
      readonly notification: ApnsNotificationPayload;
    };

function millis(iso: string | null): number | null {
  if (iso === null) return null;
  const value = Date.parse(iso);
  return Number.isNaN(value) ? null : value;
}

function needsAttention(aggregate: RelayAgentActivityAggregateState): boolean {
  return aggregate.activities.some(
    (row) => row.phase === "waiting_for_approval" || row.phase === "waiting_for_input",
  );
}

export function shouldUpdateLiveActivity(input: {
  readonly previous: RelayAgentActivityAggregateState | null;
  readonly next: RelayAgentActivityAggregateState;
  readonly lastDeliveryAt: string | null;
  readonly nowMs: number;
}): boolean {
  if (!input.previous) return true;
  if (JSON.stringify(input.previous) === JSON.stringify(input.next)) return false;
  if (input.previous.activeCount !== input.next.activeCount) return true;
  if (needsAttention(input.next)) return true;
  // A phase change may be the last update until the next transition; throttling it would leave the card stale.
  if (rowPhasesChanged(input.previous, input.next)) return true;
  const last = millis(input.lastDeliveryAt);
  return last === null || input.nowMs - last >= MIN_LIVE_ACTIVITY_UPDATE_INTERVAL_MS;
}

function liveActivityDelivery(input: {
  readonly target: Target;
  readonly aggregate: RelayAgentActivityAggregateState | null;
  readonly nowMs: number;
  readonly replay: boolean;
}): Delivery | "suppressed" | null {
  const { target } = input;
  if (target.preferences?.liveActivitiesEnabled === false) {
    return target.activityPushToken
      ? { kind: "live_activity_end", token: target.activityPushToken }
      : null;
  }
  if (!target.activityPushToken) return null;
  if (input.aggregate === null) {
    // A registration replay can come before a new thread's first publish; keep a freshly armed card.
    const armedAt = millis(target.armedAt);
    if (armedAt !== null && input.nowMs - armedAt < FRESHLY_ARMED_GRACE_MS) return null;
    return { kind: "live_activity_end", token: target.activityPushToken };
  }
  const next = input.aggregate;
  const previous = target.lastAggregate;
  if (
    !shouldUpdateLiveActivity({
      previous,
      next,
      lastDeliveryAt: target.lastDeliveryAt,
      nowMs: input.nowMs,
    })
  ) {
    // A suppressed update must not fall back to an alert push, or unchanged replays would ring.
    return "suppressed";
  }
  return {
    kind: "live_activity_update",
    token: target.activityPushToken,
    aggregate: next,
    alert: input.replay
      ? null
      : (alertForAttentionTransition({
          previousAggregate: previous,
          nextAggregate: next,
          preferences: target.preferences,
        }) ??
        alertForNewlyTerminal({
          previousAggregate: previous,
          nextAggregate: next,
          preferences: target.preferences,
          nowMs: input.nowMs,
          includeUnobserved: true,
        })),
  };
}

function notificationForState(
  target: Target,
  state: RelayAgentActivityState | null,
  nowMs: number,
): ApnsNotificationPayload | null {
  if (!target.pushToken || !state || isExpiredAgentActivityState(state, nowMs)) return null;
  if (
    !shouldAlertForActivity({
      phase: state.phase,
      updatedAt: state.updatedAt,
      preferences: target.preferences,
      nowMs,
    })
  ) {
    return null;
  }
  return notificationForActivity({ ...state, status: statusForPhase(state.phase) });
}

/** What to send `target` for a publish of `state` (null for a replay or a removed thread). */
export function chooseDelivery(input: {
  readonly target: Target;
  readonly aggregate: RelayAgentActivityAggregateState | null;
  readonly state: RelayAgentActivityState | null;
  readonly nowMs: number;
  readonly replay: boolean;
}): Delivery | null {
  const live = liveActivityDelivery(input);
  if (live === "suppressed") return null;
  if (live) return live;
  const notification = input.replay
    ? null
    : notificationForState(input.target, input.state, input.nowMs);
  return notification && input.target.pushToken
    ? { kind: "push_notification", token: input.target.pushToken, notification }
    : null;
}
