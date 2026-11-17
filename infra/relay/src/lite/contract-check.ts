// @effect-diagnostics globalDate:off globalConsole:off globalConsoleInEffect:off globalDateInEffect:off globalJsonInEffect:off -- A one-off script against a local relay.
// Drives a running relay lite with the same typed client the server and the app use, so a response
// the app couldn't decode fails here rather than on a phone. From infra/relay:
//   node src/lite/contract-check.ts http://localhost:8799 <client secret> <environment credential>

import { EnvironmentId, ThreadId } from "@t3tools/contracts";
import {
  RelayAccessTokenType,
  RelayApi,
  RelayDpopTokenExchangeGrantType,
  RelayJwtSubjectTokenType,
} from "@t3tools/contracts/relay";
import * as Effect from "effect/Effect";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";
import * as HttpApiClient from "effect/http-api/HttpApiClient";

const [baseUrl = "http://localhost:8799", clientSecret = "client-secret", credential = "env-cred"] =
  process.argv.slice(2);

const environmentId = EnvironmentId.make("env-contract");
const threadId = ThreadId.make("thread-contract");
const preferences = {
  notificationsEnabled: true,
  liveActivitiesEnabled: true,
  notifyOnApproval: true,
  notifyOnInput: true,
  notifyOnCompletion: true,
  notifyOnFailure: true,
};

const program = Effect.gen(function* () {
  const client = yield* HttpApiClient.make(RelayApi, { baseUrl });
  const server = yield* HttpApiClient.make(RelayApi, {
    baseUrl,
    transformClient: HttpClient.mapRequest(
      HttpClientRequest.setHeader("authorization", `Bearer ${credential}`),
    ),
  });

  const token = yield* client.token.exchangeDpopAccessToken({
    headers: { dpop: "proof" },
    payload: {
      grant_type: RelayDpopTokenExchangeGrantType,
      subject_token: clientSecret,
      subject_token_type: RelayJwtSubjectTokenType,
      requested_token_type: RelayAccessTokenType,
      resource: baseUrl,
      scope: "mobile:registration",
      client_id: "t3-mobile",
    },
  });
  console.log("token exchange", token.token_type, token.scope, token.expires_in);
  const headers = { authorization: `DPoP ${token.access_token}`, dpop: "proof" };

  console.log(
    "register device",
    yield* client.mobile.registerDevice({
      headers,
      payload: {
        deviceId: "contract-phone",
        label: "Contract phone",
        platform: "ios",
        iosMajorVersion: 26,
        bundleId: "io.example.t3code",
        apsEnvironment: "production",
        pushToken: "00aa",
        preferences,
      },
    }),
  );

  const published = yield* server.server.publishAgentActivity({
    params: { environmentId, threadId },
    payload: {
      proof: "unchecked",
      state: {
        environmentId,
        threadId,
        projectTitle: "Project",
        threadTitle: "Contract thread",
        phase: "waiting_for_input",
        headline: "Needs input",
        modelTitle: "Model",
        updatedAt: new Date().toISOString(),
        deepLink: `/threads/${environmentId}/${threadId}`,
      },
    },
  });
  console.log("publish", JSON.stringify(published));

  const snapshot = yield* client.mobile.getAgentActivitySnapshot({ headers });
  console.log(
    "snapshot",
    snapshot.aggregate?.activeCount,
    snapshot.aggregate?.activities[0]?.status,
  );

  console.log(
    "register live activity",
    yield* client.mobile.registerLiveActivity({
      headers,
      payload: { deviceId: "contract-phone", activityPushToken: "00bb" },
    }),
  );

  console.log(
    "remove thread",
    JSON.stringify(
      yield* server.server.publishAgentActivity({
        params: { environmentId, threadId },
        payload: { proof: "unchecked", state: null },
      }),
    ),
  );
  console.log(
    "unregister device",
    yield* client.mobile.unregisterDevice({ headers, params: { deviceId: "contract-phone" } }),
  );
});

Effect.runPromise(program.pipe(Effect.provide(FetchHttpClient.layer))).then(
  () => console.log("contract ok"),
  (error: unknown) => {
    console.error("contract failed", error);
    process.exitCode = 1;
  },
);
