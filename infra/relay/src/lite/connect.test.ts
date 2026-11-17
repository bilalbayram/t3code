import * as NodeCrypto from "@effect/platform-node/NodeCrypto";
import { describe, expect, it } from "@effect/vitest";
import { RelayCloudMintCredentialProofPayload } from "@t3tools/contracts/relay";
import {
  RELAY_HEALTH_REQUEST_TYP,
  RELAY_MINT_REQUEST_TYP,
  verifyRelayJwt,
} from "@t3tools/shared/relayJwt";
import * as Effect from "effect/Effect";
import * as TestClock from "effect/testing/TestClock";

import {
  CLOUD_USER_ID,
  mintKey,
  mintRequestProof,
  RELAY_HEALTH_REQUEST_TYP as LITE_HEALTH_TYP,
  RELAY_MINT_REQUEST_TYP as LITE_MINT_TYP,
} from "./connect.ts";

const NOW_SECONDS = 1_794_000_000;

const generateMintKey = Effect.promise(async () => {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  return mintKey(
    `-----BEGIN PRIVATE KEY-----\n${Buffer.from(der).toString("base64")}\n-----END PRIVATE KEY-----\n`,
  );
});

describe("relay-lite connect", () => {
  it.effect("signs a mint request the server's own verifier accepts", () =>
    Effect.gen(function* () {
      const key = yield* generateMintKey;
      const token = yield* Effect.promise(() =>
        mintRequestProof({
          key,
          issuer: "https://relay.example.com",
          environmentId: "env-1",
          clientProofKeyThumbprint: "thumb",
          deviceId: "phone",
          nowSeconds: NOW_SECONDS,
        }),
      );
      yield* TestClock.setTime(NOW_SECONDS * 1000);
      const claims = yield* verifyRelayJwt(RelayCloudMintCredentialProofPayload, {
        publicKey: key.publicKeyPem,
        token,
        typ: RELAY_MINT_REQUEST_TYP,
        issuer: "https://relay.example.com",
        audience: "t3-env:env-1",
      });
      expect(claims).toMatchObject({
        sub: CLOUD_USER_ID,
        environmentId: "env-1",
        clientProofKeyThumbprint: "thumb",
        cnf: { jkt: "thumb" },
        deviceId: "phone",
        scope: ["environment:connect"],
      });
      expect(claims.exp - claims.iat).toBe(120);
    }).pipe(Effect.provide(NodeCrypto.layerSignature)),
  );

  it("uses the JWT types the server checks", () => {
    expect(LITE_MINT_TYP).toBe(RELAY_MINT_REQUEST_TYP);
    expect(LITE_HEALTH_TYP).toBe(RELAY_HEALTH_REQUEST_TYP);
  });
});
