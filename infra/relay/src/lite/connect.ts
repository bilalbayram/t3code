// @effect-diagnostics globalFetch:off globalDate:off cryptoRandomUUID:off -- A plain Worker outside the relay's Effect runtime.
// The T3 Connect half of relay lite: the app lists your T3 servers here, and the relay asks a
// server, through its tunnel, for a credential bound to the app's proof key. The JWTs are the
// managed relay's (EnvironmentConnector), signed with the relay's Ed25519 mint key, which each
// server holds the public half of.

import type {
  RelayCloudEnvironmentHealthProofPayload,
  RelayCloudMintCredentialProofPayload,
  RelayClientEnvironmentRecord,
  RelayManagedEndpoint,
} from "@t3tools/contracts/relay";

// The JWT types from @t3tools/shared/relayJwt, copied so the Worker doesn't bundle its Effect crypto.
export const RELAY_MINT_REQUEST_TYP = "t3-cloud-mint+jwt";
export const RELAY_HEALTH_REQUEST_TYP = "t3-cloud-health+jwt";

/** The account every server here is linked to; `link-server.sh` writes the same id. */
export const CLOUD_USER_ID = "self-hosted";
const PROOF_LIFETIME_SECONDS = 120;
const ENVIRONMENT_TIMEOUT_MS = 10_000;

const encoder = new TextEncoder();

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64url(value: string): Uint8Array<ArrayBuffer> {
  const padded = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

function pemBody(pem: string): Uint8Array<ArrayBuffer> {
  const body = pem
    .replace(/\\n/g, "\n")
    .replace(/-----(BEGIN|END) [A-Z ]+-----/g, "")
    .replace(/\s+/g, "");
  return Uint8Array.from(atob(body), (char) => char.charCodeAt(0));
}

// SPKI for an Ed25519 key is this fixed header and the 32-byte key.
const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

export interface MintKey {
  readonly privateKey: CryptoKey;
  readonly publicKeyPem: string;
}

let cachedMintKey: { readonly pem: string; readonly key: MintKey } | null = null;

/** The relay's Ed25519 mint key from its PKCS#8 PEM, with the SPKI PEM servers verify against. */
export async function mintKey(privateKeyPem: string): Promise<MintKey> {
  if (cachedMintKey?.pem === privateKeyPem) return cachedMintKey.key;
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pemBody(privateKeyPem),
    { name: "Ed25519" },
    true,
    ["sign"],
  );
  const jwk = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
  const raw = fromBase64url(jwk.x ?? "");
  const spki = new Uint8Array(ED25519_SPKI_PREFIX.length + raw.length);
  spki.set(ED25519_SPKI_PREFIX);
  spki.set(raw, ED25519_SPKI_PREFIX.length);
  const lines = btoa(String.fromCharCode(...spki)).match(/.{1,64}/g) ?? [];
  const key = {
    privateKey: await crypto.subtle.importKey(
      "pkcs8",
      pemBody(privateKeyPem),
      { name: "Ed25519" },
      false,
      ["sign"],
    ),
    publicKeyPem: `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`,
  };
  cachedMintKey = { pem: privateKeyPem, key };
  return key;
}

export async function signJwt(key: CryptoKey, typ: string, payload: object): Promise<string> {
  const header = base64url(encoder.encode(JSON.stringify({ alg: "EdDSA", typ })));
  const body = base64url(encoder.encode(JSON.stringify(payload)));
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, key, encoder.encode(`${header}.${body}`)),
  );
  return `${header}.${body}.${base64url(signature)}`;
}

/** The issuer servers expect: the relay's origin, as `normalizeRelayIssuer` writes it. */
export function relayIssuer(requestUrl: string): string {
  return new URL(requestUrl).origin.replace(/\/+$/, "");
}

export interface EnvironmentRow {
  readonly environment_id: string;
  readonly label: string;
  readonly http_base_url: string;
  readonly ws_base_url: string;
  readonly lan_url: string | null;
  readonly linked_at: string;
}

export function endpointOf(row: EnvironmentRow): RelayManagedEndpoint {
  return { httpBaseUrl: row.http_base_url, wsBaseUrl: row.ws_base_url, providerKind: "manual" };
}

export function recordOf(row: EnvironmentRow): RelayClientEnvironmentRecord {
  return {
    environmentId: row.environment_id as RelayClientEnvironmentRecord["environmentId"],
    label: row.label,
    endpoint: endpointOf(row),
    linkedAt: row.linked_at,
    ...(row.lan_url ? { lanHttpBaseUrl: row.lan_url } : {}),
  };
}

function claims(input: {
  readonly issuer: string;
  readonly environmentId: string;
  readonly nowSeconds: number;
}) {
  return {
    iss: input.issuer,
    aud: `t3-env:${input.environmentId}`,
    sub: CLOUD_USER_ID,
    jti: crypto.randomUUID(),
    iat: input.nowSeconds,
    exp: input.nowSeconds + PROOF_LIFETIME_SECONDS,
    environmentId: input.environmentId,
    nonce: crypto.randomUUID(),
  };
}

export type EnvironmentCall<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly status: number | null; readonly error: string };

async function callEnvironment<T>(
  row: EnvironmentRow,
  path: string,
  proof: string,
): Promise<EnvironmentCall<T>> {
  try {
    const response = await fetch(new URL(path, row.http_base_url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ proof }),
      redirect: "manual",
      signal: AbortSignal.timeout(ENVIRONMENT_TIMEOUT_MS),
    });
    const text = await response.text();
    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        error: `The server answered ${response.status}: ${text.slice(0, 200)}`,
      };
    }
    return { ok: true, value: JSON.parse(text) as T };
  } catch (error) {
    return {
      ok: false,
      status: null,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/** The relay-signed request a server checks before minting a credential for the app's proof key. */
export function mintRequestProof(input: {
  readonly key: MintKey;
  readonly issuer: string;
  readonly environmentId: string;
  readonly clientProofKeyThumbprint: string;
  readonly deviceId: string | null;
  readonly nowSeconds: number;
}): Promise<string> {
  const payload = {
    ...claims(input),
    clientProofKeyThumbprint: input.clientProofKeyThumbprint,
    cnf: { jkt: input.clientProofKeyThumbprint },
    ...(input.deviceId ? { deviceId: input.deviceId } : {}),
    scope: ["environment:connect"],
  } satisfies Omit<RelayCloudMintCredentialProofPayload, "environmentId"> & {
    environmentId: string;
  };
  return signJwt(input.key.privateKey, RELAY_MINT_REQUEST_TYP, payload);
}

/** Asks the server for a connect credential bound to the app's proof key. */
export async function mintCredential(input: {
  readonly key: MintKey;
  readonly issuer: string;
  readonly row: EnvironmentRow;
  readonly clientProofKeyThumbprint: string;
  readonly deviceId: string | null;
}): Promise<EnvironmentCall<{ readonly credential: string; readonly expiresAt: string }>> {
  const proof = await mintRequestProof({
    key: input.key,
    issuer: input.issuer,
    environmentId: input.row.environment_id,
    clientProofKeyThumbprint: input.clientProofKeyThumbprint,
    deviceId: input.deviceId,
    nowSeconds: Math.floor(Date.now() / 1000),
  });
  return callEnvironment(input.row, "/api/t3-connect/mint-credential", proof);
}

/** Asks the server whether it's up, through the same tunnel the app would use. */
export async function checkHealth(input: {
  readonly key: MintKey;
  readonly issuer: string;
  readonly row: EnvironmentRow;
}): Promise<EnvironmentCall<{ readonly descriptor: unknown; readonly checkedAt: string }>> {
  const payload = {
    ...claims({
      issuer: input.issuer,
      environmentId: input.row.environment_id,
      nowSeconds: Math.floor(Date.now() / 1000),
    }),
    scope: ["environment:status"],
  } as unknown as RelayCloudEnvironmentHealthProofPayload;
  const proof = await signJwt(input.key.privateKey, RELAY_HEALTH_REQUEST_TYP, payload);
  return callEnvironment(input.row, "/api/t3-connect/health", proof);
}
