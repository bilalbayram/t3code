import { describe, expect, it, vi } from "vite-plus/test";

import { resolveCloudPublicConfig, selfHostedRelayToken } from "./publicConfig";

vi.mock("expo-constants", () => ({
  default: {
    expoConfig: {
      extra: {},
    },
  },
}));

describe("resolveCloudPublicConfig", () => {
  it("rejects an insecure relay URL", () => {
    expect(
      resolveCloudPublicConfig({
        clerk: { publishableKey: "pk_test_example", jwtTemplate: "t3-relay" },
        relay: { url: "http://relay.example.test" },
      }),
    ).toEqual({
      clerk: {
        publishableKey: "pk_test_example",
        jwtTemplate: "t3-relay",
      },
      relay: {
        url: null,
        selfHostedToken: null,
      },
      observability: {
        tracesUrl: null,
        tracesDataset: null,
        tracesToken: null,
      },
    });
  });

  it("uses a self-hosted relay token only in a build without Clerk", () => {
    const relay = { url: "https://relay.example.test", selfHostedToken: " secret " };
    expect(selfHostedRelayToken(resolveCloudPublicConfig({ relay }))).toBe("secret");
    expect(
      selfHostedRelayToken(
        resolveCloudPublicConfig({ relay, clerk: { publishableKey: "pk_test_example" } }),
      ),
    ).toBeNull();
    expect(
      selfHostedRelayToken(
        resolveCloudPublicConfig({
          relay: { url: "http://relay.example.test", selfHostedToken: "x" },
        }),
      ),
    ).toBeNull();
  });
});
