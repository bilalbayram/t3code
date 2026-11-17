import type { EnvironmentId } from "@t3tools/contracts";

import type { ReportedEndpoint } from "./routes.ts";

// LAN addresses a relay names for its environments, such as `http://bm1.local:3773/`. A server
// reports its LAN IPs, which change with DHCP; a relay that knows the machine's name replaces them.
const lanHttpBaseUrls = new Map<EnvironmentId, string>();

/** Records the LAN address the relay lists for an environment, or forgets it. */
export function setRelayLanHttpBaseUrl(
  environmentId: EnvironmentId,
  url: string | undefined,
): void {
  if (url === undefined) {
    lanHttpBaseUrls.delete(environmentId);
  } else {
    lanHttpBaseUrls.set(environmentId, url);
  }
}

/** The server's reported endpoints with its LAN IPs swapped for the relay's LAN address, if any. */
export function withRelayLanHost(
  environmentId: EnvironmentId,
  reported: ReadonlyArray<ReportedEndpoint>,
): ReadonlyArray<ReportedEndpoint> {
  const lan = lanHttpBaseUrls.get(environmentId);
  if (lan === undefined) return reported;
  return [
    ...reported.filter((endpoint) => endpoint.kind !== "lan"),
    { kind: "lan", httpBaseUrl: lan },
  ];
}
