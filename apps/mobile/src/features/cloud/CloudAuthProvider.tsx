import { ClerkProvider, getClerkInstance } from "@clerk/expo";
import { tokenCache } from "@clerk/expo/token-cache";
import type { ReactNode } from "react";

import {
  activateCloudRelayAccount,
  cloudAccountService,
  deactivateCloudRelayAccount,
} from "./cloudAccountService";
import { resolveCloudPublicConfig, selfHostedRelayToken } from "./publicConfig";

const cloudConfig = resolveCloudPublicConfig();
// Build-time constant: null when this build has no cloud config.
const publishableKey = cloudConfig.relay.url ? cloudConfig.clerk.publishableKey : null;
const selfHostedToken = selfHostedRelayToken(cloudConfig);

if (publishableKey) {
  // The same native singleton ClerkProvider renders with, so the service
  // observes it for the app's lifetime without a React subscription.
  cloudAccountService.attach(getClerkInstance({ publishableKey }));
} else if (selfHostedToken) {
  // A relay you run yourself takes its token in place of a sign-in, for everything T3 Connect
  // does: your environments, connecting to them, notifications and Live Activities.
  activateCloudRelayAccount("self-hosted", async () => selfHostedToken);
} else {
  // Without cloud config no account can ever activate, so drop anything a
  // previous build with cloud enabled left registered.
  deactivateCloudRelayAccount();
}

export function CloudAuthProvider(props: { readonly children: ReactNode }) {
  if (!publishableKey) {
    return props.children;
  }

  return (
    <ClerkProvider publishableKey={publishableKey} tokenCache={tokenCache}>
      {props.children}
    </ClerkProvider>
  );
}
