// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Bootstrap client holder — exposes the running bootstrap client + libp2p node
 * to the setup wizard so it can discover/locate an agent VTA by DID during the
 * founder-VTA step (without re-instantiating the client).
 *
 * Set once at startup in index.ts (where the node + client are available); read
 * by the `/setup/discover` route.
 */

import type { Libp2p } from 'libp2p';
import type { BootstrapClient } from '@p2p-trust-stack/core/transport/bootstrap-client.js';

let client: BootstrapClient | null = null;
let node: Libp2p | null = null;

export function setBootstrapClient(c: BootstrapClient, n: Libp2p): void {
  client = c;
  node = n;
}

export function getBootstrapQuery(): { client: BootstrapClient; node: Libp2p } | null {
  return client && node ? { client, node } : null;
}
