// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Layer 2 — Trust Spanning route registration.
 *
 * Wires up the real /relationships and /messages routes (relationships.ts,
 * messages.ts), driven by the live libp2p node passed in from index.ts.
 */

import type { FastifyInstance } from 'fastify';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { Libp2p } from 'libp2p';

import { registerRelationshipRoutes } from './relationships.js';
import { registerMessageRoutes } from './messages.js';

export function registerLayer2Routes(
  app: FastifyInstance,
  db: DataSource,
  node: Libp2p,
  keyStorePath: string,
): void {
  registerRelationshipRoutes(app, db, node, keyStorePath);
  registerMessageRoutes(app, db, node);
}


