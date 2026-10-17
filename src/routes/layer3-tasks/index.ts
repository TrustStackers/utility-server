// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Layer 3 — Trust Tasks (credentials/VCs) route registration.
 *
 * Wires up /credentials, /status-lists, and /nonces — see
 * ../../../../docs/utility-server-api-plan.md section 4 "Layer 3".
 */

import type { FastifyInstance } from 'fastify';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';

import { registerCredentialRoutes } from './credentials.js';
import { registerStatusListRoutes } from './status-lists.js';
import { registerNonceRoutes } from './nonces.js';
import { registerAuthRoutes } from './auth.js';
import { registerTrustTaskRoutes } from './trust-tasks.js';

export function registerLayer3Routes(app: FastifyInstance, db: DataSource): void {
  registerCredentialRoutes(app, db);
  registerStatusListRoutes(app, db);
  registerNonceRoutes(app, db);
  registerAuthRoutes(app, db);
  registerTrustTaskRoutes(app, db);
}

