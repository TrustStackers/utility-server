/**
 * Layer 4 — Governance route registration.
 *
 * Wires up /communities/:id/memberships, /memberships/:id/*,
 * /communities/:id/governance, /delegations, and /grants — see
 * ../../../../docs/utility-server-api-plan.md section 4 "Layer 4".
 */

import type { FastifyInstance } from 'fastify';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';

import { registerMembershipRoutes } from './memberships.js';
import { registerGovernanceRoutes } from './governance.js';
import { registerDelegationRoutes } from './delegations.js';
import { registerGrantRoutes } from './grants.js';
import { registerMemberSyncRoute } from './member-sync.js';

export function registerLayer4Routes(app: FastifyInstance, db: DataSource): void {
  registerMembershipRoutes(app, db);
  registerGovernanceRoutes(app, db);
  registerDelegationRoutes(app, db);
  registerGrantRoutes(app, db);
  registerMemberSyncRoute(app, db);
}
