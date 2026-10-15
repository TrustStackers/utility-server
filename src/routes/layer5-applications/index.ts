/**
 * Layer 5 — Trust Applications route registration.
 *
 * Wires up the real /identities/:id/profile, /communities/:id/dashboard,
 * and /graph/edges routes — each a read-only, cross-cutting composition
 * over the Layer 1-4 tables. See
 * ../../../../docs/utility-server-api-plan.md section 4 "Layer 5".
 *
 * The webhook/event-subscription surface mentioned in the plan ("Later:
 * webhook/event subscription endpoints for external Layer 4 apps") remains
 * a placeholder stub — real-time subscriptions are follow-up work beyond
 * this pass.
 */

import type { FastifyInstance } from 'fastify';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { Libp2p } from 'libp2p';
import type { TransactionManager } from '@p2p-trust-stack/core/tx/manager.js';
import type { ServerTspRequestAdapter } from '../../tx/tsp-request.js';

import type { CeremonyCoordinator } from '@p2p-trust-stack/core/tx/index.js';

import { registerProfileRoute } from './profile.js';
import { registerDashboardRoute } from './dashboard.js';
import { registerGraphEdgesRoute } from './graph-edges.js';
import { registerVtaRoutes } from './vtas.js';
import { registerVtcRoutes } from './vtcs.js';
import { registerSummaryRoute } from './summary.js';
import { registerProfileRoutes } from './profiles.js';
import { registerVtcInviteRoutes } from './vtc-invite.js';
import { registerVtnRoutes } from './vtns.js';
import { registerNameRoutes } from './names.js';

const notImplemented = async (_req: unknown, reply: { code: (n: number) => any }) => {
  return reply.code(501).send({
    error: {
      message:
        'Not Implemented — webhook/event subscription endpoints are a placeholder for future Layer 5 work.',
    },
  });
};

export function registerLayer5Routes(
  app: FastifyInstance,
  db: DataSource,
  node: Libp2p,
): void {
  const txManager = (app as any).txManager as TransactionManager | undefined;
  const tspAdapter = (app as any).tspAdapter as ServerTspRequestAdapter | undefined;
  const ceremonyCoordinator = (app as any).ceremonyCoordinator as CeremonyCoordinator | undefined;

  registerProfileRoute(app, db);
  registerDashboardRoute(app, db);
  registerGraphEdgesRoute(app, db);
  registerVtaRoutes(app, db);
  registerVtcRoutes(app, db, txManager, tspAdapter, ceremonyCoordinator);
  registerSummaryRoute(app, db);
  registerProfileRoutes(app, db);
  registerVtcInviteRoutes(app, db, node);
  registerVtnRoutes(app, db);
  registerNameRoutes(app, db);

  // Placeholder — webhook/event subscriptions, not yet built.
  app.post('/webhooks/subscriptions', notImplemented);
}
