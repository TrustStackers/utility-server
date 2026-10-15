/**
 * Layer 5 — Trust Applications: POST /vtas
 *
 * VTA creation is an EDGE responsibility (per docs/one-scid-many-apps-architecture.md
 * Section 8.2). The utility server does NOT create VTAs — that is done locally
 * by the agent-app via ScidVhAgent.create().
 *
 * This route now returns 410 Gone with a message directing users to the agent-app.
 * The utility server still stores VTAs pushed by agents via POST /identities/remote
 * (for recovery/backup purposes), and lists them via GET /identities.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

export function registerVtaRoutes(app: FastifyInstance, _db: DataSource): void {
  app.post('/vtas', async (_req: FastifyRequest, reply: FastifyReply) => {
    return reply.code(410).send({
      error: {
        message:
          'VTA creation has moved to the agent-app. Use ScidVhAgent.create() locally on your device. ' +
          'The utility server stores VTAs pushed by agents via POST /identities/remote for recovery/backup.',
      },
    });
  });
}