/**
 * GET /recovery/:identityUuid
 *
 * Returns the full public state for a given identity UUID — everything needed
 * to restore a VTA on a new device after loss. No authentication is required
 * (public data only — encrypted secret keys, passphrases, and messages are
 * NEVER included).
 *
 * See ../services/recovery.ts for the RecoveryState shape.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { assembleRecoveryState } from '../../services/recovery.js';

export function registerRecoveryRoute(app: FastifyInstance, db: DataSource): void {
  app.get('/recovery/:identityUuid', async (
    req: FastifyRequest<{ Params: { identityUuid: string } }>,
    reply: FastifyReply,
  ) => {
    const state = await assembleRecoveryState(db, req.params.identityUuid);
    if (!state) {
      return reply.code(404).send({ error: { message: 'identity not found' } });
    }
    return state;
  });
}