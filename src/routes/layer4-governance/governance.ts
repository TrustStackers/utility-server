/**
 * Layer 4 — Governance: /communities/:id/governance routes.
 *
 * - GET   /communities/:id/governance — fetch a community's governance parameters
 * - PATCH /communities/:id/governance — update a community's governance parameters
 *   (M-of-N admin approval is deferred — auth is out of scope for this pass,
 *   per the plan's "Auth" foundational decision; every route is open today.)
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import * as governanceRepo from '@p2p-trust-stack/core/db/repositories/governance-repo.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import { tryEnqueueFanout } from '../../services/exchange-runtime.js';

interface UpdateGovernanceBody {
  adminThresholdM?: number;
  adminThresholdN?: number;
  parentCommunityUuid?: string;
  adminDidDocumentUuids?: string[];
}

export function registerGovernanceRoutes(app: FastifyInstance, db: DataSource): void {
  app.get(
    '/governance/:uuid',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const uuid = req.params.uuid;
      const governance = governanceRepo.findByUuid(db, uuid);
      if (!governance) {
        return reply.code(404).send({ error: { message: `governance ${uuid} not found` } });
      }
      return governance;
    },
  );

  app.get(
    '/communities/:uuid/governance',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const communityUuid = req.params.uuid;
      if (!identitiesRepo.findByUuid(db, communityUuid)) {
        return reply.code(404).send({ error: { message: `community identity ${communityUuid} not found` } });
      }

      const governance = governanceRepo.findForCommunity(db, communityUuid);
      if (!governance) {
        return reply
          .code(404)
          .send({ error: { message: `no governance record exists yet for community ${communityUuid}` } });
      }
      return governance;
    },
  );

  app.patch(
    '/communities/:uuid/governance',
    async (
      req: FastifyRequest<{ Params: { uuid: string }; Body: UpdateGovernanceBody }>,
      reply: FastifyReply,
    ) => {
      const communityUuid = req.params.uuid;
      if (!identitiesRepo.findByUuid(db, communityUuid)) {
        return reply.code(404).send({ error: { message: `community identity ${communityUuid} not found` } });
      }

      const body = req.body ?? ({} as UpdateGovernanceBody);

      if (body.parentCommunityUuid !== undefined && !identitiesRepo.findByUuid(db, body.parentCommunityUuid)) {
        return reply
          .code(404)
          .send({ error: { message: `parent community identity ${body.parentCommunityUuid} not found` } });
      }

      // Ensure a governance row exists (first PATCH acts as an upsert), then apply the update.
      governanceRepo.findOrCreateForCommunity(db, communityUuid);

      const updated = await governanceRepo.update(db, communityUuid, {
        adminThresholdM: body.adminThresholdM,
        adminThresholdN: body.adminThresholdN,
        parentCommunityUuid: body.parentCommunityUuid,
        adminDidDocumentUuids:
          body.adminDidDocumentUuids !== undefined ? JSON.stringify(body.adminDidDocumentUuids) : undefined,
      });

      // Governance recordset on-write fan-out: enqueue a queue-row per active
      // member via the CRE engine so the updated thresholds + claim types reach
      // all agents (op exchange:governance). Idempotent per member
      // (gov_<community>_<member>_<updatedAt> key).
      if (updated) {
        try {
          await tryEnqueueFanout('governance', { communityUuid });
        } catch (err) {
          console.warn(
            `[governance] %s`,
            `failed to enqueue governance fanout for ${communityUuid}: ${(err as Error)?.message ?? err}`,
          );
        }
      }

      return updated;
    },
  );
}
