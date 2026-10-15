/**
 * Layer 3 — Trust Tasks: /status-lists routes.
 *
 * - POST /status-lists       — provision a status list ahead of time for a community
 * - GET  /status-lists/:id   — public bitstring (for external verifier compatibility)
 * - GET  /status-lists/:id/flips — raw flip history/audit log
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import * as statusListsRepo from '@p2p-trust-stack/core/db/repositories/status-lists-repo.js';
import type { StatusListPurpose } from '@p2p-trust-stack/core/db/repositories/status-lists-repo.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';

/** Reserved decoy indices 0-3, pre-flipped at mint per the schema notes. */
const RESERVED_DECOY_INDICES = [0, 1, 2, 3];

interface CreateStatusListBody {
  communityIdentityUuid: string;
  purpose: StatusListPurpose;
  publicUrl?: string;
}

const VALID_PURPOSES: StatusListPurpose[] = ['revocation', 'suspension'];

export function registerStatusListRoutes(app: FastifyInstance, db: DataSource): void {
  app.post(
    '/status-lists',
    async (req: FastifyRequest<{ Body: CreateStatusListBody }>, reply: FastifyReply) => {
      const body = req.body;
      if (!body?.communityIdentityUuid || !body?.purpose) {
        return reply.code(400).send({ error: { message: 'communityIdentityUuid and purpose are required' } });
      }
      if (!VALID_PURPOSES.includes(body.purpose)) {
        return reply.code(400).send({ error: { message: `purpose must be one of: ${VALID_PURPOSES.join(', ')}` } });
      }
      if (!await identitiesRepo.findByUuid(db, body.communityIdentityUuid)) {
        return reply
          .code(404)
          .send({ error: { message: `community identity ${body.communityIdentityUuid} not found` } });
      }
      const existing = await statusListsRepo.findForCommunity(db, body.communityIdentityUuid, body.purpose);
      if (existing) {
        return reply.code(409).send({
          error: {
            message: `a ${body.purpose} status_list already exists for community ${body.communityIdentityUuid} (uuid=${existing.uuid})`,
          },
        });
      }

      const community = await identitiesRepo.findByUuid(db, body.communityIdentityUuid);
      if (!community) {
        return reply.code(404).send({ error: { message: `community identity ${body.communityIdentityUuid} not found` } });
      }
      const uuid = await statusListsRepo.create(db, {
        communityIdentityUuid: body.communityIdentityUuid,
        purpose: body.purpose,
        publicUrl: body.publicUrl,
      });

      return reply.code(201).send(await statusListsRepo.findByUuid(db, uuid));
    },
  );

  app.get(
    '/status-lists/:uuid/flips',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const uuid = req.params.uuid;
      if (!await statusListsRepo.findByUuid(db, uuid)) {
        return reply.code(404).send({ error: { message: `status_list ${uuid} not found` } });
      }
      const statusListRow = await statusListsRepo.findByUuid(db, uuid);
      return statusListsRepo.findFlipsForList(db, statusListRow!.uuid);
    },
  );

  app.get(
    '/status-lists/:uuid',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const statusList = await statusListsRepo.findByUuid(db, req.params.uuid);
      if (!statusList) {
        return reply.code(404).send({ error: { message: `status_list ${req.params.uuid} not found` } });
      }

      const flips = await statusListsRepo.getBitstring(db, statusList.uuid);

      // Build a dense bitstring from index 0 to nextFreeIndex-1: reserved
      // decoy slots (0-3) default to 1 (pre-flipped at mint); all other
      // slots default to 0 unless a flip overrides them.
      const length = Math.max(statusList.nextFreeIndex, RESERVED_DECOY_INDICES.length);
      const bits: number[] = [];
      for (let i = 0; i < length; i++) {
        if (flips[i] !== undefined) {
          bits.push(flips[i]);
        } else {
          bits.push(RESERVED_DECOY_INDICES.includes(i) ? 1 : 0);
        }
      }

      return {
        uuid: statusList.uuid,
        communityIdentityUuid: statusList.communityIdentityUuid,
        purpose: statusList.purpose,
        publicUrl: statusList.publicUrl,
        nextFreeIndex: statusList.nextFreeIndex,
        bitstring: bits.join(''),
      };
    },
  );
}
