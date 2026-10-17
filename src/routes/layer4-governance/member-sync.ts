// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import * as governanceRepo from '@p2p-trust-stack/core/db/repositories/governance-repo.js';

export function registerMemberSyncRoute(app: FastifyInstance, db: DataSource): void {
  // GET /memberships/for/:uuid — returns membership rows + community identity
  // + governance data for a given member UUID. Used by agent apps on login.
  app.get('/memberships/for/:uuid', async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
    const memberUuid = req.params.uuid;
    if (!memberUuid) return reply.code(400).send({ error: { message: 'uuid required' } });

    const memberships = await membershipsRepo.findForMemberByUuid(db, memberUuid);
    const result = [];
    for (const m of memberships) {
      const community = await identitiesRepo.findByUuid(db, m.communityIdentityUuid);
      if (!community) continue;
      const governance = await governanceRepo.findForCommunity(db, community.uuid);
      result.push({
        membership: {
          role: m.role,
          status: m.status,
          personhoodAsserted: m.personhoodAsserted,
          uuid: m.uuid,
        },
        community: {
          uuid: community.uuid,
          did: community.did,
          name: community.name,
          role: community.role,
        },
        governance: governance ? {
          adminThresholdM: governance.adminThresholdM,
          adminThresholdN: governance.adminThresholdN,
          parentCommunityUuid: governance.parentCommunityUuid,
        } : null,
      });
    }
    return reply.code(200).send(result);
  });
}