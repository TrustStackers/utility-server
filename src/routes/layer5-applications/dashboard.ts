// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Layer 5 — Trust Applications: GET /communities/:id/dashboard
 *
 * Assembled, cross-cutting view of a community (VTC/VTN): its governance
 * parameters, its full membership roster (grouped by status), and the
 * count of memberships awaiting approval — a read-only composition over
 * Layer 1-4 tables, per
 * ../../../../docs/utility-server-api-plan.md section 4 "Layer 5".
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as governanceRepo from '@p2p-trust-stack/core/db/repositories/governance-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import type { MembershipRow } from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';

export function registerDashboardRoute(app: FastifyInstance, db: DataSource): void {
  app.get(
    '/communities/:uuid/dashboard',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const communityUuid = req.params.uuid;
      const community = await identitiesRepo.findByUuid(db, communityUuid);
      if (!community) {
        return reply.code(404).send({ error: { message: `community identity ${communityUuid} not found` } });
      }
      if (community.role !== 'vtc' && community.role !== 'vtn') {
        return reply
          .code(409)
          .send({ error: { message: `identity ${communityUuid} is not a community (role=${community.role})` } });
      }

      const governance = await governanceRepo.findForCommunity(db, communityUuid);
      const roster = await membershipsRepo.findForCommunity(db, community.uuid);

      // Resolve member names via UUID lookup — the canonical distributed key.
      const memberNames = new Map<string, string | null>();
      for (const m of roster) {
        if (!memberNames.has(m.memberIdentityUuid)) {
          const identity = await identitiesRepo.findByUuid(db, m.memberIdentityUuid);
          memberNames.set(m.memberIdentityUuid, identity?.name ?? null);
        }
      }

      const byStatus: Record<'pending' | 'active' | 'revoked', (MembershipRow & { memberName: string | null })[]> = {
        pending: [],
        active: [],
        revoked: [],
      };
      for (const membership of roster) {
        const memberName = memberNames.get(membership.memberIdentityUuid) ?? null;
        byStatus[membership.status].push({ ...membership, memberName });
      }

      return reply.code(200).send({
        community,
        governance,
        roster: {
          total: roster.length,
          pending: byStatus.pending,
          active: byStatus.active,
          revoked: byStatus.revoked,
        },
        pendingApprovalCount: byStatus.pending.length,
      });
    },
  );
}
