/**
 * Layer 5 — Trust Applications: VTN affiliation, hierarchy, and
 * effective-policy routes (Scenario 9 — "VTNs & Nested Communities",
 * see mockup/vtn-network.html and
 * docs/cross-layer-integration-plan.md Decision 2.8).
 *
 * - PATCH /vtcs/:id/affiliate      — affiliate a VTC (:id) with a parent VTN
 * - POST  /vtcs/:id/unaffiliate    — clear a VTC's parent VTN affiliation
 * - GET   /vtns/:id/hierarchy      — VTN + child VTCs + direct/unaligned members
 * - GET   /identities/:id/effective-policy — merged VTN-floor/VTC policy for an identity
 *
 * See ../../services/vtc.ts for the actual composition logic.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import {
  affiliateVtc,
  unaffiliateVtc,
  getVtnHierarchy,
  resolveEffectivePolicy,
  CreateVtcValidationError,
  CreateVtcNotFoundError,
  AffiliateCycleError,
} from '../../services/vtc.js';
import { randomUUID } from 'node:crypto';
import { validateSession } from '../../session.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import * as governanceRepo from '@p2p-trust-stack/core/db/repositories/governance-repo.js';
import { resolveCommunityClaimTypes } from '@p2p-trust-stack/core/services/policy-bindings.js';
import { GovernanceChangeStore } from '@p2p-trust-stack/core/tx/governance-change-store.js';
import { GovernanceChangeParticipant } from '../../tx/governance-change-participant.js';
import type { ApprovalScope, GovernanceChange } from '@p2p-trust-stack/core/services/governance-change.js';

interface AffiliateBody {
  parentCommunityUuid: string;
}

/**
 * Require the caller to be an admin/founding_admin of the VTN. Returns the caller's
 * identity uuid, or sends 401/403 and returns null.
 *
 * The utility server NEVER signs on the caller's behalf — it only gates access. A
 * governance change is PROPOSED here; the required admins co-sign from their AGENT
 * apps (the server holds no member keys), driven by the durable governance-proposal
 * fan-out.
 */
async function requireVtnAdmin(
  app: FastifyInstance,
  db: DataSource,
  req: FastifyRequest,
  reply: FastifyReply,
  vtnUuid: string,
): Promise<string | null> {
  const hmacSecret = (app as unknown as { hmacSecret?: Buffer }).hmacSecret;
  if (!hmacSecret) {
    reply.code(503).send({ error: { message: 'Auth is not configured on this node.' } });
    return null;
  }
  const session = validateSession(req.headers.cookie, hmacSecret);
  if (!session) {
    reply.code(401).send({ error: { message: 'Sign in to the utility server first.' } });
    return null;
  }
  const membership = await membershipsRepo.findByPair(db, session.identityUuid, vtnUuid);
  if (!membership || (membership.role !== 'admin' && membership.role !== 'founding_admin')) {
    reply.code(403).send({ error: { message: 'Only VTN admins or founding admins may manage network rules.' } });
    return null;
  }
  return session.identityUuid;
}

export function registerVtnRoutes(app: FastifyInstance, db: DataSource): void {
  app.patch(
    '/vtcs/:uuid/affiliate',
    async (req: FastifyRequest<{ Params: { uuid: string }; Body: AffiliateBody }>, reply: FastifyReply) => {
      const childVtcUuid = req.params.uuid;
      const body = req.body ?? ({} as AffiliateBody);
      if (!childVtcUuid) {
        return reply.code(400).send({ error: { message: 'uuid (param) is required' } });
      }
      if (!body.parentCommunityUuid) {
        return reply.code(400).send({ error: { message: 'parentCommunityUuid (body) is required' } });
      }

      try {
        // `await` is load-bearing: without it the handler returns before the
        // affiliation is written (a follow-up request can race it — "not
        // currently affiliated" on the very next call), and every rejection
        // below escapes the catch as an unhandledRejection instead of mapping
        // to 404/400/409. Pinned by test/routes/vtn-affiliate.test.ts.
        const result = await affiliateVtc(db, childVtcUuid, body.parentCommunityUuid);
        return reply.code(200).send(result);
      } catch (err) {
        if (err instanceof AffiliateCycleError) {
          return reply.code(409).send({ error: { message: err.message } });
        }
        if (err instanceof CreateVtcValidationError) {
          return reply.code(400).send({ error: { message: err.message } });
        }
        if (err instanceof CreateVtcNotFoundError) {
          return reply.code(404).send({ error: { message: err.message } });
        }
        throw err;
      }
    },
  );

  app.post(
    '/vtcs/:uuid/unaffiliate',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const childVtcUuid = req.params.uuid;
      if (!childVtcUuid) {
        return reply.code(400).send({ error: { message: 'uuid is required' } });
      }

      try {
        // `await` is load-bearing — see the affiliate route above.
        const result = await unaffiliateVtc(db, childVtcUuid);
        return reply.code(200).send(result);
      } catch (err) {
        if (err instanceof CreateVtcValidationError) {
          return reply.code(400).send({ error: { message: err.message } });
        }
        if (err instanceof CreateVtcNotFoundError) {
          return reply.code(404).send({ error: { message: err.message } });
        }
        throw err;
      }
    },
  );

  app.get(
    '/vtns/:uuid/hierarchy',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const vtnUuid = req.params.uuid;
      if (!vtnUuid) {
        return reply.code(400).send({ error: { message: 'uuid is required' } });
      }

      try {
        const result = getVtnHierarchy(db, vtnUuid);
        return reply.code(200).send(result);
      } catch (err) {
        if (err instanceof CreateVtcValidationError) {
          return reply.code(400).send({ error: { message: err.message } });
        }
        if (err instanceof CreateVtcNotFoundError) {
          return reply.code(404).send({ error: { message: err.message } });
        }
        throw err;
      }
    },
  );

  app.get(
    '/identities/:uuid/effective-policy',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const identityUuid = req.params.uuid;
      if (!identityUuid) {
        return reply.code(400).send({ error: { message: 'uuid is required' } });
      }

      try {
        const result = resolveEffectivePolicy(db, identityUuid);
        return reply.code(200).send(result);
      } catch (err) {
        if (err instanceof CreateVtcNotFoundError) {
          return reply.code(404).send({ error: { message: err.message } });
        }
        throw err;
      }
    },
  );

  // ── VTN governance rules (Phase B follow-up) ────────────────────────────────
  // A VTN's rules change through the SAME consent machinery as a VTC's. An admin
  // PROPOSES here (server-side begin — no signature); the required admins co-sign
  // from their AGENT apps (the utility server holds no member keys). The durable
  // `governance-proposal` fan-out delivers the proposal to each admin's agent.

  app.get(
    '/vtns/:uuid/governance',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const vtnUuid = req.params.uuid;
      const caller = await requireVtnAdmin(app, db, req, reply, vtnUuid);
      if (!caller) return;

      const vtn = await identitiesRepo.findByUuid(db, vtnUuid);
      if (!vtn) return reply.code(404).send({ error: { message: 'VTN not found' } });

      const gov = await governanceRepo.findForCommunity(db, vtnUuid);
      const allowedClaimTypes = await resolveCommunityClaimTypes(db, vtnUuid);

      const txDb = (app as unknown as { txDb?: DataSource }).txDb;
      const pending: Array<Record<string, unknown>> = [];
      if (txDb) {
        const store = new GovernanceChangeStore(txDb);
        for (const p of await store.listPendingForCommunity(vtnUuid)) {
          const approvals = await store.getApprovals(p.proposalId);
          pending.push({
            proposalId: p.proposalId,
            scope: p.scope,
            requiredApproverCount: p.requiredApproverCount,
            change: p.change,
            expiresAt: p.expiresAt,
            approvedBy: approvals.map((a) => a.approverUuid),
          });
        }
      }

      return reply.code(200).send({
        uuid: vtnUuid,
        did: vtn.did,
        name: vtn.name,
        role: vtn.role,
        governance: {
          adminThresholdM: gov?.adminThresholdM ?? null,
          adminThresholdN: gov?.adminThresholdN ?? null,
          allowedClaimTypes,
        },
        pending,
      });
    },
  );

  app.post(
    '/vtns/:uuid/governance/propose',
    async (
      req: FastifyRequest<{
        Params: { uuid: string };
        Body: { change?: GovernanceChange; scope?: ApprovalScope; minApprovals?: number };
      }>,
      reply: FastifyReply,
    ) => {
      const vtnUuid = req.params.uuid;
      const caller = await requireVtnAdmin(app, db, req, reply, vtnUuid);
      if (!caller) return;

      const txDb = (app as unknown as { txDb?: DataSource }).txDb;
      if (!txDb) {
        return reply.code(501).send({ error: { message: 'Governance changes are unavailable (no tx store wired).' } });
      }
      const body = req.body ?? {};
      if (!body.change || typeof body.change !== 'object') {
        return reply.code(400).send({ error: { message: 'change is required' } });
      }

      const proposalId = randomUUID();
      try {
        await new GovernanceChangeParticipant('server:us-1', db, txDb).beginChange({
          proposalId,
          communityUuid: vtnUuid,
          proposerUuid: caller,
          change: body.change,
          scope: body.scope,
          minApprovals: body.minApprovals,
        });
      } catch (err) {
        return reply.code(400).send({ error: { message: (err as Error)?.message ?? 'proposal failed' } });
      }
      return reply.code(200).send({
        ok: true,
        proposalId,
        note: 'Proposed. The required admins co-sign from their agent apps; the change applies on quorum.',
      });
    },
  );
}
