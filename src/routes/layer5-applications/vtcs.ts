/**
 * Layer 5 — Trust Applications: POST /vtcs, GET /vtcs
 *
 * Composed VTC/VTN creation action (Scenario 4 — "Create a Verified
 * Trust Community"): creates the `identities` row, `governance` row,
 * `founding_admin` `memberships` rows, and a pre-seeded revocation
 * `status_lists` row in one call. See ../../services/vtc.ts for the
 * actual composition logic, and mockup/vtc-create.html for the scenario.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import type { TransactionManager } from '@p2p-trust-stack/core/tx/manager.js';
import type { CeremonyCoordinator } from '@p2p-trust-stack/core/tx/index.js';
import type { ServerTspRequestAdapter } from '../../tx/tsp-request.js';
import { tryEnqueueFanout } from '../../services/exchange-runtime.js';
import { enqueueFoundingAdminVmcFanout } from '../../services/vtc-push-data.js';

import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import type { Identity } from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import type { MembershipRole } from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import * as governanceRepo from '@p2p-trust-stack/core/db/repositories/governance-repo.js';
import * as credentialsRepo from '@p2p-trust-stack/core/db/repositories/credentials-repo.js';
import * as relationshipsRepo from '@p2p-trust-stack/core/db/repositories/relationships-repo.js';
import {
  createVtc,
  listVtcs,
  checkCommunityNameAvailable,
  CREDENTIAL_TYPES,
  CreateVtcValidationError,
  CreateVtcNotFoundError,
  CreateVtcConflictError,
} from '../../services/vtc.js';
import type { VtcKind } from '../../services/vtc.js';

interface CreateVtcBody {
  name: string;
  kind?: VtcKind;
  adminUuids?: string[];           // NEW: agent-friendly, alternative to adminIdentityIds
  threshold?: number;
  parentCommunityUuid?: string;
  creatorUuid?: string;            // NEW: identifies the originating agent
}

interface ProposeBody {
  name: string;
  kind?: 'vtc' | 'vtn';
  adminDids: string[];
  threshold: number;
  proposerDid: string;
  parentCommunityDid?: string;
}

interface ApproveBody {
  approverDid: string;
  signature: string;
}

interface AddAdminBody {
  adminIdentityUuid: string;
}

export function registerVtcRoutes(
  app: FastifyInstance,
  db: DataSource,
  _txManager?: TransactionManager,
  _tspAdapter?: ServerTspRequestAdapter,
  ceremonyCoordinator?: CeremonyCoordinator,
): void {
  // GET /vtcs/admin-candidates?creatorUuid=<uuid> or ?creatorDid=<did>
  // Returns the creator (always first) plus VRC-connected co-admin candidates.
  // creatorUuid or creatorDid is required — no unfiltered fallback.
  app.get('/vtcs/admin-candidates', async (req, reply) => {
    const { creatorDid, creatorUuid } = (req.query ?? {}) as { creatorDid?: string; creatorUuid?: string };

    if (!creatorDid && !creatorUuid) {
      return reply.code(400).send({ error: { message: 'creatorUuid or creatorDid query parameter is required' } });
    }

    // Resolve creator by UUID (preferred) or by real DID
    let creator: Identity | null;
    if (creatorUuid) {
      creator = await identitiesRepo.findByUuid(db, creatorUuid);
    } else {
      creator = await identitiesRepo.findByRealDid(db, creatorDid!);
    }

    if (!creator) {
      return reply.code(404).send({ error: { message: `creator identity not found` } });
    }

    const allVtas = await identitiesRepo.findByRoleAndSubjectKind(db, 'vta', 'human');

    // Get VRC peer UUIDs and resolve ephemeral ones to canonical VTA UUIDs
    // via the keys table (both share the same Ed25519 public key).
    const vrcUuids = await relationshipsRepo.findEstablishedVrcIdentityUuids(db, creator.uuid);
    const vtaByUuid = new Map(allVtas.map(v => [v.uuid, v]));
    const resolvedUuids = new Set<string>();

    for (const vrcUuid of vrcUuids) {
      if (vtaByUuid.has(vrcUuid)) {
        resolvedUuids.add(vrcUuid);
        continue;
      }
      const real = await db.get<{ uuid: string }>(
        `SELECT i.uuid FROM identities i
         JOIN keys k ON k.identity_uuid = i.uuid
         JOIN keys k2 ON k2.public_key = k.public_key AND k2.key_type = 'ed25519'
         JOIN identities i2 ON i2.uuid = k2.identity_uuid
         JOIN peer_endpoints pe ON pe.identity_uuid = i.uuid
         WHERE i2.uuid = $1 AND i.role = 'vta'
         ORDER BY i.created_at, i.uuid`,
        vrcUuid,
      );
      if (real && vtaByUuid.has(real.uuid)) {
        resolvedUuids.add(real.uuid);
      }
    }
    const filtered = allVtas.filter((c) => resolvedUuids.has(c.uuid));

    // Always list the creator first so they can bootstrap a community solo
    const creatorEntry = {
      uuid: creator.uuid,
      name: creator.name || '(you)',
      did: creator.did,
      isCreator: true,
    };

    const coAdminEntries = await Promise.all(filtered.map(async (c) => {
      // Fetch VRC credentials between creator and this co-admin — both directions.
      // This allows the agent to sync credential data on every poll.
      const vrcCreds = await credentialsRepo.list(db, { vcType: 'vrc' });
      const relevantCreds = vrcCreds.filter(cred =>
        cred.status === 'issued' && cred.w3cVcJson !== null && (
          (cred.issuerIdentityUuid === creator.uuid && cred.subjectIdentityUuid === c.uuid) ||
          (cred.issuerIdentityUuid === c.uuid && cred.subjectIdentityUuid === creator.uuid)
        )
      );
      const vrcCredentials = relevantCreds.map(cred => ({
        issuerDid: '',  // resolved below
        subjectDid: '',
        w3cVcJson: cred.w3cVcJson!,
      }));
      // Resolve issuer/subject DIDs for each credential
      for (const vc of vrcCredentials) {
        const parsed = JSON.parse(vc.w3cVcJson);
        vc.issuerDid = parsed.issuer || '';
        vc.subjectDid = parsed.credentialSubject?.id || '';
      }
      return {
        uuid: c.uuid,
        name: c.name,
        did: c.did,
        isCreator: false,
        vrcCredentials,
      };
    }));

    return reply.code(200).send([creatorEntry, ...coAdminEntries]);
  });

  app.post('/vtcs', async (req: FastifyRequest<{ Body: CreateVtcBody }>, reply: FastifyReply) => {
    const body = req.body ?? ({} as CreateVtcBody);

    try {
      // ── Resolve admin UUIDs (agent-friendly path) ──────────────────────
      let identityUuids: string[];
      if (body.adminUuids && body.adminUuids.length > 0) {
        const resolved: string[] = [];
        for (const uuid of body.adminUuids) {
          const identity = await identitiesRepo.findByUuid(db, uuid);
          if (!identity) {
            return reply.code(404).send({ error: { message: `Identity ${uuid} not found` } });
          }
          resolved.push(identity.uuid);
        }
        identityUuids = resolved;

        // Verify creatorUuid is in the admin list
        if (body.creatorUuid && !body.adminUuids.includes(body.creatorUuid)) {
          return reply.code(400).send({ error: { message: 'creatorUuid must be in adminUuids' } });
        }
      } else {
        return reply.code(400).send({ error: { message: 'adminUuids is required' } });
      }

      // createVtc() requires ≥2 founding admins with mutual VRCs for VTCs.
      // VTN creation permits a single operator (separate genesis ceremony).
      const result = await createVtc(db, {
        name: body.name,
        kind: body.kind,
        adminIdentityUuids: identityUuids,
        threshold: body.threshold,
        parentCommunityUuid: body.parentCommunityUuid,
      });

      // ── Fan-out delivery to each founding admin via the CRE engine ────────
      // enqueueFanout materializes the vtc-membership recordset through the
      // catalog, resolves active members, and stores one durable REF row per
      // member (op exchange:vtc-membership). Payload is re-materialized at send
      // time (incl. reconnect flush), so offline agents receive fresh records on
      // return. pushVtcToFoundingAdmins (fire-and-forget, non-durable) is retired.
      await tryEnqueueFanout('vtc-membership', { communityUuid: result.identity.uuid });

      // …then deliver each founding admin's VMC (minted inside createVtc and
      // referenced by memberships.membership_credential_uuid) to its holder.
      // Queued AFTER the community package: the queue drains in created_at
      // order, so the membership link lands before the credential it references.
      await enqueueFoundingAdminVmcFanout(result.foundingAdmins);

      return reply.code(201).send(result);
    } catch (err) {
      if (err instanceof CreateVtcValidationError) {
        return reply.code(400).send({ error: { message: err.message } });
      }
      if (err instanceof CreateVtcNotFoundError) {
        return reply.code(404).send({ error: { message: err.message } });
      }
      if (err instanceof CreateVtcConflictError) {
        return reply.code(409).send({ error: { message: err.message } });
      }
      throw err;
    }
  });

  app.get('/vtcs', async (_req: FastifyRequest, _reply: FastifyReply) => {
    return listVtcs(db);
  });

  // GET /vtcs/for-member/:uuid — VTCs/VTNs where the given identity is a member.
  // Used by agent apps to sync only communities relevant to the logged-in VTA.
  app.get('/vtcs/for-member/:uuid', async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
    const memberUuid = req.params.uuid;
    if (!memberUuid) return reply.code(400).send({ error: { message: 'uuid required' } });

    const memberships = await membershipsRepo.findForMemberByUuid(db, memberUuid);
    const communityUuids = [...new Set(memberships.map((m) => m.communityIdentityUuid))];

    const allVtcs = await listVtcs(db);
    const mine = allVtcs.filter((v) => communityUuids.includes(v.identity.uuid));
    return reply.code(200).send(mine);
  });

  // GET /vtcs/credential-types — returns the known DTG credential type taxonomy.
  app.get('/vtcs/credential-types', async (_req, reply) => {
    return reply.code(200).send(CREDENTIAL_TYPES);
  });

  // GET /agent/pending/:memberUuid — generic pending delivery check.
  // Returns all pending_agent_deliveries for an agent, regardless of op_type.
  // Used by agents on login/startup to discover missed deliveries.
  app.get('/agent/pending/:memberUuid', async (req, reply) => {
    const { memberUuid } = req.params as { memberUuid: string };
    try {
      const pending = await db.all(
        `SELECT * FROM pending_agent_deliveries
         WHERE member_uuid = ? AND status IN ('pending','in_flight','failed')
         ORDER BY created_at ASC`, memberUuid,
      );
      return reply.code(200).send(pending);
    } catch (err) {
      console.error(`[agent/pending] error for ${memberUuid}:`, (err as Error)?.message ?? err);
      return reply.code(500).send({ error: { message: 'Failed to query pending deliveries' } });
    }
  });

  // ── Ceremony Protocol (Phase 3) ──────────────────────────────────────────

  // POST /vtcs/propose — create a VTC using DIDs instead of integer IDs.
  // Equivalent to POST /vtcs but accepts DIDs (agent-friendly).
  app.post('/vtcs/propose', async (req: FastifyRequest<{ Body: ProposeBody }>, reply: FastifyReply) => {
    const body = req.body ?? ({} as ProposeBody);
    try {
      if (!body.adminDids || body.adminDids.length === 0) {
        return reply.code(400).send({ error: { message: 'adminDids is required' } });
      }
      // Resolve DIDs to identity UUIDs
      const adminIdentityUuids: string[] = [];
      for (const did of body.adminDids) {
        const identity = await identitiesRepo.findByRealDid(db, did);
        if (!identity) {
          return reply.code(404).send({ error: { message: `identity not found for DID: ${did}` } });
        }
        adminIdentityUuids.push(identity.uuid);
      }

      let parentCommunityUuid: string | undefined;
      if (body.parentCommunityDid) {
        const parent = await identitiesRepo.findByRealDid(db, body.parentCommunityDid);
        if (parent) parentCommunityUuid = parent.uuid;
      }

      const result = await createVtc(db, {
        name: body.name,
        kind: body.kind ?? 'vtc',
        adminIdentityUuids,
        threshold: body.threshold,
        parentCommunityUuid,
      });

      // ── Fan-out delivery to founding admins via the CRE engine ────────────
      await tryEnqueueFanout('vtc-membership', { communityUuid: result.identity.uuid });

      // …then deliver each founding admin's VMC (minted inside createVtc) to its
      // holder, after the community package that carries the membership link.
      await enqueueFoundingAdminVmcFanout(result.foundingAdmins);

      return reply.code(201).send(result);
    } catch (err) {
      if (err instanceof CreateVtcValidationError) {
        return reply.code(400).send({ error: { message: err.message } });
      }
      if (err instanceof CreateVtcNotFoundError) {
        return reply.code(404).send({ error: { message: err.message } });
      }
      if (err instanceof CreateVtcConflictError) {
        return reply.code(409).send({ error: { message: err.message } });
      }
      return reply.code(400).send({ error: { message: (err as Error).message } });
    }
  });

  // GET /vtcs/check-name?name=... — pre-flight name availability check.
  app.get('/vtcs/check-name', async (req, reply) => {
    const name = (req.query as any)?.name;
    if (!name || !name.trim()) {
      return reply.code(400).send({ available: false, message: 'name query parameter is required' });
    }
    try {
      return reply.code(200).send(await checkCommunityNameAvailable(db, name));
    } catch (err) {
      return reply.code(200).send({ available: false, message: (err as Error).message });
    }
  });

  // POST /vtcs/proposals/:id/approve — submit an Ed25519-signed approval
  app.post('/vtcs/proposals/:id/approve', async (
    req: FastifyRequest<{ Params: { id: string }; Body: ApproveBody }>, reply: FastifyReply,
  ) => {
    if (!ceremonyCoordinator) {
      return reply.code(501).send({ error: { message: 'ceremony coordinator not available' } });
    }
    try {
      const result = await ceremonyCoordinator.recordApproval(
        req.params.id, req.body.approverDid, req.body.signature);
      return reply.code(200).send(result);
    } catch (err) {
      return reply.code(400).send({ error: { message: (err as Error).message } });
    }
  });

  // POST /vtcs/proposals/:id/admins — add an admin DID to a pending proposal
  app.post('/vtcs/proposals/:id/admins', async (
    req: FastifyRequest<{ Params: { id: string }; Body: { adminDid: string } }>, reply: FastifyReply,
  ) => {
    if (!ceremonyCoordinator) {
      return reply.code(501).send({ error: { message: 'ceremony coordinator not available' } });
    }
    try {
      await ceremonyCoordinator.addAdmin(req.params.id, req.body.adminDid);
      return reply.code(200).send({ ok: true });
    } catch (err) {
      return reply.code(400).send({ error: { message: (err as Error).message } });
    }
  });

  // GET /vtcs/proposals/:id — fetch proposal status + approvals
  app.get('/vtcs/proposals/:id', async (
    req: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply,
  ) => {
    if (!ceremonyCoordinator) {
      return reply.code(501).send({ error: { message: 'ceremony coordinator not available' } });
    }
    const detail = await ceremonyCoordinator.getProposal(req.params.id);
    if (!detail) return reply.code(404).send({ error: { message: 'proposal not found' } });
    return reply.code(200).send(detail);
  });

  // GET /vtcs/proposals — list all pending proposals
  app.get('/vtcs/proposals', async (_req, reply) => {
    if (!ceremonyCoordinator) {
      return reply.code(501).send({ error: { message: 'ceremony coordinator not available' } });
    }
    return reply.code(200).send(await ceremonyCoordinator.listPending());
  });


  // ── Admin management ──────────────────────────────────────────────────

  // POST /vtcs/:id/admins — add an admin to an existing VTC/VTN.
  app.post(
    '/vtcs/:uuid/admins',
    async (
      req: FastifyRequest<{ Params: { uuid: string }; Body: AddAdminBody }>,
      reply: FastifyReply,
    ) => {
      const communityUuid = req.params.uuid;
      const { adminIdentityUuid } = req.body ?? ({} as AddAdminBody);

      if (!communityUuid) {
        return reply.code(400).send({ error: { message: 'uuid is required' } });
      }
      if (!adminIdentityUuid) {
        return reply.code(400).send({ error: { message: 'adminIdentityUuid is required' } });
      }

      // Validate community exists and is a VTC/VTN
      const community = await identitiesRepo.findByUuid(db, communityUuid);
      if (!community) {
        return reply.code(404).send({ error: { message: `community ${communityUuid} not found` } });
      }
      if (community.role !== 'vtc' && community.role !== 'vtn') {
        return reply.code(400).send({ error: { message: `identity ${communityUuid} is not a VTC or VTN (role=${community.role})` } });
      }

      // Validate the admin identity exists and is a VTA
      const admin = await identitiesRepo.findByUuid(db, adminIdentityUuid);
      if (!admin) {
        return reply.code(404).send({ error: { message: `admin identity ${adminIdentityUuid} not found` } });
      }
      if (admin.role !== 'vta') {
        return reply.code(400).send({ error: { message: `identity ${adminIdentityUuid} is not a VTA` } });
      }

      // Check not already a member
      const existing = await membershipsRepo.findByPair(db, admin.uuid, community.uuid);
      if (existing) {
        return reply.code(409).send({ error: { message: `identity ${adminIdentityUuid} is already a member of this community` } });
      }

      // Create admin membership.
      // Post-creation admin additions use role 'admin' — founding_admin
      // is reserved for the initial founders specified at creation time.
      const memberRole: MembershipRole = 'admin';

      const membershipUuid = await membershipsRepo.create(db, {
        memberIdentityUuid: admin.uuid,
        communityIdentityUuid: community.uuid,
        role: memberRole,
        status: 'active',
      });
      await membershipsRepo.approve(db, membershipUuid, null);
      try { const { DidManager } = await import("@p2p-trust-stack/core/services/did-manager.js"); await new DidManager(db).createMemberDid(admin.uuid, communityUuid); } catch (err) { console.warn("[vtcs] M-DID skipped for admin", admin.uuid, ":", (err as Error).message); }

      // Update governance N count
      const gov = await governanceRepo.findForCommunity(db, communityUuid);
      if (gov) {
        await governanceRepo.update(db, communityUuid, {
          adminThresholdN: (gov.adminThresholdN ?? 0) + 1,
        });
      }

      const membership = await membershipsRepo.findByUuid(db, membershipUuid);

      // ── Fan-out delivery to the (now active) admin via the CRE engine ─────
      // Idempotent: existing founders already have their idempotency_key, so
      // only the new admin gets a fresh queue row, delivering the full community
      // package to them via the durable queue when reachable.
      await tryEnqueueFanout('vtc-membership', { communityUuid });

      return reply.code(201).send({ membership });
    },
  );

  // ── Community lifecycle ───────────────────────────────────────────────

  // DELETE /vtcs/:id — permanently delete a VTC/VTN and all related data.
  // Cascades via ON DELETE CASCADE: governance, memberships, credentials,
  // status_lists, did_documents, keys, profiles, relationships, etc.
  app.delete(
    '/vtcs/:uuid',
    async (
      req: FastifyRequest<{ Params: { uuid: string } }>,
      reply: FastifyReply,
    ) => {
      const uuid = req.params.uuid;

      const community = await identitiesRepo.findByUuid(db, uuid);
      if (!community) {
        return reply.code(404).send({ error: { message: `community ${uuid} not found` } });
      }
      if (community.role !== 'vtc' && community.role !== 'vtn') {
        return reply.code(400).send({ error: { message: `identity ${uuid} is not a VTC or VTN (role=${community.role})` } });
      }

      const name = community.name ?? community.uuid;
      await db.run('DELETE FROM identities WHERE uuid = ?', uuid);
      console.log(`[vtcs] Deleted community: ${name} (uuid=${uuid})`);

      return reply.code(200).send({ deleted: true, uuid, name });
    },
  );
}
