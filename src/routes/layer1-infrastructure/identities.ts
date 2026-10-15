/**
 * Layer 1 — Infrastructure: /identities routes.
 *
 * CRUD-ish surface over the `identities` table (VTAs, VTCs, VTNs).
 * The real DID lives in did_documents.did; identities.uuid is the stable identity key.
 *
 * Routes:
 *   POST /identities             — create identity (local custody)
 *   POST /identities/remote      — agent-pushed identity (remote custody, no secrets)
 *   GET  /identities             — list all
 *   GET  /identities/:param      — by integer ID or UUID
 *   GET  /identities/by-did/:did — by real DID (joins did_documents)
 *   GET  /identities/by-peer/:id — by libp2p PeerID
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import type { IdentityRole, Custody, SubjectKind } from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import { createRemoteVta } from '@p2p-trust-stack/core/services/vta.js';
import { setActiveEndpoint } from '@p2p-trust-stack/core/db/repositories/peer-endpoints-repo.js';

interface CreateIdentityBody {
  realDid: string;
  role: IdentityRole;
  subjectKind?: SubjectKind;
  custody?: Custody;
  name?: string;
  vid?: string;
  peerId?: string;
}

interface RemoteVtaBody {
  realDid: string;
  name?: string;
  subjectKind?: SubjectKind;
  didDocument: object;
  publicKeys: { ed25519: string; x25519: string };
  peerId?: string;
}

interface ListQuery {
  role?: IdentityRole;
  custody?: Custody;
  subject_kind?: SubjectKind;
}

export function registerIdentityRoutes(app: FastifyInstance, db: DataSource): void {

  // ── Create identity (local custody) ─────────────────────────────────────
  app.post('/identities', async (req: FastifyRequest<{ Body: CreateIdentityBody }>, reply: FastifyReply) => {
    const body = req.body;
    if (!body?.realDid || !body?.role) {
      return reply.code(400).send({ error: { message: 'realDid and role are required' } });
    }

    const identityUuid = await identitiesRepo.create(db, {
      realDid: body.realDid,
      role: body.role,
      subjectKind: body.subjectKind,
      custody: body.custody ?? 'local',
      name: body.name,
      vid: body.vid,
      peerId: body.peerId,
    });

    if (body.peerId) {
      const identity = await identitiesRepo.findByUuid(db, identityUuid);
      if (identity) {
        await setActiveEndpoint(db, { identityUuid: identity.uuid, peerId: body.peerId });
      }
    }

    const identity = await identitiesRepo.findByUuid(db, identityUuid);
    return reply.code(201).send(identity);
  });

  // ── Agent-pushed identity (remote custody) — Phase 2 ────────────────────
  app.post('/identities/remote', async (req: FastifyRequest<{ Body: RemoteVtaBody }>, reply: FastifyReply) => {
    const body = req.body;
    if (!body?.realDid) {
      return reply.code(400).send({ error: { message: 'realDid is required' } });
    }

    try {
      const result = await createRemoteVta(db, {
        realDid: body.realDid,
        name: body.name,
        subjectKind: body.subjectKind,
        didDocument: body.didDocument,
        publicKeys: body.publicKeys,
        peerId: body.peerId,
      });
      return reply.code(201).send(result);
    } catch (err) {
      return reply.code(500).send({ error: { message: err instanceof Error ? err.message : String(err) } });
    }
  });

  // ── List identities ─────────────────────────────────────────────────────
  // Supports ?role=, ?custody=, and ?subject_kind=. When subject_kind is
  // provided, uses findByRoleAndSubjectKind which also excludes TSP-bridge
  // fakes (peer_id IS NULL) — returning only real, agent-registered VTAs.
  app.get('/identities', async (req: FastifyRequest<{ Querystring: ListQuery }>, _reply: FastifyReply) => {
    const { role, custody, subject_kind } = req.query;

    if (role && subject_kind) {
      return identitiesRepo.findByRoleAndSubjectKind(db, role, subject_kind);
    }

    return identitiesRepo.list(db, { role, custody });
  });

  // ── Get identity by UUID ────────────────────────────────────────────────
  app.get('/identities/:param', async (req: FastifyRequest<{ Params: { param: string } }>, reply: FastifyReply) => {
    const param = req.params.param;

    const identity = await identitiesRepo.findByUuid(db, param);
    if (!identity) {
      return reply.code(404).send({ error: { message: `identity ${param} not found` } });
    }
    return identity;
  });

  // ── Resolve by real DID string (joins did_documents) ────────────────────
  app.get('/identities/by-did/:did', async (req: FastifyRequest<{ Params: { did: string } }>, reply: FastifyReply) => {
    const did = decodeURIComponent(req.params.did);
    const identity = await identitiesRepo.findByRealDid(db, did);
    if (!identity) {
      return reply.code(404).send({ error: { message: 'identity not found for that DID' } });
    }
    return identity;
  });

  // ── Resolve by libp2p PeerID ───────────────────────────────────────────
  app.get('/identities/by-peer/:peerId', async (req: FastifyRequest<{ Params: { peerId: string } }>, reply: FastifyReply) => {
    const identity = await identitiesRepo.findByPeerId(db, req.params.peerId);
    if (!identity) {
      return reply.code(404).send({ error: { message: 'identity not found for that peer' } });
    }
    return identity;
  });
}