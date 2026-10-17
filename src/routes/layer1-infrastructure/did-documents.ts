// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Layer 1 — Infrastructure: /did-documents routes.
 *
 * CRUD-ish surface over the `did_documents` table. An identity can have
 * multiple did_document rows over its lifetime (e.g. one per DID method it
 * has ever used, or one per historical rotation-log-backed method
 * instance); exactly one is flagged `is_primary` at a time.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';

interface CreateDidDocumentBody {
  identityUuid: string;
  did: string;
  method: string;
  documentJson?: string;
  isPrimary?: boolean;
}

export function registerDidDocumentRoutes(app: FastifyInstance, db: DataSource): void {
  app.post(
    '/did-documents',
    async (req: FastifyRequest<{ Body: CreateDidDocumentBody }>, reply: FastifyReply) => {
      const body = req.body;
      if (!body?.identityUuid || !body?.did || !body?.method) {
        return reply.code(400).send({ error: { message: 'identityUuid, did, and method are required' } });
      }
      if (await didDocumentsRepo.findByRealDid(db, body.did)) {
        return reply.code(409).send({ error: { message: `did_document for ${body.did} already exists` } });
      }
      const identity = await identitiesRepo.findByUuid(db, body.identityUuid);
      if (!identity) {
        return reply.code(404).send({ error: { message: `identity ${body.identityUuid} not found` } });
      }
      const uuid = await didDocumentsRepo.create(db, body);
      return reply.code(201).send(await didDocumentsRepo.findByUuid(db, uuid));
    },
  );

  app.get(
    '/did-documents/:uuid',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const uuid = req.params.uuid;
      const doc = await didDocumentsRepo.findByUuid(db, uuid);
      if (!doc) {
        return reply.code(404).send({ error: { message: `did_document ${uuid} not found` } });
      }
      return doc;
    },
  );

  app.get(
    '/did-documents/by-did/:did',
    async (req: FastifyRequest<{ Params: { did: string } }>, reply: FastifyReply) => {
      const doc = await didDocumentsRepo.findByRealDid(db, decodeURIComponent(req.params.did));
      if (!doc) {
        return reply.code(404).send({ error: { message: 'did_document not found for that did' } });
      }
      return doc;
    },
  );

  // ── DID Resolution endpoint: rotation log by DID ──────────────────────
  // The utility server is the de-facto DID Resolution endpoint for
  // did:scid:vh in this DNS-free deployment. A resolver fetches the
  // append-only log here and replays it to reconstruct the current DID document.
  app.get(
    '/did-documents/by-did/:did/rotation-log',
    async (req: FastifyRequest<{ Params: { did: string } }>, reply: FastifyReply) => {
      const did = decodeURIComponent(req.params.did);
      const doc = await didDocumentsRepo.findByRealDid(db, did);
      if (!doc) {
        return reply.code(404).send({ error: { message: 'did_document not found for that did' } });
      }

      const { findForDidDocument } = await import('@p2p-trust-stack/core/db/repositories/rotation-repo.js');
      const rows = await findForDidDocument(db, doc.uuid);

      // Serialize the verifiable rotation entries so a remote resolver can
      // replay the chain. Byte fields are base64 for JSON transport.
      const log = rows.map((row) => ({
        uuid: row.uuid,
        did_document_uuid: row.didDocumentUuid,
        version: row.version,
        previous_hash: row.previousHash ? Buffer.from(row.previousHash).toString('base64') : null,
        new_public_key: Buffer.from(row.newPublicKey).toString('base64'),
        signed_entry: Buffer.from(row.signedEntry).toString('base64'),
        created_at: row.createdAt,
      }));

      return { did, did_document_uuid: doc.uuid, log };
    },
  );

  app.get(
    '/identities/:identityUuid/did-documents',
    async (req: FastifyRequest<{ Params: { identityUuid: string } }>) => {
      return didDocumentsRepo.listByIdentity(db, req.params.identityUuid);
    },
  );

  app.patch(
    '/did-documents/:uuid/primary',
    async (req: FastifyRequest<{ Params: { uuid: string }; Body: { identityUuid: string } }>, reply: FastifyReply) => {
      const { identityUuid } = req.body ?? ({} as { identityUuid: string });
      if (!req.params.uuid || !identityUuid) {
        return reply.code(400).send({ error: { message: 'uuid (param) and identityUuid (body) are required' } });
      }
      await didDocumentsRepo.setPrimary(db, req.params.uuid, identityUuid);
      return didDocumentsRepo.findByUuid(db, req.params.uuid);
    },
  );

  app.patch(
    '/did-documents/:uuid/status',
    async (
      req: FastifyRequest<{ Params: { uuid: string }; Body: { status: 'active' | 'deactivated' | 'superseded' } }>,
      reply: FastifyReply,
    ) => {
      const status = req.body?.status;
      if (!req.params.uuid || !status) {
        return reply.code(400).send({ error: { message: 'uuid (param) and status (body) are required' } });
      }
      await didDocumentsRepo.setStatus(db, req.params.uuid, status);
      return didDocumentsRepo.findByUuid(db, req.params.uuid);
    },
  );
}
