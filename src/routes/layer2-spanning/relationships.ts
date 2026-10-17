// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Layer 2 — Trust Spanning: /relationships routes.
 *
 * - POST /relationships/oobi   — generate an OOBI for a local identity
 * - POST /relationships        — establish a relationship from a received OOBI (drives RFI via RelationshipManager)
 * - GET  /relationships        — list relationships, optionally filtered by ?identityId=
 * - GET  /relationships/:id    — fetch a single relationship
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { Libp2p } from 'libp2p';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import { encodeOobi, decodeOobi } from '@p2p-trust-stack/core/relationship/oobi.js';
import { maybeSignOobi } from '@p2p-trust-stack/core/relationship/oobi-signer.js';
import { RelationshipManager } from '@p2p-trust-stack/core/relationship/manager.js';
import type { RelationshipStore } from '@p2p-trust-stack/core/relationship/store.js';
import { Libp2pTransport } from '@p2p-trust-stack/core/transport/libp2p-transport.js';
import type { LocalIdentity } from '@p2p-trust-stack/core/relationship/types.js';
import type { DidDocument } from '@p2p-trust-stack/core/did/types.js';
import { SqliteKeyStore } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
import { cesrEncode, CESR_CODES } from '@p2p-trust-stack/core/crypto/cesr.js';
import {
  DsIdentityResolver,
  DsRelationshipStore,
} from '../../node/relationship-store-ds.js';

import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import type { Identity } from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as relationshipsRepo from '@p2p-trust-stack/core/db/repositories/relationships-repo.js';

const DEV_PASSPHRASE = process.env.NODE_PASSPHRASE ?? 'dev-only-insecure-passphrase';

interface GenerateOobiBody {
  identityUuid: string;
}

interface CreateRelationshipBody {
  identityUuid: string;
  oobi: string;
}

interface ListQuery {
  identityUuid?: string;
}

/**
 * Build a LocalIdentity (as required by RelationshipManager) for a given
 * local identity row, loading its keys from the shared keystore.
 */
async function loadLocalIdentity(
  db: DataSource,
  keyStorePath: string,
  identityUuid: string,
): Promise<LocalIdentity> {
  const identity = await identitiesRepo.findByUuid(db, identityUuid);
  if (!identity) {
    throw new Error(`identity ${identityUuid} not found`);
  }
  const primaryDoc = await didDocumentsRepo.findPrimaryForIdentity(db, identityUuid);
  if (!primaryDoc || !primaryDoc.documentJson) {
    throw new Error(`identity ${identityUuid} has no primary did_document with a document_json`);
  }

  const keyStore = new SqliteKeyStore(keyStorePath);
  let signingKeyPair;
  let agreementKeyPair;
  try {
    signingKeyPair = await keyStore.retrieveKeyPairAsync(identity.did ?? identity.uuid, 'ed25519', DEV_PASSPHRASE);
    agreementKeyPair = await keyStore.retrieveKeyPairAsync(identity.did ?? identity.uuid, 'x25519', DEV_PASSPHRASE);
  } finally {
    keyStore.close();
  }

  const didDocument = JSON.parse(primaryDoc.documentJson);

  return {
    cesrVid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, signingKeyPair.publicKey),
    did: primaryDoc.did,
    didDocument,
    signingKeyPair,
    agreementKeyPair,
  };
}


export function registerRelationshipRoutes(
  app: FastifyInstance,
  db: DataSource,
  node: Libp2p,
  keyStorePath: string,
): void {
  // -------------------------------------------------------------------------
  // POST /relationships/oobi — generate an OOBI for a local identity
  // -------------------------------------------------------------------------
  app.post(
    '/relationships/oobi',
    async (req: FastifyRequest<{ Body: GenerateOobiBody }>, reply: FastifyReply) => {
      const { identityUuid } = req.body ?? ({} as GenerateOobiBody);
      if (!identityUuid) {
        return reply.code(400).send({ error: { message: 'identityUuid is required' } });
      }

      const identity = await identitiesRepo.findByUuid(db, identityUuid);
      if (!identity) {
        return reply.code(404).send({ error: { message: `identity ${identityUuid} not found` } });
      }

      const primaryDoc = await didDocumentsRepo.findPrimaryForIdentity(db, identityUuid);
      if (!primaryDoc || !primaryDoc.documentJson) {
        return reply
          .code(409)
          .send({ error: { message: `identity ${identityUuid} has no primary did_document` } });
      }

      let vid: string;
      try {
        const keyStore = new SqliteKeyStore(keyStorePath);
        let publicKey: Uint8Array;
        try {
          const kp = await keyStore.retrieveKeyPairAsync(identity.did ?? identity.uuid, 'ed25519', DEV_PASSPHRASE);
          publicKey = kp.publicKey;
        } finally {
          keyStore.close();
        }
        vid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, publicKey);
      } catch (err) {
        return reply.code(500).send({ error: { message: `failed to load signing key: ${(err as Error).message}` } });
      }

      const peerId = node.peerId.toString();
      const multiaddrs = node.getMultiaddrs().map((a) => a.toString());

      const oobiPayload = {
        cesrVid: vid,
        peerId,
        multiaddrs,
        did: identity.did ?? identity.uuid,
      };
      // Signed ONLY when this server is the authority for that identity's DID
      // (H2): the signature is verified against the ML-DSA key published in the
      // document of `oobi.did`, so signing an OOBI for a community or for an
      // agent's did:scid:vh — the founder-admin case — could never verify.
      const signedPayload = maybeSignOobi(oobiPayload);
      const oobi = encodeOobi(signedPayload);
      return reply.code(200).send({
        oobi, vid, peerId, multiaddrs,
        signed: !!signedPayload.mlDsa65Signature,
      });
    },
  );

  // -------------------------------------------------------------------------
  // POST /relationships — establish a relationship from a received OOBI
  // -------------------------------------------------------------------------
  app.post(
    '/relationships',
    async (req: FastifyRequest<{ Body: CreateRelationshipBody }>, reply: FastifyReply) => {
      const { identityUuid, oobi } = req.body ?? ({} as CreateRelationshipBody);
      if (!identityUuid || !oobi) {
        return reply.code(400).send({ error: { message: 'identityUuid and oobi are required' } });
      }

      const identity = await identitiesRepo.findByUuid(db, identityUuid);
      if (!identity) {
        return reply.code(404).send({ error: { message: `identity ${identityUuid} not found` } });
      }

      let localIdentity: LocalIdentity;
      try {
        localIdentity = await loadLocalIdentity(db, keyStorePath, identityUuid);
      } catch (err) {
        return reply.code(500).send({ error: { message: (err as Error).message } });
      }

      const resolver = new DsIdentityResolver(db);
      const dsStore = new DsRelationshipStore(db, resolver);
      const store = dsStore as unknown as RelationshipStore;

      const transport = new Libp2pTransport(node);
      const manager = new RelationshipManager({
        transport, store, identity: localIdentity,
        /**
         * Anchored document lookup for the OOBI introduction check (H2).
         *
         * This server already holds a document for every identity that has
         * connected to it or pushed its identity, so a first contact with a
         * did:scid:vh peer can be checked against our own record instead of
         * reporting it unverifiable — no network round trip and no dependence on
         * the artifact under test.
         */
        resolvePeerDocument: async (did: string) => {
          const row = await identitiesRepo.findByRealDid(db, did);
          if (!row) return undefined;
          const doc = await didDocumentsRepo.findPrimaryForIdentity(db, row.uuid);
          if (!doc?.documentJson) return undefined;
          try {
            return JSON.parse(doc.documentJson) as DidDocument;
          } catch {
            return undefined;
          }
        },
      });
      manager.start();

      try {
        await manager.sendRfi(oobi);
      } catch (err) {
        return reply.code(400).send({ error: { message: `failed to send RFI: ${(err as Error).message}` } });
      }

      // The RFI has been sent and an outbound-pending record now exists in
      // the (VID-keyed) RelationshipStore table. Mirror a corresponding row
      // into the identity-keyed `relationships` table used by the rest of
      // this API surface, so /relationships and /relationships/:id can
      // return it without callers needing to know about VIDs directly.
      const record = await store.get(localIdentity.cesrVid, decodeOobiVid(oobi));
      const remoteIdentity = await ensureRemoteIdentity(db, oobi);

      const relationshipUuid = await relationshipsRepo.create(db, {
        localIdentityUuid: identity.uuid,
        remoteIdentityUuid: remoteIdentity.uuid,
        direction: record?.direction ?? 'outbound',
        status: record?.status ?? 'pending',
        remoteTransport: record?.remoteTransport ? JSON.stringify(record.remoteTransport) : undefined,
      });

      const row = await relationshipsRepo.findByUuid(db, relationshipUuid);
      return reply.code(201).send(row);
    },
  );

  // -------------------------------------------------------------------------
  // GET /relationships — list, optionally filtered by ?identityId=
  // -------------------------------------------------------------------------
  app.get('/relationships', async (req: FastifyRequest<{ Querystring: ListQuery }>, reply: FastifyReply) => {
    const { identityUuid } = req.query;
    if (!identityUuid) {
      return reply.code(400).send({ error: { message: 'identityUuid query parameter is required' } });
    }
    return relationshipsRepo.listByLocal(db, identityUuid);
  });

  app.get(
    '/relationships/:uuid',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const uuid = req.params.uuid;
      const row = await relationshipsRepo.findByUuid(db, uuid);
      if (!row) {
        return reply.code(404).send({ error: { message: `relationship ${uuid} not found` } });
      }
      return row;
    },
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function decodeOobiVid(encodedOobi: string): string {
  return decodeOobi(encodedOobi).cesrVid;
}

/**
 * Ensure a remote `identities` row exists for the peer described by an OOBI,
 * creating a minimal remote-custody placeholder identity if one doesn't
 * already exist for that VID/did. Since Layer 2 has no DID resolution step
 * for arbitrary remote VIDs yet, the remote identity is recorded using the
 * VID itself as a stand-in `did` value when no did:peer:4 doc is available.
 */
async function ensureRemoteIdentity(db: DataSource, encodedOobi: string): Promise<Identity> {
  const oobi = decodeOobi(encodedOobi);
  const pseudoDid = `did:key:${oobi.cesrVid}`;

  const existing = await identitiesRepo.findByRealDid(db, pseudoDid);
  if (existing) return existing;

  const id = await identitiesRepo.create(db, {
    realDid: pseudoDid,
    role: 'vta',
    custody: 'remote',
    name: oobi.peerId,
  });

  const created = await identitiesRepo.findByUuid(db, id);
  if (!created) {
    throw new Error(`could not resolve created remote identity (id=${id})`);
  }
  return created;
}