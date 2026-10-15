/**
 * DataSource-backed RelationshipStore + IdentityResolver for the utility server.
 *
 * The shared RelationshipStore and IdentityResolver use `node:sqlite` DatabaseSync
 * directly, which is correct for the agent-app (SQLite on-device). The utility
 * server uses a YugabyteDB DataSource — this module provides the same conceptual
 * interface backed by DataSource async methods.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import { didToUuid, generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import {
  extractEd25519PublicKey,
  extractX25519PublicKey,
  extractHybridKemPublicKey,
  extractMlDsa65PublicKey,
  buildCleanPeer4FromDocument,
} from '@p2p-trust-stack/core/relationship/key-extract.js';
import type { DidDocument } from '@p2p-trust-stack/core/did/types.js';
import type { TransportAddress } from '@p2p-trust-stack/core/transport/types.js';
import type {
  RelationshipRecord,
  RelationshipDirection,
  RelationshipStatus,
} from '@p2p-trust-stack/core/relationship/types.js';

// ---------------------------------------------------------------------------
// ResolvedIdentity — same shape as IdentityResolver.ResolvedIdentity
// ---------------------------------------------------------------------------

export interface ResolvedIdentity {
  identityUuid: string;
  didDocumentUuid: string | null;
}

// ---------------------------------------------------------------------------
// Identity resolution (DataSource-backed)
// ---------------------------------------------------------------------------

export class DsIdentityResolver {
  private readonly db: DataSource;

  constructor(db: DataSource) {
    this.db = db;
  }

  /**
   * Ensure a local VTA identity row exists and return its IDs.
   */
  async resolveLocalIdentity(params: {
    did: string;
    name: string;
    method: string;
    peerId: string;
    cesrVid?: string;
    didDocumentJson?: string;
  }): Promise<ResolvedIdentity> {
    const existing = await this.db.get<{ uuid: string; vid: string | null }>(
      `SELECT i.uuid, i.vid FROM identities i
        JOIN did_documents d ON d.identity_uuid = i.uuid WHERE d.did = ?`,
      params.did,
    );
    const identityUuid = existing?.uuid ?? didToUuid(params.did);

    if (existing) {
      if (params.cesrVid && existing.vid !== params.cesrVid) {
        await this.db.run(
          'UPDATE identities SET vid = ? WHERE uuid = ?',
          params.cesrVid,
          identityUuid,
        );
      }
    } else {
      await this.db.run(
        `INSERT INTO identities (uuid, role, subject_kind, custody, name, vid)
         VALUES (?, 'vta', 'organization', 'local', ?, ?)`,
        identityUuid,
        params.name,
        params.cesrVid ?? null,
      );
    }

    const didDoc = await this.upsertDidDocument({
      identityUuid,
      realDid: params.did,
      method: params.method,
      documentJson: params.didDocumentJson,
      isPrimary: 1,
    });

    // Record the server/agent's live endpoint through the guarded
    // peer_endpoints write (refuses cross-identity claims, retires
    // superseded endpoints).
    if (params.peerId) {
      await this.upsertPeerEndpoint(identityUuid, params.peerId);
    }

    return { identityUuid, didDocumentUuid: didDoc.uuid };
  }

  /**
   * Ensure a remote VTA identity row exists and return its IDs.
   */
  async resolveRemoteIdentity(params: {
    did: string;
    method: string;
    name?: string;
    peerId?: string;
    didDocumentJson?: string;
    /** Whether this DID document is primary (default true). Handshake identities use false. */
    isPrimary?: boolean;
    /** Node ID that recorded this row (for replication tracking). */
    recordedByNode?: string;
    /**
     * Whether an unseen DID may be MATERIALIZED as a new identity row
     * (default `true`).
     *
     * Pass `false` for any path driven by an UNVERIFIED value — most importantly
     * the TSP bridge's per-message endpoint recording, which runs on every inbound
     * envelope right after `peekEnvelope()` (a parse, not a signature check). With
     * the default, any peer could make this node INSERT an identity row keyed by
     * `didToUuid(<whatever it put in the envelope's VID field>)`, i.e. mint an
     * orphan identity with no document, no key and no endpoint. Those orphans are
     * what `createVtc`'s `hasAnyEndpoint` discriminator and
     * `resolveRealVtaForStub` exist to work around.
     *
     * With `false` the method returns `null` instead of creating the row; the
     * caller should treat that as "unknown sender" and do nothing.
     */
    createIfMissing?: boolean;
  }): Promise<ResolvedIdentity | null> {
    const existing = await this.db.get<{ uuid: string }>(
      `SELECT i.uuid FROM identities i
        JOIN did_documents d ON d.identity_uuid = i.uuid WHERE d.did = ?`,
      params.did,
    );
    let identityUuid = existing?.uuid ?? didToUuid(params.did);

    if (!existing) {
      // The deterministic uuid may already exist WITHOUT a document row for this
      // DID (a document-less identity, or one whose document is under another
      // DID). Treat that as existing rather than colliding on the primary key.
      const rowForUuid = await this.db.get<{ uuid: string }>(
        'SELECT uuid FROM identities WHERE uuid = ?',
        identityUuid,
      );
      if (rowForUuid) {
        identityUuid = rowForUuid.uuid;
      } else if (params.createIfMissing === false) {
        return null;
      } else {
        await this.db.run(
          `INSERT INTO identities (uuid, role, subject_kind, custody, name)
           VALUES (?, 'vta', 'human', 'remote', ?)`,
          identityUuid,
          params.name ?? null,
        );
      }
    }

    const didDoc = await this.upsertDidDocument({
      identityUuid,
      realDid: params.did,
      method: params.method,
      documentJson: params.didDocumentJson,
      isPrimary: params.isPrimary !== false ? 1 : 0,
      recordedByNode: params.recordedByNode,
    });

    if (params.didDocumentJson && didDoc.uuid) {
      await this.upsertRemotePublicKeys(identityUuid, didDoc.uuid, params.didDocumentJson);
    }

    // Handshake stubs (no peerId) get NO endpoint — preserving the
    // "TSP-bridge fake has no endpoint" discriminator. When a real peer
    // (with a peerId) is resolved, record its live endpoint.
    if (params.peerId) {
      await this.upsertPeerEndpoint(identityUuid, params.peerId);
    }

    return { identityUuid, didDocumentUuid: didDoc.uuid };
  }

  /**
   * Guarded endpoint write (DataSource-backed version of the shared
   * peer-endpoints-repo `setActiveEndpoint`). Refuses to claim a peer that is
   * already active on a different identity, and retires the identity's other
   * active endpoints.
   */
  private async upsertPeerEndpoint(identityUuid: string, peerId: string): Promise<void> {
    const owner = await this.db.get<{ uuid: string; identity_uuid: string; is_active: number }>(
      'SELECT uuid, identity_uuid, is_active FROM peer_endpoints WHERE peer_id = ?',
      peerId,
    );
    if (owner && owner.is_active === 1 && owner.identity_uuid !== identityUuid) {
      console.warn(
        `[DsIdentityResolver] refusing to assign peer ${peerId.slice(0, 12)}... ` +
        `to identity ${identityUuid.slice(0, 8)} — already active on ${owner.identity_uuid.slice(0, 8)}`,
      );
      return;
    }

    if (owner) {
      await this.db.run(
        'UPDATE peer_endpoints SET identity_uuid = ?, is_active = 1, updated_at = ?, last_seen_at = ? WHERE uuid = ?',
        identityUuid,
        Math.floor(Date.now() / 1000),
        Math.floor(Date.now() / 1000),
        owner.uuid,
      );
    } else {
      const rowUuid = generateUuid();
      await this.db.run(
        `INSERT INTO peer_endpoints (uuid, identity_uuid, peer_id, is_active, created_at, updated_at, last_seen_at)
         VALUES (?, ?, ?, 1, ?, ?, ?)`,
        rowUuid,
        identityUuid,
        peerId,
        Math.floor(Date.now() / 1000),
        Math.floor(Date.now() / 1000),
        Math.floor(Date.now() / 1000),
      );
    }

    await this.db.run(
      `UPDATE peer_endpoints SET is_active = 0, updated_at = ?
       WHERE identity_uuid = ? AND peer_id <> ? AND is_active = 1`,
      Math.floor(Date.now() / 1000),
      identityUuid,
      peerId,
    );
  }

  async lookupByDid(did: string): Promise<ResolvedIdentity | undefined> {
    const ident = await this.db.get<{ uuid: string }>(
      `SELECT i.uuid FROM identities i
        JOIN did_documents d ON d.identity_uuid = i.uuid WHERE d.did = ?`,
      did,
    );
    if (!ident) return undefined;

    const didDoc = await this.db.get<{ uuid: string }>(
      'SELECT uuid FROM did_documents WHERE identity_uuid = ? AND is_primary = 1',
      ident.uuid,
    );

    return {
      identityUuid: ident.uuid,
      didDocumentUuid: didDoc?.uuid ?? null,
    };
  }

  private async upsertDidDocument(params: {
    identityUuid: string;
    realDid: string;
    method: string;
    documentJson?: string;
    isPrimary?: number;
    recordedByNode?: string;
  }): Promise<{ uuid: string | null }> {
    const existing = await this.db.get<{ uuid: string }>(
      'SELECT uuid FROM did_documents WHERE identity_uuid = ? AND did = ?',
      params.identityUuid,
      params.realDid,
    );

    if (existing) {
      if (params.documentJson) {
        await this.db.run(
          'UPDATE did_documents SET document_json = ? WHERE uuid = ?',
          params.documentJson,
          existing.uuid,
        );
      }
      return { uuid: existing.uuid };
    }

    const uuid = generateUuid();
    await this.db.run(
      `INSERT INTO did_documents
         (identity_uuid, did, method, document_json, is_primary, status, uuid, recorded_by_node)
       VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`,
      params.identityUuid,
      params.realDid,
      params.method,
      params.documentJson ?? null,
      params.isPrimary ?? 0,
      uuid,
      params.recordedByNode ?? null,
    );
    return { uuid };
  }

  private async upsertRemotePublicKeys(
    identityUuid: string,
    didDocumentUuid: string | null,
    documentJson: string,
  ): Promise<void> {
    let doc: DidDocument;
    try {
      doc = JSON.parse(documentJson) as DidDocument;
    } catch {
      return;
    }

    const keyEntries: Array<{ keyType: 'ed25519' | 'x25519' | 'mlkem768_x25519' | 'ml_dsa_65'; publicKey: Uint8Array }> = [];

    try {
      keyEntries.push({ keyType: 'ed25519', publicKey: extractEd25519PublicKey(doc) });
    } catch { /* skip */ }

    try {
      keyEntries.push({ keyType: 'x25519', publicKey: extractX25519PublicKey(doc) });
    } catch { /* skip */ }

    // MLKEM768-X25519 hybrid KEM key from #key-kem, when the peer publishes one.
    // Recorded so DsRelationshipStore can expose it and confidential traffic to
    // that peer can use post-quantum key agreement (absent → stays classical).
    try {
      const kemKey = extractHybridKemPublicKey(doc);
      if (kemKey) keyEntries.push({ keyType: 'mlkem768_x25519', publicKey: kemKey });
    } catch { /* skip */ }

    // ML-DSA-65 root-of-trust key from #key-mldsa. Recorded for the same reason
    // the agent records it: it verifies the peer's OOBI introduction signature,
    // and a did:scid:vh peer's DID cannot be resolved locally (see the fallback
    // in RelationshipManager.checkOobiIntroductionIntegrity).
    try {
      const mlDsaKey = extractMlDsa65PublicKey(doc);
      if (mlDsaKey) keyEntries.push({ keyType: 'ml_dsa_65', publicKey: mlDsaKey });
    } catch { /* skip */ }

    for (const entry of keyEntries) {
      const existing = await this.db.get<{ uuid: string }>(
        'SELECT uuid FROM keys WHERE identity_uuid = ? AND key_type = ? AND rotation_version = 0',
        identityUuid,
        entry.keyType,
      );
      if (existing) continue;

      const keyUuid = generateUuid();
      await this.db.run(
        `INSERT INTO keys
           (identity_uuid, did_document_uuid,
            key_type, public_key, rotation_version, uuid)
         VALUES (?, ?, ?, ?, 0, ?)`,
        identityUuid,
        didDocumentUuid,
        entry.keyType,
        Buffer.from(entry.publicKey),
        keyUuid,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// RelationshipStore (DataSource-backed)
// ---------------------------------------------------------------------------

export class DsRelationshipStore {
  private readonly db: DataSource;
  private readonly resolver: DsIdentityResolver;

  constructor(
    db: DataSource,
    resolver: DsIdentityResolver,
  ) {
    this.db = db;
    this.resolver = resolver;
  }

  /**
   * Resolve the peer identity for a store operation, materializing it when absent
   * (the resolver's default). The store's operations all require a persisted peer
   * row, so a null result — only reachable when a caller passes
   * `createIfMissing: false` — is a hard error here.
   */
  private async requireRemoteIdentity(
    params: Parameters<DsIdentityResolver['resolveRemoteIdentity']>[0],
  ): Promise<ResolvedIdentity> {
    const remote = await this.resolver.resolveRemoteIdentity(params);
    if (!remote) {
      throw new Error(
        `DsRelationshipStore: remote identity ${params.did} does not exist and could not be created`,
      );
    }
    return remote;
  }

  async insertOutbound(params: {
    localDid: string;
    localMethod: string;
    remoteDid: string;
    remoteMethod: string;
    didDocument?: DidDocument;
    remoteTransport: TransportAddress;
    rfiDigest?: Uint8Array;
  }): Promise<void> {
    const local = await this.ensureLocalIdentity(params.localDid);
    const remote = await this.requireRemoteIdentity({
      did: params.remoteDid,
      method: params.remoteMethod,
      didDocumentJson: params.didDocument
        ? JSON.stringify(buildCleanPeer4FromDocument(params.didDocument))
        : undefined,
      isPrimary: false,
      recordedByNode: 'tsp-bridge',
    });

    const existing = await this.db.get<{ 1: number }>(
      'SELECT 1 FROM relationships WHERE local_identity_uuid = ? AND remote_identity_uuid = ?',
      local.identityUuid,
      remote.identityUuid,
    );
    if (existing) {
      throw new Error('DsRelationshipStore.insertOutbound: relationship already exists');
    }

    await this.db.run(
      `INSERT INTO relationships
         (local_identity_uuid, remote_identity_uuid,
          local_did_document_uuid, remote_did_document_uuid,
          direction, status, remote_transport, rfi_digest, uuid)
       VALUES (?, ?, ?, ?, 'outbound', 'pending', ?, ?, gen_random_uuid())`,
      local.identityUuid,
      remote.identityUuid,
      local.didDocumentUuid,
      remote.didDocumentUuid,
      JSON.stringify(params.remoteTransport),
      params.rfiDigest ?? null,
    );
  }

  async upsertInbound(params: {
    localDid: string;
    localMethod: string;
    remoteDid: string;
    remoteMethod: string;
    didDocument: DidDocument;
    remoteTransport: TransportAddress;
    rfiDigest?: Uint8Array;
  }): Promise<'accepted' | 'rejected-lower-digest'> {
    const local = await this.ensureLocalIdentity(params.localDid);
    const remote = await this.requireRemoteIdentity({
      did: params.remoteDid,
      method: params.remoteMethod,
      didDocumentJson: JSON.stringify(buildCleanPeer4FromDocument(params.didDocument)),
      isPrimary: false,
      recordedByNode: 'tsp-bridge',
    });

    const existing = await this.db.get<{ direction: string }>(
      'SELECT direction FROM relationships WHERE local_identity_uuid = ? AND remote_identity_uuid = ?',
      local.identityUuid,
      remote.identityUuid,
    );

    if (existing && existing.direction === 'outbound') {
      await this.db.run(
        `UPDATE relationships SET direction = 'bidirectional', status = 'established',
           remote_transport = ?, rfi_digest = COALESCE(rfi_digest, ?)
         WHERE local_identity_uuid = ? AND remote_identity_uuid = ?`,
        JSON.stringify(params.remoteTransport),
        params.rfiDigest ?? null,
        local.identityUuid,
        remote.identityUuid,
      );
    } else if (existing) {
      await this.db.run(
        `UPDATE relationships SET direction = 'inbound', status = 'pending',
           remote_transport = ?, rfi_digest = COALESCE(rfi_digest, ?)
         WHERE local_identity_uuid = ? AND remote_identity_uuid = ?`,
        JSON.stringify(params.remoteTransport),
        params.rfiDigest ?? null,
        local.identityUuid,
        remote.identityUuid,
      );
    } else {
      await this.db.run(
        `INSERT INTO relationships
           (local_identity_uuid, remote_identity_uuid,
            local_did_document_uuid, remote_did_document_uuid,
            direction, status, remote_transport, rfi_digest, uuid)
         VALUES (?, ?, ?, ?, 'inbound', 'pending', ?, ?, gen_random_uuid())`,
        local.identityUuid,
        remote.identityUuid,
        local.didDocumentUuid,
        remote.didDocumentUuid,
        JSON.stringify(params.remoteTransport),
        params.rfiDigest ?? null,
      );
    }

    return 'accepted';
  }

  async confirmBidirectional(params: {
    localDid: string;
    remoteDid: string;
    remoteTransport: TransportAddress;
    rfaReplyDigest?: Uint8Array;
  }): Promise<void> {
    const local = await this.resolver.lookupByDid(params.localDid);
    const remote = await this.resolver.lookupByDid(params.remoteDid);
    if (!local || !remote) {
      throw new Error('DsRelationshipStore.confirmBidirectional: identity not resolved');
    }

    const result = await this.db.run(
      `UPDATE relationships SET direction = 'bidirectional', status = 'established',
         remote_transport = ?,
         rfa_reply_digest = COALESCE(?, rfa_reply_digest)
       WHERE local_identity_uuid = ? AND remote_identity_uuid = ?`,
      JSON.stringify(params.remoteTransport),
      params.rfaReplyDigest ?? null,
      local.identityUuid,
      remote.identityUuid,
    );

    if (result.changes === 0) {
      throw new Error('DsRelationshipStore.confirmBidirectional: no record found');
    }
  }

  async setRfaReplyDigest(localDid: string, remoteDid: string, rfaReplyDigest: Uint8Array): Promise<void> {
    const local = await this.resolver.lookupByDid(localDid);
    const remote = await this.resolver.lookupByDid(remoteDid);
    if (!local || !remote) return;

    await this.db.run(
      'UPDATE relationships SET rfa_reply_digest = ? WHERE local_identity_uuid = ? AND remote_identity_uuid = ?',
      rfaReplyDigest,
      local.identityUuid,
      remote.identityUuid,
    );
  }

  async storeRemoteDidDocument(
    localDid: string,
    remoteDid: string,
    didDocument: DidDocument,
  ): Promise<void> {
    const local = await this.resolver.lookupByDid(localDid);
    const remoteBefore = await this.resolver.lookupByDid(remoteDid);
    if (!local || !remoteBefore) return;

    const remote = await this.requireRemoteIdentity({
      did: remoteDid,
      method: remoteDid.startsWith('did:scid:vh:') ? 'did:scid:vh' : 'did:peer:4',
      didDocumentJson: JSON.stringify(buildCleanPeer4FromDocument(didDocument)),
      isPrimary: false,
      recordedByNode: 'tsp-bridge',
    });

    if (remote.didDocumentUuid) {
      await this.db.run(
        `UPDATE relationships SET
           remote_did_document_uuid = ?
         WHERE local_identity_uuid = ? AND remote_identity_uuid = ?`,
        remote.didDocumentUuid,
        local.identityUuid,
        remote.identityUuid,
      );
    }
  }

  async updateTransport(localDid: string, remoteDid: string, transport: TransportAddress): Promise<void> {
    const local = await this.resolver.lookupByDid(localDid);
    const remote = await this.resolver.lookupByDid(remoteDid);
    if (!local || !remote) return;

    await this.db.run(
      'UPDATE relationships SET remote_transport = ? WHERE local_identity_uuid = ? AND remote_identity_uuid = ?',
      JSON.stringify(transport),
      local.identityUuid,
      remote.identityUuid,
    );
  }

  async get(localDid: string, remoteDid: string): Promise<RelationshipRecord | undefined> {
    const local = await this.resolver.lookupByDid(localDid);
    const remote = await this.resolver.lookupByDid(remoteDid);
    if (!local || !remote) return undefined;

    const row = await this.db.get<{
      uuid: string; direction: string; status: string;
      remote_transport: string | null;
      rfi_digest: Buffer | null; rfa_reply_digest: Buffer | null;
      remote_ed25519_key: Buffer | null; remote_x25519_key: Buffer | null;
      remote_hybrid_kem_key: Buffer | null;
      remote_ml_dsa_65_key: Buffer | null;
    }>(
      `SELECT r.uuid, r.direction, r.status, r.remote_transport,
              r.rfi_digest, r.rfa_reply_digest,
              ked.public_key AS remote_ed25519_key,
              kex.public_key AS remote_x25519_key,
              khyb.public_key AS remote_hybrid_kem_key,
              kmld.public_key AS remote_ml_dsa_65_key
       FROM relationships r
       LEFT JOIN identities ri ON ri.uuid = r.remote_identity_uuid
       LEFT JOIN keys ked ON ked.identity_uuid = ri.uuid
                          AND ked.key_type = 'ed25519'
                          AND ked.rotation_version = 0
       LEFT JOIN keys kex ON kex.identity_uuid = ri.uuid
                          AND kex.key_type = 'x25519'
                          AND kex.rotation_version = 0
       -- The peer's MLKEM768-X25519 key, when it publishes one. Only a HINT for
       -- which KEM split to try first when opening a confidential message (the
       -- AEAD authenticates, so the other split is tried regardless) — but
       -- without it every hybrid sender would log a spurious "stale keys" note.
       LEFT JOIN keys khyb ON khyb.identity_uuid = ri.uuid
                          AND khyb.key_type = 'mlkem768_x25519'
                          AND khyb.rotation_version = 0
       -- The peer's ML-DSA-65 root-of-trust key, used to verify an OOBI
       -- introduction from a did:scid:vh peer (whose DID cannot be resolved
       -- locally). See RelationshipRecord.remoteMlDsa65Key.
       LEFT JOIN keys kmld ON kmld.identity_uuid = ri.uuid
                          AND kmld.key_type = 'ml_dsa_65'
                          AND kmld.rotation_version = 0
       WHERE r.local_identity_uuid = ? AND r.remote_identity_uuid = ?
       -- Deterministic verification-key selection: prefer the row linked to the
       -- peer's PRIMARY did_document (the one identity_push maintains), then the
       -- newest. Without an ORDER BY, the JOIN over two ed25519/rv-0 rows picked
       -- one arbitrarily, so this node sometimes verified TSP signatures with a
       -- stale key ("tspOpen: signature verification failed"). See
       -- syncRemotePublicKeys() in src/services/vta.ts for the write-side
       -- convergence that keeps a single active row.
       ORDER BY (ked.did_document_uuid = (
                   SELECT d.uuid FROM did_documents d
                    WHERE d.identity_uuid = ri.uuid AND d.is_primary = 1
                 )) DESC NULLS LAST,
                ked.created_at DESC
       LIMIT 1`,
      local.identityUuid,
      remote.identityUuid,
    );

    if (!row) return undefined;

    return {
      localDid: localDid,
      remoteDid: remoteDid,
      direction: row.direction as RelationshipDirection,
      status: row.status as RelationshipStatus,
      rfiDigest: row.rfi_digest ? new Uint8Array(row.rfi_digest) : undefined,
      rfaReplyDigest: row.rfa_reply_digest ? new Uint8Array(row.rfa_reply_digest) : undefined,
      remoteEd25519Key: row.remote_ed25519_key ? new Uint8Array(row.remote_ed25519_key) : undefined,
      remoteX25519Key: row.remote_x25519_key ? new Uint8Array(row.remote_x25519_key) : undefined,
      remoteHybridKemKey: row.remote_hybrid_kem_key
        ? new Uint8Array(row.remote_hybrid_kem_key)
        : undefined,
      remoteMlDsa65Key: row.remote_ml_dsa_65_key
        ? new Uint8Array(row.remote_ml_dsa_65_key)
        : undefined,
      remoteTransport: row.remote_transport
        ? (JSON.parse(row.remote_transport) as TransportAddress)
        : undefined,
      createdAt: 0,
      updatedAt: 0,
    };
  }

  private async ensureLocalIdentity(did: string) {
    const resolved = await this.resolver.lookupByDid(did);
    if (!resolved) {
      throw new Error(`DsRelationshipStore: local identity "${did}" not resolved`);
    }
    return resolved;
  }
}