/**
 * Recovery Service — assembles the full public state for a VTA identity
 * so it can be restored on a new device after loss.
 *
 * Flow:
 * 1. User authenticates to a utility server (challenge-response, recovery key, or social recovery)
 * 2. Server returns the VTA's full public state: identity, DIDs, keys, credentials, memberships, rotations
 * 3. User generates new keys on the new device, creates a rotation entry
 * 4. Recovery rotation is published to pubsub, network nodes update their state
 *
 * Private data (encrypted secret keys, passphrases, messages) is NEVER returned.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as keysRepo from '@p2p-trust-stack/core/db/repositories/keys-repo.js';

/**
 * Resolve the CURRENT active libp2p peer for an identity from the normalized
 * `peer_endpoints` table, falling back to the legacy identities.peer_id mirror
 * only when no endpoint row exists.
 */
async function resolveActivePeerId(
  db: DataSource,
  identityUuid: string,
  legacyPeerId: string | null,
): Promise<string | null> {
  const row = await db.get<{ peer_id: string }>(
    `SELECT peer_id FROM peer_endpoints
     WHERE identity_uuid = ? AND is_active = 1
     ORDER BY updated_at DESC, created_at DESC LIMIT 1`,
    identityUuid,
  );
  return row?.peer_id ?? legacyPeerId ?? null;
}

export interface RecoveryState {
  identity: {
    uuid: string;
    role: string;
    subjectKind: string | null;
    name: string | null;
    vid: string | null;
    peerId: string | null;
    createdAt: number | null;
  };
  didDocuments: Array<{
    uuid: string;
    did: string;
    method: string;
    documentJson: string | null;
    isPrimary: boolean;
    status: string;
    createdAt: number | null;
  }>;
  publicKeys: Array<{
    uuid: string;
    keyType: string;
    publicKey: string; // base64
    rotationVersion: number;
    createdAt: number | null;
  }>;
  rotationLog: Array<{
    uuid: string;
    version: number;
    previousHash: string | null; // base64
    newPublicKey: string; // base64
    signedEntry: string; // base64
    createdAt: number | null;
  }>;
  witnessAttestations: Array<{
    uuid: string;
    rotationLogUuid: string;
    witnessDidDocumentUuid: string;
    signature: string; // base64
    attestedAt: number | null;
  }>;
  credentials: Array<{
    uuid: string;
    vcType: string;
    issuerIdentityUuid: string;
    claim: string | null;
    status: string;
    validFrom: number;
    validUntil: number | null;
    createdAt: number | null;
  }>;
  memberships: Array<{
    uuid: string;
    communityIdentityUuid: string;
    role: string;
    status: string;
    issuedAt: number | null;
  }>;
  relationships: Array<{
    uuid: string;
    remoteIdentityUuid: string;
    direction: string;
    status: string;
    remoteTransport: string | null;
    createdAt: number | null;
  }>;
}

/** Return the full public state for a given identity UUID. */
export async function assembleRecoveryState(
  db: DataSource,
  identityUuid: string,
): Promise<RecoveryState | null> {
  const identity = await identitiesRepo.findByUuid(db, identityUuid);
  if (!identity) return null;

  // ── DID documents ──────────────────────────────────────────────────────
  const didDocs = await didDocumentsRepo.findByIdentityUuid(db, identityUuid);
  const didDocsOut = didDocs.map(d => ({
    uuid: d.uuid,
    did: d.did,
    method: d.method,
    documentJson: d.documentJson,
    isPrimary: d.isPrimary === 1,
    status: d.status,
    createdAt: d.createdAt,
  }));

  // ── Public keys (NEVER return encrypted secret material) ───────────────
  const keys = await keysRepo.findByIdentityUuid(db, identityUuid);
  const keysOut = keys.map(k => ({
    uuid: k.uuid,
    keyType: k.keyType,
    publicKey: k.publicKey ? k.publicKey.toString('base64') : '',
    rotationVersion: k.rotationVersion,
    createdAt: k.createdAt,
  }));

  // ── Rotation log ───────────────────────────────────────────────────────
  const rotationRows = await db.all<{
    uuid: string; version: number; previous_hash: Buffer | null;
    new_public_key: Buffer; signed_entry: Buffer; created_at: number | null;
  }>(`
    SELECT rl.uuid, rl.version, rl.previous_hash, rl.new_public_key,
           rl.signed_entry, rl.created_at
    FROM rotation_log rl
    JOIN did_documents dd ON dd.uuid = rl.did_document_uuid
    WHERE dd.identity_uuid = ?
    ORDER BY rl.version ASC
  `, identityUuid);

  const rotationLog = rotationRows.map(r => ({
    uuid: r.uuid,
    version: r.version,
    previousHash: r.previous_hash ? r.previous_hash.toString('base64') : null,
    newPublicKey: r.new_public_key ? r.new_public_key.toString('base64') : '',
    signedEntry: r.signed_entry ? r.signed_entry.toString('base64') : '',
    createdAt: r.created_at,
  }));

  // ── Witness attestations ───────────────────────────────────────────────
  const witnessRows = await db.all<{
    uuid: string; rotation_log_uuid: string; witness_did_document_uuid: string;
    signature: Buffer; attested_at: number | null;
  }>(`
    SELECT wa.uuid, wa.rotation_log_uuid, wa.witness_did_document_uuid,
           wa.signature, wa.attested_at
    FROM witness_attestations wa
    JOIN rotation_log rl ON rl.uuid = wa.rotation_log_uuid
    JOIN did_documents dd ON dd.uuid = rl.did_document_uuid
    WHERE dd.identity_uuid = ?
  `, identityUuid);

  const witnessAttestations = witnessRows.map(w => ({
    uuid: w.uuid,
    rotationLogUuid: w.rotation_log_uuid,
    witnessDidDocumentUuid: w.witness_did_document_uuid,
    signature: w.signature ? w.signature.toString('base64') : '',
    attestedAt: w.attested_at,
  }));

  // ── Credentials (as subject) ───────────────────────────────────────────
  const credRows = await db.all<{
    uuid: string; vc_type: string; issuer_identity_uuid: string;
    claim: string | null; status: string; valid_from: number;
    valid_until: number | null; created_at: number | null;
  }>(`
    SELECT uuid, vc_type, issuer_identity_uuid, claim, status,
           valid_from, valid_until, created_at
    FROM credentials
    WHERE subject_identity_uuid = ?
    ORDER BY created_at DESC
  `, identityUuid);

  const credentials = credRows.map(c => ({
    uuid: c.uuid,
    vcType: c.vc_type,
    issuerIdentityUuid: c.issuer_identity_uuid,
    claim: c.claim,
    status: c.status,
    validFrom: c.valid_from,
    validUntil: c.valid_until,
    createdAt: c.created_at,
  }));

  // ── Memberships ────────────────────────────────────────────────────────
  const memberRows = await db.all<{
    uuid: string; community_identity_uuid: string; role: string;
    status: string; issued_at: number | null;
  }>(`
    SELECT uuid, community_identity_uuid, role, status, issued_at
    FROM memberships
    WHERE member_identity_uuid = ?
    ORDER BY issued_at DESC
  `, identityUuid);

  const memberships = memberRows.map(m => ({
    uuid: m.uuid,
    communityIdentityUuid: m.community_identity_uuid,
    role: m.role,
    status: m.status,
    issuedAt: m.issued_at,
  }));

  // ── Relationships ──────────────────────────────────────────────────────
  const relRows = await db.all<{
    uuid: string; remote_identity_uuid: string; direction: string;
    status: string; remote_transport: string | null; created_at: number | null;
  }>(`
    SELECT uuid, remote_identity_uuid, direction, status, remote_transport, created_at
    FROM relationships
    WHERE local_identity_uuid = ?
    ORDER BY created_at DESC
  `, identityUuid);

  const relationships = relRows.map(r => ({
    uuid: r.uuid,
    remoteIdentityUuid: r.remote_identity_uuid,
    direction: r.direction,
    status: r.status,
    remoteTransport: r.remote_transport,
    createdAt: r.created_at,
  }));

  return {
    identity: {
      uuid: identity.uuid,
      role: identity.role,
      subjectKind: identity.subjectKind,
      name: identity.name,
      vid: identity.vid,
      // Source the current peer from the ACTIVE peer_endpoints row (the live
      // libp2p node key). The legacy identities.peer_id column (which used to
      // back this field) does not exist in the base schema (0001).
      peerId: await resolveActivePeerId(db, identityUuid, null),
      createdAt: identity.createdAt,
    },
    didDocuments: didDocsOut,
    publicKeys: keysOut,
    rotationLog,
    witnessAttestations,
    credentials,
    memberships,
    relationships,
  };
}