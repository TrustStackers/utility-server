// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * setup-service — business logic for the first-launch configuration wizard.
 *
 * Unlike the crowdfund app (which creates a synthetic VTA + a VTN that is
 * "just a record in the DB"), this service creates a REAL VTN: the founder is a
 * REAL human VTA (role='vta', subject_kind='human', with an active libp2p
 * endpoint) that becomes the VTN's founding_admin, so they can later
 * authenticate and edit configuration. The VTN is created through the shared
 * `createVtc` service (identities + governance + memberships + status_lists) —
 * a first-class governance construct, not a stub row.
 */

import { existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import { setActiveEndpoint } from '@p2p-trust-stack/core/db/repositories/peer-endpoints-repo.js';
import { createRemoteVta } from '@p2p-trust-stack/core/services/vta.js';
import { decryptSecretKey } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
import { exportSeedPhrase } from '@p2p-trust-stack/core/crypto/seed-phrase.js';
import { ScidVhMethod, type ScidVhMethodCreateResult } from '@p2p-trust-stack/core/did/scid-vh-method.js';
import {
  createVtc,
  checkCommunityNameAvailable,
  CreateVtcValidationError,
  CreateVtcConflictError,
  CreateVtcNotFoundError,
} from '../services/vtc.js';
import { setNamespaceConfig, getNamespaceConfig } from '../services/namespace-service.js';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { getVtaPaths, listVtaAgentDirs } from '@p2p-trust-stack/core/platform/p2pts-home.js';

const NAMESPACE_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9.-]*$/;

// ── Founder VTA ────────────────────────────────────────────────────

export interface FounderVtaResult {
  identityUuid: string;
  did: string;
  name: string;
  /** 24-word BIP-39 mnemonic (only when a NEW VTA was created) — the user's
   *  cross-device transfer secret. Absent when registering an existing VTA. */
  mnemonic?: string;
}

/** A VTA found in the agent-app's local P2PTS_HOME/vta SQLite database. */
export interface LocalVta {
  did: string;
  name: string | null;
  subjectKind: string | null;
  vid: string | null;
}

export interface LocalVtaScan {
  /** Whether any per-agent directory under P2PTS_HOME/vta/ exists. */
  localDbExists: boolean;
  /** Local VTAs (role=vta, custody=local) found across the agent directories. */
  vtas: LocalVta[];
}

/**
 * Find the per-agent database under P2PTS_HOME/vta/<agentKey>/ that holds a
 * local VTA with the given DID. Returns the database path, or undefined.
 *
 * Each agent owns its own database (there is no shared one), so locating a VTA
 * by DID means scanning the agent directories.
 */
async function findLocalVtaDbPath(did: string): Promise<string | undefined> {
  for (const agentKey of listVtaAgentDirs()) {
    const dbPath = getVtaPaths(agentKey).dbPath;
    if (!existsSync(dbPath)) continue;
    let ds: SqliteDataSource | null = null;
    try {
      ds = new SqliteDataSource(dbPath);
      const row = await ds.get<{ uuid: string }>(
        `SELECT i.uuid FROM identities i
         JOIN did_documents dd ON dd.identity_uuid = i.uuid AND dd.is_primary = 1
         WHERE dd.did = ? AND i.role = 'vta' AND i.custody = 'local'`,
        did,
      );
      if (row) return dbPath;
    } catch {
      // Unreadable/missing tables → skip this agent directory.
    } finally {
      if (ds) await ds.close();
    }
  }
  return undefined;
}

/**
 * Look for the operator's existing VTAs by scanning the agent-app's per-agent
 * databases under P2PTS_HOME/vta/<agentKey>/. This is the first place to check:
 * the operator has typically already created a VTA via the agent-app. If there
 * are no agent directories, or none hold a local VTA, the wizard forces creation.
 */
export async function listLocalFounderVtas(): Promise<LocalVtaScan> {
  const agentDirs = listVtaAgentDirs();
  if (agentDirs.length === 0) {
    return { localDbExists: false, vtas: [] };
  }

  const vtas: LocalVta[] = [];
  for (const agentKey of agentDirs) {
    const dbPath = getVtaPaths(agentKey).dbPath;
    if (!existsSync(dbPath)) continue;
    let localDs: SqliteDataSource | null = null;
    try {
      localDs = new SqliteDataSource(dbPath);
      const rows = await localDs.all<{
        did: string;
        name: string | null;
        subject_kind: string | null;
        vid: string | null;
      }>(
        `SELECT dd.did, i.name, i.subject_kind, i.vid
         FROM identities i
         JOIN did_documents dd ON dd.identity_uuid = i.uuid AND dd.is_primary = 1
         WHERE i.role = 'vta' AND i.custody = 'local'
         ORDER BY i.created_at ASC`,
      );
      for (const r of rows) {
        vtas.push({ did: r.did, name: r.name, subjectKind: r.subject_kind, vid: r.vid });
      }
    } catch {
      // Tables missing / unreadable → skip this agent directory.
    } finally {
      if (localDs) await localDs.close();
    }
  }
  return { localDbExists: true, vtas };
}

/**
 * Register an EXISTING local VTA (found by `listLocalFounderVtas`) with the
 * utility server so it can become the VTN's founder-admin:
 *   1. Reads its DID document + public Ed25519/X25519 keys from local SQLite.
 *   2. Pushes public data to the utility server DB (custody='remote').
 *   3. Records a bootstrap endpoint (hasAnyEndpoint must pass in createVtc).
 */
export async function registerLocalVtaAsFounder(
  db: DataSource,
  input: { did: string; passphrase: string },
): Promise<FounderVtaResult> {
  if (!input.did?.trim()) throw new CreateVtcValidationError('did is required');
  if (!input.passphrase) throw new CreateVtcValidationError('passphrase is required to unlock your VTA');

  const dbPath = await findLocalVtaDbPath(input.did.trim());
  if (!dbPath) {
    throw new CreateVtcNotFoundError(`No local VTA database was found for ${input.did}. Create a new VTA instead.`);
  }

  let localDs: SqliteDataSource | null = null;
  try {
    localDs = new SqliteDataSource(dbPath);
    const row = await localDs.get<{
      uuid: string; did: string; name: string | null; subject_kind: string | null; document_json: string | null;
    }>(
      `SELECT i.uuid, dd.did, i.name, i.subject_kind, dd.document_json
       FROM identities i
       JOIN did_documents dd ON dd.identity_uuid = i.uuid AND dd.is_primary = 1
       WHERE dd.did = ? AND i.role = 'vta' AND i.custody = 'local'`,
      input.did.trim(),
    );
    if (!row) throw new CreateVtcNotFoundError(`Local VTA ${input.did} not found in the agent database`);
    if (row.subject_kind !== 'human') {
      throw new CreateVtcValidationError(`Founder must be a human VTA (got subject_kind=${row.subject_kind ?? 'null'})`);
    }

    // Public keys + the encrypted Ed25519 secret (used to verify the passphrase).
    const keys = await localDs.all<{
      key_type: string; public_key: Uint8Array;
      encrypted_secret_key: Uint8Array | null; salt: Uint8Array | null; nonce: Uint8Array | null; auth_tag: Uint8Array | null;
    }>(
      `SELECT key_type, public_key, encrypted_secret_key, salt, nonce, auth_tag
       FROM keys WHERE identity_uuid = ? ORDER BY rotation_version DESC`,
      row.uuid,
    );
    const ed = keys.find((k) => k.key_type === 'ed25519');
    const x = keys.find((k) => k.key_type === 'x25519');
    if (!ed || !x) throw new CreateVtcValidationError('Local VTA is missing its published Ed25519/X25519 keys');

    // ── Prove control: the passphrase must decrypt the stored secret key ──
    if (!ed.encrypted_secret_key || !ed.salt || !ed.nonce || !ed.auth_tag) {
      throw new CreateVtcValidationError('Local VTA has no encrypted key to verify the passphrase against');
    }
    try {
      await decryptSecretKey({
        ciphertext: ed.encrypted_secret_key, nonce: ed.nonce, authTag: ed.auth_tag, salt: ed.salt,
      }, input.passphrase);
    } catch {
      throw new CreateVtcValidationError('Incorrect passphrase for that VTA');
    }

    // ── The founder's REAL agent endpoint (recorded by the Agent App on login) ──
    const ep = await localDs.get<{ peer_id: string; multiaddrs: string | null }>(
      `SELECT peer_id, multiaddrs FROM peer_endpoints
       WHERE identity_uuid = ? AND is_active = 1
       ORDER BY updated_at DESC, created_at DESC LIMIT 1`,
      row.uuid,
    );
    if (!ep) {
      throw new CreateVtcValidationError('That VTA has no recorded peer endpoint. Run the Agent App with it once, then retry.');
    }

    let didDocument: object;
    if (row.document_json) {
      try { didDocument = JSON.parse(row.document_json) as object; } catch { didDocument = { id: row.did }; }
    } else {
      didDocument = { id: row.did };
    }

    const remote = await createRemoteVta(db, {
      realDid: row.did,
      name: row.name ?? input.did,
      subjectKind: 'human',
      didDocument,
      publicKeys: {
        ed25519: Buffer.from(ed.public_key).toString('base64'),
        x25519: Buffer.from(x.public_key).toString('base64'),
      },
      peerId: ep.peer_id,
    });

    let multiaddrs: string[] | undefined;
    if (ep.multiaddrs) {
      try { multiaddrs = JSON.parse(ep.multiaddrs) as string[]; } catch { /* ignore malformed */ }
    }
    await setActiveEndpoint(db, { identityUuid: remote.identity.uuid, peerId: ep.peer_id, multiaddrs });

    return { identityUuid: remote.identity.uuid, did: row.did, name: row.name ?? input.did };
  } finally {
    if (localDs) await localDs.close();
  }
}

/**
 * Create a NEW founder VTA the same way the agent-app does, then register it
 * with this utility server so it can become founder-admin.
 *
 *  1. Writes the VTA into the local P2PTS_HOME/vta SQLite + keystore (identical
 *     tables the agent-app would create — shared schema, encrypted keys).
 *  2. Pushes its public DID document + keys to the utility server's DB
 *     (custody='remote', no secrets held by the server).
 *  3. Records an active endpoint so the founder passes the "real VTA" check.
 */
export async function createFounderVta(
  db: DataSource,
  input: { name: string; passphrase: string },
): Promise<FounderVtaResult> {
  if (!input.name?.trim()) throw new CreateVtcValidationError('Name is required');
  if (!input.passphrase || input.passphrase.length < 8) {
    throw new CreateVtcValidationError('Passphrase must be at least 8 characters');
  }

  // A newly created VTA has no agent running yet, so use a unique placeholder
  // peer ID. The agent app replaces it with the real peer ID once the operator
  // runs it and it connects (setActiveEndpoint retires this).
  const peerId = `bootstrap-${randomBytes(16).toString('hex')}`;

  // Generate a fresh did:scid:vh identity (VTAs are ALWAYS did:scid:vh) in
  // memory. No local SQLite DB or keystore is created on the utility server —
  // the VTA's home is the operator's agent device; the server holds only the
  // public (custody='remote') copy, and the private key is handed to the
  // operator as a seed phrase below.
  const scidVhMethod = new ScidVhMethod({ store: undefined });
  const identitySeed = new Uint8Array(randomBytes(32));
  // No transport in the genesis document: the service endpoint is added later
  // by the agent when it boots. This keeps the DID deterministic from the seed
  // (transport is NOT part of the SCID), so the same seed phrase reproduces the
  // same DID on import.
  const result = (await scidVhMethod.create(
    undefined,
    { identitySeed },
  )) as ScidVhMethodCreateResult;

  // Register the public identity on the server (custody='remote').
  const remote = await createRemoteVta(db, {
    realDid: result.did,
    name: input.name.trim(),
    subjectKind: 'human',
    didDocument: result.document,
    publicKeys: {
      ed25519: Buffer.from(result.signingKeyPair.publicKey).toString('base64'),
      x25519: Buffer.from(result.agreementKeyPair.publicKey).toString('base64'),
    },
    peerId,
  });
  await setActiveEndpoint(db, { identityUuid: remote.identity.uuid, peerId });

  // The seed phrase is the operator's cross-device transfer secret: import it
  // on the agent app to take ownership of this VTA.
  const mnemonic = exportSeedPhrase(result.signingKeyPair).mnemonic;

  return { identityUuid: remote.identity.uuid, did: result.did, name: input.name.trim(), mnemonic };
}


// ── VTN creation / selection ──────────────────────────────────────

export interface NamespaceVtnResult {
  vtnUuid: string;
  vtnDid: string;
  name: string;
  namespace: string;
}

function validateNamespace(namespace: string): void {
  if (!namespace?.trim()) throw new CreateVtcValidationError('namespace is required');
  const ns = namespace.trim();
  if (!NAMESPACE_REGEX.test(ns)) {
    throw new CreateVtcValidationError(
      'Invalid namespace: must be dot-separated alphanumeric segments (e.g. "p2pts.mainnet")',
    );
  }
}

/**
 * Create a REAL namespace VTN with the founder as its sole founding_admin, and
 * bind the namespace string to it for agent name registration.
 */
export async function createNamespaceVtn(
  db: DataSource,
  input: { name: string; namespace: string; founderUuid: string },
): Promise<NamespaceVtnResult> {
  if (!input.name?.trim()) throw new CreateVtcValidationError('VTN name is required');
  validateNamespace(input.namespace);

  const name = input.name.trim();
  const namespace = input.namespace.trim();

  // Namespace must be unique across the network (UNIQUE(namespace) guard).
  const existing = await getNamespaceConfig(db);
  if (existing) {
    throw new CreateVtcConflictError(
      `A namespace is already configured (${existing.namespace}). ` +
      'This server currently serves one namespace at a time.',
    );
  }

  // Delegate all governance construction to the shared service — this is the
  // "real VTN" path (identities + governance + memberships + status_lists),
  // which also re-validates the founder is a real human VTA with an endpoint.
  const result = await createVtc(db, {
    name,
    kind: 'vtn',
    adminIdentityUuids: [input.founderUuid],
    threshold: 1,
  });

  await setNamespaceConfig(db, {
    vtnIdentityUuid: result.identity.uuid,
    namespace,
  });

  return {
    vtnUuid: result.identity.uuid,
    vtnDid: result.identity.did ?? '',
    name: result.identity.name ?? name,
    namespace,
  };
}

/**
 * Join / select an EXISTING VTN. Deliberately stubbed for the first pass —
 * full multi-signature join is governed by the external VTN's own ceremony.
 * The default (create-new-VTN) path above is fully enabled.
 */
export async function selectExternalVtn(
  _db: DataSource,
  _vtnDid: string,
): Promise<{ stub: true; message: string }> {
  return {
    stub: true,
    message:
      'Joining an existing VTN is not yet implemented. ' +
      'Create a new VTN to continue (default).',
  };
}

/** Pre-flight name availability check (delegated to the shared service). */
export async function checkVtnNameAvailable(db: DataSource, name: string) {
  return checkCommunityNameAvailable(db, name);
}
