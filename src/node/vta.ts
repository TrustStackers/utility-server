/**
 * This server's own VTA identity.
 *
 * On first boot, creates a did:scid:vh identity for the utility server itself,
 * persists it into `identities` (uuid=UUIDv5, custody='local') and
 * `did_documents` (did=real DID), stores rotation log entries in the
 * `rotation_log` table, and encrypts/stores its key material.
 * On subsequent boots, loads the existing identity.
 *
 * ## Slot-A decoupling (ToIP)
 *
 * The server's permanent TSP VID key and its did:scid:vh identity key are
 * UNRELATED, both derived from separate seeds in config.json:
 *   - identity.didSeedHex    → the did:scid:vh identity (chain) key
 *   - identity.tspVidSeedHex → the permanent TSP VID key (never rotates)
 *
 * The DID document keeps the TSP VID key at verificationMethod[0] (`#key-1`,
 * what the TSP handshake verifies against) and the did:scid:vh identity key at
 * a second verification method (`#key-scid`, what the did:scid:vh chain
 * follows). A future log roll of the identity key therefore never changes the
 * transport VID — per ToIP, the VID is a persistent session pointer.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { Libp2p } from 'libp2p';
import { ScidVhMethod } from '@p2p-trust-stack/core/did/scid-vh-method.js';
import { encryptSecretKey } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
import { generateMlDsa65KeyPair, generateMlKem768X25519KeyPair } from '@p2p-trust-stack/core/crypto/pqc.js';
import { extractMlDsa65PublicKey } from '@p2p-trust-stack/core/relationship/key-extract.js';
import type { DidDocument } from '@p2p-trust-stack/core/did/types.js';
import {
  generateEd25519KeyPairFromSeed,
  ed25519ToX25519,
  type Ed25519KeyPair,
  type X25519KeyPair,
} from '@p2p-trust-stack/core/crypto/primitives.js';
import { cesrEncode, CESR_CODES } from '@p2p-trust-stack/core/crypto/cesr.js';
import { didToUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as keysRepo from '@p2p-trust-stack/core/db/repositories/keys-repo.js';
import { setActiveEndpoint } from '@p2p-trust-stack/core/db/repositories/peer-endpoints-repo.js';
import { YugabyteRotationLogStore } from '../db/yugabyte-rotation-log-store.js';

const DEV_PASSPHRASE = process.env.NODE_PASSPHRASE ?? 'dev-only-insecure-passphrase';

export interface ServerVtaIdentity {
  identityUuid: string;
  realDid: string;
  didDocumentUuid: string | null;
}

export interface ServerVtaKeys {
  /** Permanent TSP VID (CESR-encoded Ed25519 of the TSP key). */
  tspVid: string;
  /** Permanent TSP signing key pair (from tspVidSeedHex). */
  tspSigningKeyPair: Ed25519KeyPair;
  /** X25519 agreement derived from the TSP signing key. */
  tspAgreementKeyPair: X25519KeyPair;
}

export type ServerVta = ServerVtaIdentity & Partial<ServerVtaKeys>;

/**
 * Encrypt and store one post-quantum key pair.
 *
 * The DB `keys` rows are this server's store of record — it never writes a
 * keystore file — and boot loads the PQ pair from here to build its runtime
 * identity (see `tryLoadSecretKeyPair` in index.ts).
 */
async function persistPqcPair(
  db: DataSource,
  identityUuid: string,
  didDocumentUuid: string,
  keyType: 'ml_dsa_65' | 'mlkem768_x25519',
  pair: { publicKey: Uint8Array; secretKey: Uint8Array },
): Promise<void> {
  const enc = await encryptSecretKey(pair.secretKey, DEV_PASSPHRASE);
  await keysRepo.createWithSecret(db, {
    identityUuid,
    didDocumentUuid,
    keyType,
    publicKey: pair.publicKey,
    encryptedSecretKey: enc.ciphertext,
    salt: enc.salt,
    nonce: enc.nonce,
    authTag: enc.authTag,
  });
}

/** Does a stored document already publish an ML-DSA-65 key? */
function documentPublishesMlDsa(documentJson: string | null | undefined): boolean {
  if (!documentJson) return false;
  try {
    return !!extractMlDsa65PublicKey(JSON.parse(documentJson) as DidDocument);
  } catch {
    return false;
  }
}

/**
 * Load this server's own VTA identity from the database, creating it on first boot.
 *
 * @param seeds Optional hex seeds for the did:scid:vh identity key and the
 *   permanent TSP VID key (from config.json `identity`). When provided, both
 *   keys are derived deterministically (Slot-A). When omitted, the legacy
 *   random single-key path is used.
 */
export async function ensureServerVta(
  db: DataSource,
  node: Libp2p,
  nodeName: string,
  nodeId: string,
  seeds?: { didSeedHex?: string; tspVidSeedHex?: string },
): Promise<ServerVta> {
  const existing = (await identitiesRepo.findByRole(db, 'vta')).find(
    (i: { name: string | null }) => i.name === nodeName,
  );

  if (existing) {
    const primaryDoc = await didDocumentsRepo.findPrimaryForIdentity(db, existing.uuid);
    if (primaryDoc) {
      // Record the server's CURRENT node peer as its active endpoint on every
      // boot. The server's libp2p node key can change across restarts (unless
      // LIBP2P_SEED is set); keeping the endpoint current prevents agents that
      // dial this identity via peer_endpoints from targeting a stale peer.
      await setActiveEndpoint(db, {
        identityUuid: existing.uuid,
        peerId: node.peerId.toString(),
        multiaddrs: node.getMultiaddrs().map(a => a.toString()),
        recordedByNode: nodeId,
      });

      // Slot-A: derive the permanent TSP keypair from the seed (if configured).
      const tspKeys = deriveTspKeys(seeds?.tspVidSeedHex);

      // Publish/refresh the OPERATION-SIGNING VID (F-010 / R1). The server signs its
      // operation proofs with the PERMANENT TSP key (`vta.tspVid`), not with its identity
      // key — so a peer can never derive it and has to be told. `identities.vid` is where;
      // without it every peer can only report the sender binding `indeterminate`.
      if (tspKeys?.tspVid && existing.vid !== tspKeys.tspVid) {
        await db.run('UPDATE identities SET vid = ? WHERE uuid = ?', tspKeys.tspVid, existing.uuid);
        console.log(
          `[utility-server] published operation VID ${tspKeys.tspVid.slice(0, 12)}… for ${existing.name}`,
        );
      }

      // ── Backfill the post-quantum roots of trust (H4 upstream) ────────────
      // An identity created before `persistPqcPair` existed holds no ML-DSA/KEM
      // secret, so boot loads none, the document publishes neither
      // #key-mldsa nor #key-kem, and hybrid-confidential traffic plus OOBI
      // signatures are impossible. Generating a pair here is PURELY ADDITIVE
      // when the stored document publishes no ML-DSA key — which the guard below
      // requires, because inventing a key for an identity whose document already
      // names someone else's would invalidate theirs.
      const existingKeys = await keysRepo.findByIdentityUuid(db, existing.uuid);
      const hasPqcSecret = (t: 'ml_dsa_65' | 'mlkem768_x25519') =>
        existingKeys.some((k) => k.keyType === t && !!k.encryptedSecretKey);
      if (!hasPqcSecret('ml_dsa_65') || !hasPqcSecret('mlkem768_x25519')) {
        if (existing.custody !== 'local') {
          console.warn(
            `[utility-server] identity ${existing.name} (custody=${existing.custody}) has no PQ keys, ` +
            `and this server does not own its identity key — generating none, because the document ` +
            `for that DID is authoritative elsewhere`,
          );
        } else if (documentPublishesMlDsa(primaryDoc.documentJson)) {
          console.warn(
            `[utility-server] identity ${existing.name} PUBLISHES #key-mldsa but this server holds no ` +
            `ML-DSA secret for it. This is the state of every identity created before PQ keys were ` +
            `persisted, and it is NOT repaired automatically: generating a new pair would publish a ` +
            `different key than the did:scid:vh log entry names, so the identity's own signatures ` +
            `would stop verifying for a log-anchored resolver. Consequently this server cannot ` +
            `ML-DSA-sign an OOBI introduction and cannot open hybrid-confidential traffic. ` +
            `Remedy: re-provision the identity (dev), or add PQ keys through a rotation (production).`,
          );
        } else {
          await persistPqcPair(db, existing.uuid, primaryDoc.uuid, 'ml_dsa_65', generateMlDsa65KeyPair());
          await persistPqcPair(db, existing.uuid, primaryDoc.uuid, 'mlkem768_x25519', generateMlKem768X25519KeyPair());
          console.log(
            `[utility-server] backfilled PQ roots of trust for ${existing.name} — nothing was published ` +
            `for this identity before, so peers see only additive change`,
          );
        }
      }

      return {
        identityUuid: existing.uuid,
        realDid: primaryDoc.did,
        didDocumentUuid: primaryDoc.uuid,
        ...(tspKeys ?? {}),
      };
    }
    // Orphaned identity from a failed previous startup — clean up and recreate.
    console.warn(`[utility-server] Cleaning up orphaned identity ${existing.name} (uuid=${existing.uuid})`);
    await db.run('DELETE FROM identities WHERE uuid = ?', existing.uuid);
  }

  // ── Create a new did:scid:vh identity (Slot-A when seeds are provided) ──
  const transport = {
    peerId: node.peerId.toString(),
    multiaddrs: node.getMultiaddrs().map(a => a.toString()),
  };

  const tspKeys = deriveTspKeys(seeds?.tspVidSeedHex);
  const identitySeed = seeds?.didSeedHex
    ? hexToBytes(seeds.didSeedHex)
    : undefined;

  const method = new ScidVhMethod();
  const result = await method.create(transport, {
    identitySeed,
    ...(tspKeys ? { transportSigningKeyPair: tspKeys.tspSigningKeyPair } : {}),
  });
  const identityUuid = didToUuid(result.did);

  // 1. identities row — uuid is UUIDv5 (deterministic identity key)
  await identitiesRepo.create(db, {
    uuid: identityUuid,
    realDid: result.did,
    role: 'vta',
    subjectKind: 'organization',
    custody: 'local',
    name: nodeName,
    peerId: node.peerId.toString(),
    // `identities.vid` records the VID this identity signs OPERATION PROOFS with. For the
    // server that is the permanent TSP key (Slot-A), which no peer can derive from the
    // identity key — so it is published here for peers to bind our proofs (F-010 / R1).
    vid: tspKeys?.tspVid,
    recordedByNode: nodeId,
  });

  // 2. did_documents row — did is the actual did:scid:vh string
  const didDocumentUuid = await didDocumentsRepo.create(db, {
    identityUuid,
    did: result.did,
    method: 'did:scid:vh',
    documentJson: JSON.stringify(result.document),
    isPrimary: true,
    recordedByNode: nodeId,
  });

  // 3. Persist rotation log entries in YugabyteDB
  const logStore = new YugabyteRotationLogStore(db);
  for (const entry of result.log) {
    await logStore.appendEntry(didDocumentUuid, entry);
  }

  // 4. Encrypt and store keys
  const edEncrypted = await encryptSecretKey(result.signingKeyPair.secretKey, DEV_PASSPHRASE);
  await keysRepo.createWithSecret(db, {
    identityUuid,
    didDocumentUuid,
    keyType: 'ed25519',
    publicKey: result.signingKeyPair.publicKey,
    encryptedSecretKey: edEncrypted.ciphertext,
    salt: edEncrypted.salt,
    nonce: edEncrypted.nonce,
    authTag: edEncrypted.authTag,
  });

  const xEncrypted = await encryptSecretKey(result.agreementKeyPair.secretKey, DEV_PASSPHRASE);
  await keysRepo.createWithSecret(db, {
    identityUuid,
    didDocumentUuid,
    keyType: 'x25519',
    publicKey: result.agreementKeyPair.publicKey,
    encryptedSecretKey: xEncrypted.ciphertext,
    salt: xEncrypted.salt,
    nonce: xEncrypted.nonce,
    authTag: xEncrypted.authTag,
  });

  // 5. Post-quantum roots of trust. `ScidVhMethod.create()` GENERATES these and
  //    this function used to drop them on the floor: the server then published no
  //    #key-mldsa/#key-kem (so agents stayed classical and could not verify its
  //    introductions) while the pair itself existed nowhere.
  if (result.mlDsa65KeyPair) {
    await persistPqcPair(db, identityUuid, didDocumentUuid, 'ml_dsa_65', result.mlDsa65KeyPair);
  }
  if (result.hybridKemKeyPair) {
    await persistPqcPair(db, identityUuid, didDocumentUuid, 'mlkem768_x25519', result.hybridKemKeyPair);
  }
  if (result.mlDsa65KeyPair && result.hybridKemKeyPair) {
    console.log('[utility-server] server PQ roots of trust persisted (#key-mldsa, #key-kem)');
  } else {
    console.warn(
      '[utility-server] this DID method produced no post-quantum key pair — ' +
      'the server will publish no #key-mldsa/#key-kem and its OOBIs cannot be ML-DSA-signed',
    );
  }

  return {
    identityUuid,
    realDid: result.did,
    didDocumentUuid,
    ...(tspKeys ?? {}),
  };
}

/**
 * Derive the server's PERMANENT TSP signing key + agreement key from the
 * `tspVidSeedHex` seed. Returns undefined when the seed is absent (legacy mode).
 */
function deriveTspKeys(tspVidSeedHex?: string): ServerVtaKeys | undefined {
  if (!tspVidSeedHex) return undefined;
  const tspSigningKeyPair = generateEd25519KeyPairFromSeed(hexToBytes(tspVidSeedHex));
  const tspAgreementKeyPair = ed25519ToX25519(tspSigningKeyPair.secretKey);
  return {
    tspVid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, tspSigningKeyPair.publicKey),
    tspSigningKeyPair,
    tspAgreementKeyPair,
  };
}

/** Convert a hex string to a Uint8Array. */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}