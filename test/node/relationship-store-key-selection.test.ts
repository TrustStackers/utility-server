/**
 * Regression tests for the utility server's verification-key selection.
 *
 * `DsRelationshipStore.get()` resolves the peer's Ed25519 key with:
 *
 *   LEFT JOIN keys ked ON ked.identity_uuid = ri.uuid
 *                     AND ked.key_type = 'ed25519' AND ked.rotation_version = 0
 *
 * That join produced MORE THAN ONE row whenever an identity had two active
 * ed25519 keys — which the handshake could create, because the keys UNIQUE tuple
 * includes `did_document_uuid`: the handshake wrote the key extracted from the
 * document IT upserted (a non-primary stub row) while identity_push wrote the
 * primary document's uuid. With no ORDER BY, the driver returned one of them
 * arbitrarily, so the server sometimes verified TSP signatures with a key the
 * agent does not sign with → `tspOpen: signature verification failed` on every
 * message from that agent, with no deterministic pattern.
 *
 * The write side now converges to a single active row
 * (src/services/vta.ts syncRemotePublicKeys). This test pins the READ side:
 * deterministic, preferring the key linked to the peer's primary document, and
 * still falling back to any active key so a peer is never left keyless.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs --test test/node/relationship-store-key-selection.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as keysRepo from '@p2p-trust-stack/core/db/repositories/keys-repo.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import {
  DsIdentityResolver,
  DsRelationshipStore,
} from '../../src/node/relationship-store-ds.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

const LOCAL_DID = 'did:scid:vh:1:zLocalServer';
const REMOTE_DID = 'did:scid:vh:1:zRemoteAgent';
const REMOTE_OTHER_DID = 'did:peer:4zRemoteLegacyDoc';

const KEY_PRIMARY = Buffer.from(new Uint8Array(32).fill(0xa1));
const KEY_OTHER = Buffer.from(new Uint8Array(32).fill(0xb2));

function makeDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

/**
 * Build: a local identity, a remote identity with a PRIMARY document and a second
 * (non-primary) document, two active ed25519 keys (one per document), and a
 * bidirectional relationship row between them.
 */
async function seed(ds: SqliteDataSource) {
  const localUuid = await identitiesRepo.create(ds, {
    realDid: LOCAL_DID, role: 'vta', subjectKind: 'organization', custody: 'local', name: 'server',
  });
  const remoteUuid = await identitiesRepo.create(ds, {
    realDid: REMOTE_DID, role: 'vta', subjectKind: 'human', custody: 'remote', name: 'alice',
  });

  await didDocumentsRepo.create(ds, {
    identityUuid: localUuid, did: LOCAL_DID, method: 'did:scid:vh',
    documentJson: JSON.stringify({ id: LOCAL_DID }), isPrimary: true,
  });
  const primaryDoc = await didDocumentsRepo.create(ds, {
    identityUuid: remoteUuid, did: REMOTE_DID, method: 'did:scid:vh',
    documentJson: JSON.stringify({ id: REMOTE_DID }), isPrimary: true,
  });
  const otherDoc = await didDocumentsRepo.create(ds, {
    identityUuid: remoteUuid, did: REMOTE_OTHER_DID, method: 'did:peer:4',
    documentJson: JSON.stringify({ id: REMOTE_OTHER_DID }), isPrimary: false,
  });

  // NOTE the insertion order: the NON-primary key is written FIRST, so a join
  // without an ORDER BY returns THAT one (rowid order). Inserted the other way
  // round the test would pass even with the bug present.
  await keysRepo.create(ds, {
    identityUuid: remoteUuid, didDocumentUuid: otherDoc, keyType: 'ed25519',
    publicKey: KEY_OTHER, recordedByNode: 'tsp-bridge',
  });
  const primaryKeyUuid = await keysRepo.create(ds, {
    identityUuid: remoteUuid, didDocumentUuid: primaryDoc, keyType: 'ed25519',
    publicKey: KEY_PRIMARY, recordedByNode: 'agent-push',
  });

  await ds.run(
    `INSERT INTO relationships
       (uuid, local_identity_uuid, remote_identity_uuid, direction, status, created_at, updated_at)
     VALUES (?, ?, ?, 'bidirectional', 'established', 0, 0)`,
    generateUuid(), localUuid, remoteUuid,
  );

  return { remoteUuid, primaryKeyUuid };
}

test('DsRelationshipStore.get: prefers the key linked to the peer PRIMARY document', async () => {
  const ds = makeDb();
  const { remoteUuid } = await seed(ds);
  const store = new DsRelationshipStore(ds, new DsIdentityResolver(ds));

  // Sanity: the seeded state really does have two active ed25519 rows — i.e. the
  // ambiguous join this test exists for.
  const rows = await ds.all<{ uuid: string }>(
    `SELECT uuid FROM keys WHERE identity_uuid = ? AND key_type = 'ed25519' AND rotation_version = 0`,
    remoteUuid,
  );
  assert.equal(rows.length, 2, 'precondition: two active ed25519 keys exist');

  const record = await store.get(LOCAL_DID, REMOTE_DID);
  assert.ok(record, 'the relationship must resolve');
  assert.ok(record!.remoteEd25519Key, 'a verification key must be returned');
  assert.equal(
    b64(record!.remoteEd25519Key!), b64(KEY_PRIMARY),
    'the PRIMARY-document key must win, deterministically',
  );

  await ds.close();
});

test('DsRelationshipStore.get: still falls back to any active key (never keyless)', async () => {
  const ds = makeDb();
  const { primaryKeyUuid } = await seed(ds);

  // Drop the primary-linked key, leaving only the non-primary one.
  await ds.run('DELETE FROM keys WHERE uuid = ?', primaryKeyUuid);

  const store = new DsRelationshipStore(ds, new DsIdentityResolver(ds));
  const record = await store.get(LOCAL_DID, REMOTE_DID);
  assert.ok(record?.remoteEd25519Key, 'a peer with only a stub-linked key must still be verifiable');
  assert.equal(b64(record!.remoteEd25519Key!), b64(KEY_OTHER));

  await ds.close();
});
