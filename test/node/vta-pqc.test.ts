/**
 * PQC provisioning for the utility server's OWN identity (H4, upstream half).
 *
 * `ScidVhMethod.create()` always GENERATES an ML-DSA-65 + MLKEM768-X25519 pair,
 * but `ensureServerVta` used to drop them: it persisted only ed25519/x25519. The
 * consequences were invisible but real —
 *
 *   - boot's `tryLoadSecretKeyPair` found no `ml_dsa_65` / `mlkem768_x25519` row,
 *     so the server published no `#key-mldsa` / `#key-kem`;
 *   - agents therefore stayed classical on confidential traffic to the server;
 *   - the server could not ML-DSA-sign an OOBI introduction (no PQ key to sign
 *     with), so an `enforce` agent could never accept its introduction;
 *   - the generated pair existed nowhere at all, not even on disk.
 *
 * These tests pin the persistence AND the guards around the backfill, because
 * inventing a key for an identity whose document is authoritative elsewhere
 * would invalidate someone else's published key.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs --test test/node/vta-pqc.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as keysRepo from '@p2p-trust-stack/core/db/repositories/keys-repo.js';
import { ensureServerVta } from '../../src/node/vta.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

/** The minimum of a libp2p node that ensureServerVta touches. */
function stubNode(peerId = '12D3KooWTestNode') {
  return {
    peerId: { toString: () => peerId },
    getMultiaddrs: () => [] as unknown[],
  } as unknown as Parameters<typeof ensureServerVta>[1];
}

function makeDb() {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

/** Which PQ key types this identity holds a usable (secret-bearing) row for. */
async function pqSecrets(ds: SqliteDataSource, identityUuid: string): Promise<string[]> {
  const rows = await keysRepo.findByIdentityUuid(ds, identityUuid);
  return rows
    .filter((r) => (r.keyType === 'ml_dsa_65' || r.keyType === 'mlkem768_x25519') && !!r.encryptedSecretKey)
    .map((r) => r.keyType);
}

// ---------------------------------------------------------------------------
// Create path: the generated PQ pair must survive
// ---------------------------------------------------------------------------

test('ensureServerVta: a NEW server identity persists both PQ keys WITH secrets', async () => {
  const ds = makeDb();
  const vta = await ensureServerVta(ds, stubNode(), 'test-node', 'node-1');

  const types = (await pqSecrets(ds, vta.identityUuid)).sort();
  assert.deepEqual(
    types,
    ['ml_dsa_65', 'mlkem768_x25519'],
    'boot can only load (and the document can only publish) PQ keys that were persisted here',
  );
});

// ---------------------------------------------------------------------------
// Existing path: backfill, but only where this server is authoritative
// ---------------------------------------------------------------------------

test('ensureServerVta: backfills PQ keys for a local identity whose document publishes none', async () => {
  const ds = makeDb();
  const uuid = '00000000-0000-4000-8000-00000000ab01';
  const did = 'did:scid:vh:1:zLocalNoPqKey';
  await identitiesRepo.create(ds, {
    uuid, realDid: did, role: 'vta', subjectKind: 'organization', custody: 'local',
    name: 'test-node', recordedByNode: 'setup',
  });
  await didDocumentsRepo.create(ds, {
    identityUuid: uuid, did, method: 'did:scid:vh',
    documentJson: JSON.stringify({ id: did }), isPrimary: true, recordedByNode: 'setup',
  });

  const vta = await ensureServerVta(ds, stubNode(), 'test-node', 'node-1');
  assert.equal(vta.identityUuid, uuid, 'the existing identity is reused');
  assert.deepEqual(
    (await pqSecrets(ds, uuid)).sort(),
    ['ml_dsa_65', 'mlkem768_x25519'],
    'nothing was published for this identity, so persisting a pair is purely additive',
  );
});

test('ensureServerVta: does NOT replace a published PQ key whose secret it lacks', async () => {
  const ds = makeDb();
  // This is the state EVERY pre-existing install is in: `ScidVhMethod.create()`
  // built the stored document WITH #key-mldsa/#key-kem, but the secret was never
  // persisted. Deleting the key rows reproduces it exactly.
  const first = await ensureServerVta(ds, stubNode(), 'test-node', 'node-1');
  const db = ds.getRawDb();
  db.prepare(`DELETE FROM keys WHERE identity_uuid = ? AND key_type IN ('ml_dsa_65','mlkem768_x25519')`)
    .run(first.identityUuid);

  await ensureServerVta(ds, stubNode(), 'test-node', 'node-1');

  // Generating a fresh pair here would publish a DIFFERENT ML-DSA key than the
  // did:scid:vh log entry names — and the log is what a log-anchored verifier
  // checks, so the identity's own signatures would stop verifying. The server
  // must report this state, never silently re-key the identity.
  assert.deepEqual(
    await pqSecrets(ds, first.identityUuid),
    [],
    'a published-but-unheld PQ key must be reported, not replaced',
  );
});


test('ensureServerVta: does NOT invent PQ keys for a REMOTE-custody identity', async () => {
  const ds = makeDb();
  // A VTA this server did not create (the "utility server operated from an
  // agent's did:scid:vh" case): its document and keys are authoritative on the
  // agent, so publishing a server-generated #key-mldsa here would contradict a
  // key the agent already publishes.
  const uuid = '00000000-0000-4000-8000-00000000abcd';
  const did = 'did:scid:vh:1:zRemoteClaimed';
  await identitiesRepo.create(ds, {
    uuid, realDid: did, role: 'vta', subjectKind: 'human', custody: 'remote',
    name: 'test-node', recordedByNode: 'setup',
  });
  await didDocumentsRepo.create(ds, {
    identityUuid: uuid, did, method: 'did:scid:vh',
    documentJson: JSON.stringify({ id: did }), isPrimary: true, recordedByNode: 'setup',
  });

  const vta = await ensureServerVta(ds, stubNode(), 'test-node', 'node-1');
  assert.equal(vta.identityUuid, uuid, 'the existing identity is reused');
  assert.deepEqual(
    await pqSecrets(ds, uuid),
    [],
    'a remote-custody identity must be left alone — its document is authoritative elsewhere',
  );
});

