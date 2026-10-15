/**
 * Regression tests for the keys-table write path used by concurrent
 * identity_push transactions.
 *
 * Reproduced bug: two overlapping identity_push 2PC transactions (agent99 and
 * G7WIN11 logging in/out/operating) both archive the same co-admin identity and
 * race on the keys unique constraint:
 *   keys_identity_id_did_document_id_key_type_rotation_version_key
 * The old syncRemotePublicKeys() did a SELECT-then-INSERT; under YugabyteDB
 * READ COMMITTED both sides saw "absent", the loser INSERT raised a
 * duplicate-key violation, and prepare() voted 'no', aborting the whole
 * transaction (see the utility terminal log: `[identity-push-participant]
 * prepare failed for tx ... duplicate key value violates unique constraint`).
 *
 * The fix replaces check-then-insert with an atomic
 *   INSERT ... ON CONFLICT (identity_id, did_document_id, key_type, rotation_version)
 *   DO UPDATE SET ... upsert, so the unique constraint merges instead of aborting.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs --test test/db/keys-upsert.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as keysRepo from '@p2p-trust-stack/core/db/repositories/keys-repo.js';
import { createRemoteVta } from '@p2p-trust-stack/core/services/vta.js';
import { DsIdentityResolver } from '../../src/node/relationship-store-ds.js';
import { buildDidPeer4Document } from '@p2p-trust-stack/core/did/create.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

function makeDb() {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

const KEY_A = b64(new Uint8Array(32).fill(0xaa));
const KEY_B = b64(new Uint8Array(32).fill(0xbb));

function pushInput(realDid: string, publicKeys: { ed25519: string; x25519: string }) {
  return {
    realDid,
    uuid: `00000000-0000-4000-8000-${realDid.slice(-12).padStart(12, '0')}`,
    name: `Name-${realDid.slice(-4)}`,
    subjectKind: 'human' as const,
    didDocument: { id: realDid, hello: 'world' },
    publicKeys,
    recordedByNode: 'agent-push',
  };
}

test('identity_push: repeated push of the same identity converges, never duplicates keys', async () => {
  const ds = makeDb();
  const realDid = 'did:scid:vh:1:zTestIssue1';
  const first = await createRemoteVta(ds, pushInput(realDid, { ed25519: KEY_A, x25519: KEY_A }));
  const identityUuid = first.identity.uuid;

  let rows = await ds.all<{ key_type: string; public_key: Buffer | Uint8Array }>(
    'SELECT key_type, public_key FROM keys WHERE identity_uuid = ? ORDER BY key_type',
    identityUuid,
  );
  assert.strictEqual(rows.length, 2, 'new identity should create exactly one ed25519 + one x25519 key row');

  // Second (existing-identity) push with rotated key material → the upsert must
  // UPDATE in place, not insert a second row on the same unique tuple.
  const second = await createRemoteVta(ds, pushInput(realDid, { ed25519: KEY_B, x25519: KEY_A }));
  assert.strictEqual(second.identity.uuid, first.identity.uuid);

  rows = await ds.all<{ key_type: string; public_key: Buffer | Uint8Array }>(
    'SELECT key_type, public_key FROM keys WHERE identity_uuid = ? ORDER BY key_type',
    identityUuid,
  );
  assert.strictEqual(rows.length, 2, 'key rows must stay merged after a rotated re-push');
  const ed = rows.find((r) => r.key_type === 'ed25519')!;
  assert.ok(
    ed.public_key instanceof Uint8Array
      ? Buffer.from(ed.public_key as Uint8Array).toString('base64') === KEY_B
      : (ed.public_key as Buffer).toString('base64') === KEY_B,
    'ed25519 public key should be overwritten by the authoritative live key',
  );
  await ds.close();
});

test('identity_push: concurrent overlapping pushes of the same identity do not abort (ON CONFLICT merge)', async () => {
  const ds = makeDb();
  const realDid = 'did:scid:vh:1:zTestIssue2';
  // Seed the identity first so both "pushes" exercise the existing-identity
  // syncRemotePublicKeys upsert path — the exact path that raised the
  // duplicate-key violation in the utility terminal log.
  const seeded = await createRemoteVta(ds, pushInput(realDid, { ed25519: KEY_A, x25519: KEY_A }));
  const identityUuid = seeded.identity.uuid;

  // Both pushes run interleaved on the same identity; whichever lands last
  // overwrites the key. Nothing may throw a duplicate-key violation.
  await Promise.all([
    createRemoteVta(ds, pushInput(realDid, { ed25519: KEY_B, x25519: KEY_A })),
    createRemoteVta(ds, pushInput(realDid, { ed25519: KEY_A, x25519: KEY_B })),
    createRemoteVta(ds, pushInput(realDid, { ed25519: KEY_B, x25519: KEY_B })),
  ]);

  const rows = await ds.all<{ key_type: string }>(
    'SELECT key_type FROM keys WHERE identity_uuid = ? ORDER BY key_type',
    identityUuid,
  );
  assert.strictEqual(rows.length, 2, 'concurrent pushes must converge to a single key row per type');
  await ds.close();
});

test('createRemoteVta: brand-new identity creation is atomic under a transaction', async () => {
  const ds = makeDb();
  const realDid = 'did:scid:vh:1:zTestIssue3';
  const result = await createRemoteVta(ds, {
    realDid,
    name: 'Atomic',
    subjectKind: 'human',
    didDocument: { id: realDid },
    publicKeys: { ed25519: KEY_A, x25519: KEY_A },
  });
  assert.ok(result.identity.uuid);
  assert.ok(result.didDocument.uuid);
  await ds.close();
});

// ---------------------------------------------------------------------------
// One ACTIVE key per (identity, key_type, rotation_version)
//
// The handshake writes the key it extracted from the DID document IT upserted
// (a NON-primary handshake-stub row), while identity_push writes the primary
// document's uuid. Because the keys UNIQUE tuple includes did_document_uuid, a
// doc-scoped upsert INSERTED a second ed25519/rv-0 row instead of updating —
// leaving two candidates, of which the relationship store picked one
// arbitrarily. That is the mechanism behind the observed
// `tspOpen: signature verification failed` on otherwise valid messages.
// ---------------------------------------------------------------------------

function docFor(did: string, ed: Uint8Array): Record<string, unknown> {
  const doc = buildDidPeer4Document(ed, new Uint8Array(32).fill(0x22), {
    peerId: '12D3KooWKeysConverge', multiaddrs: ['/ip4/127.0.0.1/tcp/40003'],
  }) as unknown as Record<string, unknown>;
  doc.id = did;
  return doc;
}

async function ed25519Rows(ds: SqliteDataSource, identityUuid: string) {
  return ds.all<{ uuid: string; public_key: Buffer | Uint8Array; did_document_uuid: string | null }>(
    `SELECT uuid, public_key, did_document_uuid FROM keys
      WHERE identity_uuid = ? AND key_type = 'ed25519' AND rotation_version = 0`,
    identityUuid,
  );
}

test('identity_push: converges onto ONE active key row even when the handshake linked it to another document', async () => {
  const ds = makeDb();
  const oldDid = 'did:scid:vh:1:zKeysConvergeOld';
  const newDid = 'did:scid:vh:1:zKeysConvergeNew';

  // Handshake for the OLD did: identity + non-primary doc + a key row linked to it.
  const resolver = new DsIdentityResolver(ds);
  const resolvedStub = await resolver.resolveRemoteIdentity({
    did: oldDid,
    method: 'did:scid:vh',
    didDocumentJson: JSON.stringify(docFor(oldDid, new Uint8Array(32).fill(0x11))),
    isPrimary: false,
    recordedByNode: 'tsp-bridge',
    peerId: '12D3KooWKeysConverge',
  });
  if (!resolvedStub) throw new Error('test setup: handshake stub was not created');
  const stub = resolvedStub;

  const before = await ed25519Rows(ds, stub.identityUuid);
  assert.equal(before.length, 1, 'precondition: the handshake wrote exactly one ed25519 row');
  const handshakeRowUuid = before[0].uuid;

  // The agent later presents a NEW did (the peer4 -> scid:vh case) with its LIVE key.
  await createRemoteVta(ds, {
    realDid: newDid,
    uuid: stub.identityUuid,
    name: 'converge',
    subjectKind: 'human',
    didDocument: docFor(newDid, new Uint8Array(32).fill(0xbb)),
    publicKeys: { ed25519: KEY_B, x25519: KEY_A },
    recordedByNode: 'agent-push',
  });

  const after = await ed25519Rows(ds, stub.identityUuid);
  assert.equal(after.length, 1, 'must UPDATE the existing active key, never add a second ed25519/rv-0 row');
  assert.equal(after[0].uuid, handshakeRowUuid, 'the same row is updated in place');
  const key = after[0].public_key instanceof Uint8Array ? after[0].public_key : new Uint8Array(after[0].public_key);
  assert.equal(Buffer.from(key).toString('base64'), KEY_B, 'the LIVE key from identity_push wins');

  // ...and the row is re-pointed at the new primary document, which is the one the
  // relationship store prefers when it resolves the verification key.
  const primary = await didDocumentsRepo.findPrimaryForIdentity(ds, stub.identityUuid);
  assert.ok(primary, 'the pushed document must be promoted to primary');
  assert.equal(after[0].did_document_uuid, primary!.uuid, 'the active key follows the primary document');

  await ds.close();
});

test('keys-repo: upsertPublicKeyFromReplication is idempotent (merge, not duplicate)', async () => {
  const ds = makeDb();
  const realDid = 'did:scid:vh:1:zTestIssue4';
  const push = pushInput(realDid, { ed25519: KEY_A, x25519: KEY_A });
  const identityUuid = await identitiesRepo.create(ds, { realDid, uuid: push.uuid, role: 'vta', name: 'Rep', recordedByNode: 'n1' });
  const docUuid = await didDocumentsRepo.create(ds, { identityUuid, did: realDid, method: 'did:scid:vh', documentJson: '{}', isPrimary: true, recordedByNode: 'n1' });

  const keyUuid1 = await keysRepo.upsertPublicKeyFromReplication(ds, {
    identityUuid, didDocumentUuid: docUuid, keyType: 'ed25519',
    publicKey: Buffer.from(KEY_A, 'base64'), recordedByNode: 'n1', replicatedAt: 1000,
  });
  const keyUuid2 = await keysRepo.upsertPublicKeyFromReplication(ds, {
    identityUuid, didDocumentUuid: docUuid, keyType: 'ed25519',
    publicKey: Buffer.from(KEY_B, 'base64'), recordedByNode: 'n2', replicatedAt: 2000,
  });

  assert.strictEqual(keyUuid2, keyUuid1, 're-inserting the same unique tuple must return the merged row uuid');
  const rows = await ds.all<{ public_key: Buffer | Uint8Array }>(
    'SELECT public_key FROM keys WHERE uuid = ?',
    keyUuid1,
  );
  const stored = Buffer.from(rows[0].public_key as Uint8Array).toString('base64');
  assert.strictEqual(stored, KEY_B, 'public key should merge to the newer replicated value');
  await ds.close();
});

/**
 * The 2026-09-25 field loop.
 *
 * Live symptom: a rapid `tx_prepare` → `prepare failed … duplicate key value violates
 * unique constraint "keys_identity_uuid_did_document_uuid_key_type_rotation_vers_key"`
 * → vote 'no' → `tx_abort` loop between an agent and the utility server after creating a
 * community. The agent's durable outbox replayed forever because every replay failed the
 * same way.
 *
 * State found in the server DB for the pushed identity (shannon): TWO ed25519/rv-0 rows
 * linked to DIFFERENT did_documents — one to a `did:peer:4` handshake stub, one to the
 * primary `did:scid:vh` document. `syncRemotePublicKeys` picks the newest row and tries to
 * re-point it at the passed (primary) document; because `did_document_uuid` is part of the
 * unique tuple, that collides with the sibling already holding it. The failed UPDATE
 * changed nothing, so it was deterministic, not a race.
 *
 * This test seeds that exact two-row state and asserts the push now CONVERGES to one row
 * instead of aborting the transaction.
 */
test('identity_push: two rv-0 rows across documents converge instead of aborting the push', async () => {
  const ds = makeDb();
  const realDid = 'did:scid:vh:1:zKeysDupFieldLoop';

  // 1) Normal push → identity + primary document + one ed25519/rv-0 row on it.
  const seeded = await createRemoteVta(ds, pushInput(realDid, { ed25519: KEY_A, x25519: KEY_A }));
  const identityUuid = seeded.identity.uuid;

  // 2) A second (non-primary) document with a key row linked to IT — the handshake-stub /
  //    replicated side of the two-row state. Created LATER on purpose: it wins
  //    `ORDER BY created_at DESC` and becomes the row the convergence UPDATE moves.
  const otherDoc = await didDocumentsRepo.create(ds, {
    identityUuid,
    did: 'did:peer:4zKeysDupFieldLoopOtherDoc',
    method: 'did:peer:4',
    documentJson: '{}',
    isPrimary: false,
    recordedByNode: 'tsp-bridge',
  });
  await keysRepo.upsertPublicKeyFromReplication(ds, {
    identityUuid,
    didDocumentUuid: otherDoc,
    keyType: 'ed25519',
    publicKey: Buffer.from(KEY_A, 'base64'),
    recordedByNode: 'tsp-bridge',
    replicatedAt: Math.floor(Date.now() / 1000),
  });

  const before = await ed25519Rows(ds, identityUuid);
  assert.equal(before.length, 2, 'precondition: two ed25519/rv-0 rows');
  assert.equal(
    new Set(before.map((r) => r.did_document_uuid)).size, 2,
    'precondition: the two rows are linked to DIFFERENT documents (the collision condition)',
  );

  const primary = await didDocumentsRepo.findPrimaryForIdentity(ds, identityUuid);
  assert.ok(primary, 'precondition: a primary document exists');

  // 3) The replay. Before the fix this rejected the whole identity push, which the agent's
  //    outbox then retried immediately — the observed rapid fire.
  await createRemoteVta(ds, pushInput(realDid, { ed25519: KEY_B, x25519: KEY_A }));

  const after = await ed25519Rows(ds, identityUuid);
  assert.equal(after.length, 1, 'must converge to exactly ONE ed25519/rv-0 row');
  assert.equal(after[0].did_document_uuid, primary!.uuid, 'the survivor carries the primary-document linkage');
  const key = after[0].public_key instanceof Uint8Array ? after[0].public_key : new Uint8Array(after[0].public_key);
  assert.equal(Buffer.from(key).toString('base64'), KEY_B, 'and the LIVE key from the push wins');

  await ds.close();
});