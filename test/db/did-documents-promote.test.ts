// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Regression tests for the identity_push → did_documents write path.
 *
 * Reproduced bug (TSP v3): `createRemoteVta` self-healed a handshake stub by
 * INSERTing a row it assumed did not exist:
 *
 *   let existingDoc = await didDocumentsRepo.findPrimaryForIdentity(db, uuid);
 *   if (!existingDoc) { await didDocumentsRepo.create(db, { did: realDid, isPrimary: true }); }
 *
 * But the RFI/RFA handshake and the per-message endpoint recording both
 * materialize stubs with `isPrimary: false` (DsIdentityResolver), so a stub
 * ALWAYS already has a row for its DID — and `did_documents.did` is globally
 * UNIQUE (migrations 0002 / 0019). The INSERT therefore raised a
 * unique-constraint violation, `exchange-push-participant.prepare()` voted `no`,
 * and the whole identity_push 2PC aborted — the exact opposite of the intended
 * self-heal (the agent's name, R-Card, VRC-archive and VMC pushes all ride this).
 *
 * Second defect closed at the same time: resolving via `findPrimaryForIdentity()`
 * can return a row belonging to a DIFFERENT DID (context C-DID / M-DID rows, or a
 * legacy peer:4 row still flagged primary after the agent moved to did:scid:vh),
 * and overwriting its `document_json` made the row's `document_json` disagree
 * with its `did`.
 *
 * Invariants asserted here:
 *  1. at most ONE did_documents row per DID (the existing row is promoted, not
 *     duplicated, and its uuid is preserved)
 *  2. exactly one is_primary=1 row per identity
 *  3. a push never overwrites another DID's document_json
 *  4. the push's LIVE keys win over the handshake's document-derived keys
 *  5. a DID bound to a DIFFERENT identity is refused loudly instead of being
 *     written across identities
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs --test test/db/did-documents-promote.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import { createRemoteVta } from '@p2p-trust-stack/core/services/vta.js';
import { buildDidPeer4Document } from '@p2p-trust-stack/core/did/create.js';
import { DsIdentityResolver } from '../../src/node/relationship-store-ds.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

function makeDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

const ED_A = new Uint8Array(32).fill(0x11);
const X_A = new Uint8Array(32).fill(0x22);
const ED_B = new Uint8Array(32).fill(0xbb);   // the agent's LIVE keystore key
const X_B = new Uint8Array(32).fill(0xcc);

/** A well-formed did:peer:4 document so extractEd25519/X25519PublicKey work. */
function makeDoc(did: string, ed: Uint8Array = ED_A, x: Uint8Array = X_A): Record<string, unknown> {
  const doc = buildDidPeer4Document(ed, x, {
    peerId: '12D3KooWTestPeerId',
    multiaddrs: ['/ip4/127.0.0.1/tcp/40003'],
  }) as unknown as Record<string, unknown>;
  doc.id = did;
  return doc;
}

/**
 * Drive the REAL handshake path: creates the identity, a NON-primary
 * did_documents row and the document-derived keys rows — exactly what
 * `tsp-bridge.processRfi` / the per-message endpoint recording do.
 */
async function seedHandshakeStub(ds: SqliteDataSource, did: string, peerId = '12D3KooWTestPeerId') {
  const resolver = new DsIdentityResolver(ds);
  const resolved = await resolver.resolveRemoteIdentity({
    did,
    method: 'did:scid:vh',
    didDocumentJson: JSON.stringify(makeDoc(did)),
    isPrimary: false,
    recordedByNode: 'tsp-bridge',
    peerId,
  });
  if (!resolved) throw new Error('test setup: handshake stub was not created');
  return resolved;
}

async function rowsForIdentity(ds: SqliteDataSource, identityUuid: string) {
  return ds.all<{ did: string; uuid: string; is_primary: number; document_json: string | null }>(
    'SELECT did, uuid, is_primary, document_json FROM did_documents WHERE identity_uuid = ? ORDER BY did',
    identityUuid,
  );
}

// ---------------------------------------------------------------------------
// 1. The bug: stub upgrade must promote the existing row, never duplicate it
// ---------------------------------------------------------------------------

test('identity_push: upgrading a handshake stub promotes its DID document row (no duplicate, no unique violation)', async () => {
  const ds = makeDb();
  const did = 'did:scid:vh:1:zTestPromote1';

  const stub = await seedHandshakeStub(ds, did);
  const before = await rowsForIdentity(ds, stub.identityUuid);
  assert.equal(before.length, 1, 'handshake stub should have exactly one did_documents row');
  assert.equal(before[0].is_primary, 0, 'the handshake writes stubs non-primary (the precondition for the bug)');
  const stubDocUuid = before[0].uuid;

  const pushed = { ...makeDoc(did), alsoKnownAs: ['vta:vta:alice'] };
  const result = await createRemoteVta(ds, {
    realDid: did,
    uuid: stub.identityUuid,
    name: 'alice',
    subjectKind: 'human',
    didDocument: pushed,
    publicKeys: { ed25519: b64(ED_B), x25519: b64(X_B) },
    peerId: '12D3KooWTestPeerId',
    recordedByNode: 'agent-push',
  });

  assert.equal(result.identity.uuid, stub.identityUuid);

  const after = await rowsForIdentity(ds, stub.identityUuid);
  assert.equal(after.length, 1, 'must NOT create a second did_documents row for the same DID');
  assert.equal(after[0].uuid, stubDocUuid, 'must promote the SAME row (uuid preserved), not replace it');
  assert.equal(after[0].is_primary, 1, 'the promoted row must be the primary');

  const doc = JSON.parse(after[0].document_json!) as { alsoKnownAs?: string[] };
  assert.deepEqual(doc.alsoKnownAs, ['vta:vta:alice'], 'document_json must carry the pushed document');

  // Invariant 4: the push's LIVE keystore key wins over the handshake's
  // document-derived key (this is the Bug B repair path).
  const ed = await ds.get<{ public_key: Uint8Array | Buffer }>(
    `SELECT public_key FROM keys
      WHERE identity_uuid = ? AND did_document_uuid = ? AND key_type = 'ed25519' AND rotation_version = 0`,
    stub.identityUuid,
    stubDocUuid,
  );
  assert.ok(ed, 'ed25519 key row must exist');
  const keyBytes = ed.public_key instanceof Uint8Array ? ed.public_key : new Uint8Array(ed.public_key);
  assert.equal(b64(keyBytes), b64(ED_B), 'the live key from identity_push must overwrite the document-derived key');

  await ds.close();
});

// ---------------------------------------------------------------------------
// 2. Repeated pushes converge on one row
// ---------------------------------------------------------------------------

test('identity_push: repeated pushes of a stub identity converge (still one row, still primary)', async () => {
  const ds = makeDb();
  const did = 'did:scid:vh:1:zTestPromote2';
  const stub = await seedHandshakeStub(ds, did);

  for (const name of ['first', 'second', 'third']) {
    await createRemoteVta(ds, {
      realDid: did,
      uuid: stub.identityUuid,
      name,
      subjectKind: 'human',
      didDocument: { ...makeDoc(did), alsoKnownAs: [`vta:vta:${name}`] },
      publicKeys: { ed25519: b64(ED_B), x25519: b64(X_B) },
      recordedByNode: 'agent-push',
    });
  }

  const rows = await rowsForIdentity(ds, stub.identityUuid);
  assert.equal(rows.length, 1, 'repeated pushes must converge on a single did_documents row');
  assert.equal(rows[0].is_primary, 1);
  const doc = JSON.parse(rows[0].document_json!) as { alsoKnownAs?: string[] };
  assert.deepEqual(doc.alsoKnownAs, ['vta:vta:third'], 'the latest push wins');

  await ds.close();
});

// ---------------------------------------------------------------------------
// 3. A legacy primary for a DIFFERENT DID is demoted, and never overwritten
// ---------------------------------------------------------------------------

test('identity_push: a primary document for a different DID is demoted, not overwritten', async () => {
  const ds = makeDb();
  const legacyDid = 'did:peer:4zLegacyPrimaryDoc';
  const newDid = 'did:scid:vh:1:zTestPromote3';

  // An identity whose primary document is a legacy peer:4 DID, with NO row at
  // all for the DID the agent now presents.
  const identityUuid = await identitiesRepo.create(ds, {
    realDid: legacyDid,
    role: 'vta',
    subjectKind: 'human',
    custody: 'remote',
    name: 'legacy',
  });
  const legacyDocUuid = await didDocumentsRepo.create(ds, {
    identityUuid,
    did: legacyDid,
    method: 'did:peer:4',
    documentJson: JSON.stringify(makeDoc(legacyDid)),
    isPrimary: true,
    recordedByNode: 'tsp-bridge',
  });

  await createRemoteVta(ds, {
    realDid: newDid,
    uuid: identityUuid,
    name: 'alice',
    subjectKind: 'human',
    didDocument: makeDoc(newDid),
    publicKeys: { ed25519: b64(ED_B), x25519: b64(X_B) },
    recordedByNode: 'agent-push',
  });

  const rows = await rowsForIdentity(ds, identityUuid);
  assert.equal(rows.length, 2, 'two DISTINCT DIDs legitimately have two rows');

  const legacyRow = rows.find((r) => r.did === legacyDid)!;
  const newRow = rows.find((r) => r.did === newDid)!;
  assert.equal(newRow.is_primary, 1, 'the pushed DID becomes primary');
  assert.equal(legacyRow.is_primary, 0, 'the legacy primary is demoted — one primary per identity');

  // Invariant 3: the other DID's document must be untouched.
  const legacyDoc = JSON.parse(legacyRow.document_json!) as { id?: string };
  assert.equal(legacyDoc.id, legacyDid, "another DID's document_json must never be overwritten");
  assert.equal(legacyRow.uuid, legacyDocUuid);

  await ds.close();
});

// ---------------------------------------------------------------------------
// 4. A DID bound to a different identity is refused, not written across
// ---------------------------------------------------------------------------

test('identity_push: a DID bound to a different identity is refused loudly (no cross-identity write)', async () => {
  const ds = makeDb();
  const did = 'did:scid:vh:1:zTestPromote4';

  // The DID's single row belongs to identity Y (an orphaned stub).
  const orphan = await seedHandshakeStub(ds, did, '12D3KooWOrphanPeer');
  const orphanDocUuid = (await rowsForIdentity(ds, orphan.identityUuid))[0].uuid;

  // The agent pushes the same DID but claims a DIFFERENT (authoritative) uuid.
  const claimedUuid = '11111111-2222-4333-8444-555555555555';
  await identitiesRepo.create(ds, {
    realDid: 'did:scid:vh:1:zTestPromote4-other',
    uuid: claimedUuid,
    role: 'vta',
    subjectKind: 'human',
    custody: 'remote',
    name: 'alice',
  });

  await assert.rejects(
    createRemoteVta(ds, {
      realDid: did,
      uuid: claimedUuid,
      name: 'alice',
      subjectKind: 'human',
      didDocument: makeDoc(did),
      publicKeys: { ed25519: b64(ED_B), x25519: b64(X_B) },
      recordedByNode: 'agent-push',
    }),
    /could not resolve or materialize the DID document/,
    'a DID bound to another identity must fail loudly rather than being written across identities',
  );

  // The orphan's row is untouched and still owned by the orphan identity.
  const orphanRows = await rowsForIdentity(ds, orphan.identityUuid);
  assert.equal(orphanRows.length, 1);
  assert.equal(orphanRows[0].uuid, orphanDocUuid);
  const orphanDoc = JSON.parse(orphanRows[0].document_json!) as { alsoKnownAs?: string[] };
  assert.equal(orphanDoc.alsoKnownAs, undefined, "the refused push must not modify the other identity's document");

  const claimedRows = await rowsForIdentity(ds, claimedUuid);
  assert.equal(claimedRows.length, 0, 'the refused push must not create a row for the claimed identity');

  await ds.close();
});
