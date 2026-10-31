// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for the identity/DID-document/key reconciliation pass.
 *
 * The damaged states are seeded with raw SQL on purpose: the application can no
 * longer produce them (that is what the G3a/G3b fixes achieved), so only direct
 * inserts can reproduce the population this script exists to clean up:
 *  - two primary did_documents rows for one identity;
 *  - an identity with documents but NO primary (handshake stubs → `Identity.did`
 *    resolves to null and callers fall back to the uuid, the D12 symptom);
 *  - two active keys rows for one (identity, key_type, rv=0) — the doc-linkage
 *    divergence that made signature verification pick a key arbitrarily;
 *  - an identity with no documents at all (an orphan);
 *  - a non-canonical identity (uuid ≠ UUIDv5(primaryDid), the pre-v3 VID-keyed
 *    stub shape).
 *
 * The pass must be READ-ONLY by default, repair the three in-identity shapes with
 * `fix: true`, leave the report-only shapes untouched, and be idempotent.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ../test-loader.mjs --test test/node/reconcile-identities.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { didToUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import { reconcileIdentities } from '@p2p-trust-stack/core/db/reconcile-identities.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

const A_DID = 'did:scid:vh:1:zMultiPrimary';
const A_DID_2 = 'did:peer:4zMultiPrimarySecond';
const B_DID = 'did:scid:vh:1:zNoPrimary';
const B_DID_2 = 'did:peer:4zNoPrimarySecond';
const C_DID = 'did:scid:vh:1:zDupKeys';
const ORPHAN_UUID = 'orphan-uuid-d';
const E_DID = 'did:scid:vh:1:zNonCanonical';

const KEY_C_PRIMARY = Buffer.from(new Uint8Array(32).fill(0xc1));
const KEY_C_STALE = Buffer.from(new Uint8Array(32).fill(0xc2));

function makeDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

async function insertIdentity(ds: SqliteDataSource, uuid: string, name: string, custody = 'remote'): Promise<string> {
  await ds.run(
    `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
     VALUES (?, 'vta', 'human', ?, ?, 0, 0)`,
    uuid, custody, name,
  );
  return uuid;
}

async function insertDoc(
  ds: SqliteDataSource, uuid: string, identityUuid: string, did: string, isPrimary: boolean, createdAt: number,
): Promise<string> {
  await ds.run(
    `INSERT INTO did_documents
       (uuid, identity_uuid, did, method, document_json, is_primary, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
    uuid, identityUuid, did, did.startsWith('did:scid:vh:') ? 'did:scid:vh' : 'did:peer:4',
    JSON.stringify({ id: did }), isPrimary ? 1 : 0, createdAt, createdAt,
  );
  return uuid;
}

async function insertKey(
  ds: SqliteDataSource, uuid: string, identityUuid: string, docUuid: string | null,
  publicKey: Buffer, createdAt: number, keyType = 'ed25519',
): Promise<string> {
  await ds.run(
    `INSERT INTO keys
       (uuid, identity_uuid, did_document_uuid, key_type, public_key, rotation_version, created_at)
     VALUES (?, ?, ?, ?, ?, 0, ?)`,
    uuid, identityUuid, docUuid, keyType, publicKey, createdAt,
  );
  return uuid;
}

interface Seeded {
  aUuid: string; aDoc1: string; aDoc2: string;
  bUuid: string; bDoc1: string; bDoc2: string;
  cUuid: string; cKey1: string; cKey2: string;
  eUuid: string;
}

/** Seed every damaged shape. Returns the uuids the assertions need. */
async function seedDamaged(ds: SqliteDataSource): Promise<Seeded> {
  // A: identity with TWO primaries; doc1 is referenced by a relationship, so the
  // ranking must keep doc1 (referenced) over the newer doc2.
  const aUuid = await insertIdentity(ds, didToUuid(A_DID), 'multi-primary');
  const aDoc1 = await insertDoc(ds, 'doc-a1', aUuid, A_DID, true, 100);
  const aDoc2 = await insertDoc(ds, 'doc-a2', aUuid, A_DID_2, true, 200);
  await ds.run(
    `INSERT INTO relationships
       (uuid, local_identity_uuid, remote_identity_uuid, remote_did_document_uuid, direction, status, created_at, updated_at)
     VALUES ('rel-a', ?, ?, ?, 'bidirectional', 'established', 0, 0)`,
    aUuid, aUuid, aDoc1,
  );

  // B: documents but NO primary; doc1 (the canonical DID) is the one an active
  // key is linked to, so the ranking must prefer it over the newer doc2.
  const bUuid = await insertIdentity(ds, didToUuid(B_DID), 'no-primary');
  const bDoc1 = await insertDoc(ds, 'doc-b1', bUuid, B_DID, false, 100);
  const bDoc2 = await insertDoc(ds, 'doc-b2', bUuid, B_DID_2, false, 200);
  await insertKey(ds, 'key-b1', bUuid, bDoc1, Buffer.from(new Uint8Array(32).fill(0xb1)), 100);

  // C: one primary document and TWO active ed25519 keys (primary-linked + stale).
  const cUuid = await insertIdentity(ds, didToUuid(C_DID), 'dup-keys');
  const cDoc = await insertDoc(ds, 'doc-c1', cUuid, C_DID, true, 100);
  const cKey1 = await insertKey(ds, 'key-c1', cUuid, cDoc, KEY_C_PRIMARY, 100);
  const cKey2 = await insertKey(ds, 'key-c2', cUuid, 'doc-a2', KEY_C_STALE, 300);

  // D: orphan — an identity row with no documents at all.
  await insertIdentity(ds, ORPHAN_UUID, 'orphan', 'remote');

  // E: non-canonical uuid with a perfectly good primary document.
  const eUuid = await insertIdentity(ds, 'not-a-canonical-uuid', 'non-canonical');
  await insertDoc(ds, 'doc-e1', eUuid, E_DID, true, 100);

  return { aUuid, aDoc1, aDoc2, bUuid, bDoc1, bDoc2, cUuid, cKey1, cKey2, eUuid };
}

async function primaries(ds: SqliteDataSource, identityUuid: string): Promise<string[]> {
  const rows = await ds.all<{ uuid: string }>(
    'SELECT uuid FROM did_documents WHERE identity_uuid = ? AND is_primary = 1 ORDER BY uuid',
    identityUuid,
  );
  return rows.map((r) => r.uuid);
}

async function activeKeys(ds: SqliteDataSource, identityUuid: string): Promise<string[]> {
  const rows = await ds.all<{ uuid: string }>(
    `SELECT uuid FROM keys WHERE identity_uuid = ? AND key_type = 'ed25519' AND rotation_version = 0 ORDER BY uuid`,
    identityUuid,
  );
  return rows.map((r) => r.uuid);
}

test('reconcileIdentities: report-only by default — identifies every shape, changes nothing', async () => {
  const ds = makeDb();
  const s = await seedDamaged(ds);

  const report = await reconcileIdentities(ds);

  assert.equal(report.scanned.identities, 5);
  assert.equal(report.applied.documentFixes, 0, 'report mode must not write');
  assert.equal(report.applied.keyFixes, 0);

  assert.equal(report.multiplePrimaries.length, 1);
  assert.equal(report.multiplePrimaries[0].identityUuid, s.aUuid);
  assert.equal(
    report.multiplePrimaries[0].keptDocUuid, s.aDoc1,
    'the REFERENCED document wins over the newer one',
  );
  assert.deepEqual(report.multiplePrimaries[0].otherDocUuids, [s.aDoc2]);

  assert.equal(report.missingPrimary.length, 1);
  assert.equal(
    report.missingPrimary[0].keptDocUuid, s.bDoc1,
    'the document an active key is linked to wins (over the newer one)',
  );

  assert.equal(report.duplicateActiveKeys.length, 1);
  assert.equal(report.duplicateActiveKeys[0].keptKeyUuid, s.cKey1, 'the primary-linked key wins');
  assert.deepEqual(report.duplicateActiveKeys[0].removedKeyUuids, [s.cKey2]);

  assert.deepEqual(
    report.orphanIdentities.map((o) => o.identityUuid), [ORPHAN_UUID],
    'an identity with no documents is reported, not repaired',
  );

  assert.equal(report.nonCanonicalIdentities.length, 1);
  assert.equal(report.nonCanonicalIdentities[0].identityUuid, s.eUuid);
  assert.equal(report.nonCanonicalIdentities[0].expectedUuid, didToUuid(E_DID));
  assert.equal(report.nonCanonicalIdentities[0].canonicalRowExists, false);

  // Nothing moved.
  assert.deepEqual(await primaries(ds, s.aUuid), [s.aDoc1, s.aDoc2].sort());
  assert.deepEqual(await primaries(ds, s.bUuid), []);
  assert.equal((await activeKeys(ds, s.cUuid)).length, 2);

  await ds.close();
});

test('reconcileIdentities: fix applies the three in-identity repairs and is idempotent', async () => {
  const ds = makeDb();
  const s = await seedDamaged(ds);

  const report = await reconcileIdentities(ds, { fix: true });
  assert.deepEqual(report.applied, { documentFixes: 2, keyFixes: 1 });

  // exactly one primary per identity, and it is the ranked keeper
  assert.deepEqual(await primaries(ds, s.aUuid), [s.aDoc1]);
  assert.deepEqual(await primaries(ds, s.bUuid), [s.bDoc1]);
  // the demoted document still exists (demotion, not deletion)
  const aDocs = await ds.all<{ uuid: string }>(
    'SELECT uuid FROM did_documents WHERE identity_uuid = ?', s.aUuid,
  );
  assert.equal(aDocs.length, 2, 'the losing document is demoted, not deleted');

  // duplicate active key collapsed onto the primary-linked row
  assert.deepEqual(await activeKeys(ds, s.cUuid), [s.cKey1]);

  // report-only shapes were NOT touched
  assert.equal((await ds.all('SELECT uuid FROM identities WHERE uuid = ?', ORPHAN_UUID)).length, 1);
  assert.deepEqual(await primaries(ds, s.eUuid), ['doc-e1']);

  // idempotent: a second pass finds nothing left to repair
  const second = await reconcileIdentities(ds, { fix: true });
  assert.deepEqual(second.applied, { documentFixes: 0, keyFixes: 0 });
  assert.equal(second.multiplePrimaries.length, 0);
  assert.equal(second.missingPrimary.length, 0);
  assert.equal(second.duplicateActiveKeys.length, 0);
  // the report-only findings persist across runs (they need a human decision)
  assert.equal(second.nonCanonicalIdentities.length, 1);
  assert.equal(second.orphanIdentities.length, 1);

  await ds.close();
});

// ---------------------------------------------------------------------------
// Atomicity of --fix (H11). The reconciliation CLI is the tool an operator runs
// against a LIVE, damaged database, so a partial repair is worse than no repair:
// `setPrimary()` is two statements, and a crash between them leaves an identity
// with no primary at all — the exact shape repair #2 exists to fix.
// ---------------------------------------------------------------------------

/**
 * A DataSource that forwards to a real one with two seams:
 *  - `failAfterRuns` — throw instead of performing the (n+1)th `run`, so a failure
 *    lands exactly between the two statements of `setPrimary`;
 *  - `transactions` — count the atomic units the repair pass opens.
 *
 * A forwarding wrapper is required rather than `Object.create(db)`: SqliteDataSource
 * uses private class fields (`#db`), which a derived plain object cannot reach.
 * `transaction()` re-wraps the transaction-bound source it hands to the callback, so
 * writes made *inside* the transaction still cross the seam.
 */
interface SeamState {
  runs: number;
  transactions: number;
  failAfterRuns: number;
}

class SeamDataSource implements DataSource {
  private readonly inner: DataSource;
  private readonly state: SeamState;

  constructor(inner: DataSource, state: SeamState) {
    this.inner = inner;
    this.state = state;
  }

  all<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T[]> {
    return this.inner.all<T>(sql, ...params);
  }
  get<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T | null> {
    return this.inner.get<T>(sql, ...params);
  }
  async run(sql: string, ...params: unknown[]) {
    this.state.runs += 1;
    if (this.state.runs > this.state.failAfterRuns) throw new Error('simulated mid-repair failure');
    return this.inner.run(sql, ...params);
  }
  exec(sql: string): Promise<void> {
    return this.inner.exec(sql);
  }
  transaction<T>(fn: (ds: DataSource) => Promise<T>): Promise<T> {
    this.state.transactions += 1;
    return this.inner.transaction((tx) => fn(new SeamDataSource(tx, this.state)));
  }
  close(): Promise<void> {
    return this.inner.close();
  }
}

function seam(db: SqliteDataSource, failAfterRuns = Number.POSITIVE_INFINITY): { ds: DataSource; state: SeamState } {
  const state: SeamState = { runs: 0, transactions: 0, failAfterRuns };
  return { ds: new SeamDataSource(db, state), state };
}

test('reconcileIdentities: a failure mid-fix rolls back the WHOLE pass (no half-repaired db)', async () => {
  const ds = makeDb();
  const s = await seedDamaged(ds);

  const before = {
    aPrimaries: await primaries(ds, s.aUuid),
    bPrimaries: await primaries(ds, s.bUuid),
    cKeys: await activeKeys(ds, s.cUuid),
  };
  assert.deepEqual(before.aPrimaries, [s.aDoc1, s.aDoc2], 'seeded with two primaries');
  assert.deepEqual(before.bPrimaries, [], 'seeded with none');

  // Allow ONE write (the first setPrimary's `clear is_primary`) and then fail —
  // exactly inside the window where an untransacted repair would leave A with
  // zero primaries.
  const { ds: failing } = seam(ds, 1);
  await assert.rejects(
    () => reconcileIdentities(failing, { fix: true }),
    /simulated mid-repair failure/,
  );

  // Nothing changed: not A's demotion, not B's promotion, not C's keys.
  assert.deepEqual(
    await primaries(ds, s.aUuid),
    before.aPrimaries,
    'A must still have its original primaries — the demote step must not survive alone',
  );
  assert.deepEqual(await primaries(ds, s.bUuid), before.bPrimaries, 'B untouched');
  assert.deepEqual(await activeKeys(ds, s.cUuid), before.cKeys, 'C keys untouched');
  assert.equal(
    (await ds.all('SELECT uuid FROM did_documents WHERE uuid = ?', s.aDoc2)).length,
    1,
    'the losing document still exists',
  );

  // The pass is still usable afterwards: a clean re-run applies everything.
  const report = await reconcileIdentities(ds, { fix: true });
  assert.deepEqual(report.applied, { documentFixes: 2, keyFixes: 1 });
  assert.deepEqual(await primaries(ds, s.aUuid), [s.aDoc1]);
  assert.deepEqual(await primaries(ds, s.bUuid), [s.bDoc1]);

  await ds.close();
});

test('reconcileIdentities: report-only never opens a transaction; fix opens exactly one', async () => {
  const ds = makeDb();
  await seedDamaged(ds);
  const { ds: counting, state } = seam(ds);

  await reconcileIdentities(counting);
  assert.equal(state.transactions, 0, 'a report run must not open a transaction (read-only by default)');

  await reconcileIdentities(counting, { fix: true });
  assert.equal(state.transactions, 1, 'the repair pass is one atomic unit');

  await ds.close();
});

// ---------------------------------------------------------------------------
// Dialect portability of the reconcile path (H11)
//
// The CLI connects to YugabyteDB (`YugabyteDataSource`) — the same engine
// production runs — yet no test in the tree exercises Postgres, so a SQLite-only
// construct would surface for the first time when an operator runs the tool
// against a LIVE, damaged database. The SQL this pass executes is portable today
// (plain SELECT/UPDATE/DELETE, `?` placeholders, INTEGER booleans); this test is
// the tripwire that keeps it that way.
//
// It is deliberately narrow — the pass plus the one repo it writes through — and
// scans comment-stripped source, so an explanatory mention of a banned token in a
// comment does not fail the build. A real Postgres run is still what H11's option
// (a) would add; this is the cheap half of option (b).
// ---------------------------------------------------------------------------

const SQLITE_ONLY_TOKENS: Array<[string, string]> = [
  ['pragma', 'SQLite-only PRAGMA statement'],
  ['sqlite_master', 'SQLite-only catalog table'],
  ['unixepoch(', 'SQLite-only time function — a JS timestamp is used instead'],
  ['strftime(', 'SQLite-only date formatting'],
  ['julianday(', 'SQLite-only date arithmetic'],
  ['ifnull(', 'SQLite/MySQL only — Postgres needs COALESCE'],
  ['insert or ', 'SQLite-only INSERT OR REPLACE/IGNORE — Postgres needs ON CONFLICT'],
  ['last_insert_rowid', 'SQLite-only — Postgres uses RETURNING'],
  ['group_concat(', 'SQLite only — Postgres spells it string_agg'],
  ['autoincrement', 'SQLite-only keyword — Postgres uses SERIAL/IDENTITY'],
  ['iif(', 'SQLite-only — Postgres uses CASE'],
  ['printf(', 'SQLite-only formatting'],
];

/** Source with comments removed, so only executable SQL is scanned. */
function stripComments(fileUrl: URL): string {
  return readFileSync(fileUrl, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');
}

test('reconcile path SQL stays dialect-portable (it runs against YugabyteDB, not SQLite)', () => {
  const files: Array<[string, URL]> = [
    ['src/db/reconcile-identities.ts', new URL('../../node_modules/@p2p-trust-stack/core/src/db/reconcile-identities.ts', import.meta.url)],
    ['src/db/repositories/did-documents-repo.ts', new URL('../../node_modules/@p2p-trust-stack/core/src/db/repositories/did-documents-repo.ts', import.meta.url)],
  ];

  for (const [label, url] of files) {
    const sql = stripComments(url).toLowerCase();
    for (const [token, reason] of SQLITE_ONLY_TOKENS) {
      assert.ok(
        !sql.includes(token),
        `${label} must not use "${token}" (${reason}) — this SQL also runs on YugabyteDB/Postgres`,
      );
    }
  }
});



