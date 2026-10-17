// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for identities-repo.ts — UUIDv5-based identity creation and lookups.
 * Uses SqliteDataSource (in-memory) + the sync migration runner via getRawDb().
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import { didToUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

function makeDb() {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

test('identities-repo: create derives UUIDv5 from realDid', async () => {
  const ds = makeDb();
  const realDid = 'did:peer:4zTestCreate';
  const id = await identitiesRepo.create(ds, { realDid, role: 'vta' });
  const row = await identitiesRepo.findByUuid(ds, id);
  assert.ok(row);
  assert.strictEqual(row!.uuid, didToUuid(realDid));
  await ds.close();
});

test('identities-repo: create returns a uuid, defaults custody', async () => {
  const ds = makeDb();
  const id = await identitiesRepo.create(ds, { realDid: 'did:peer:4zCustody', role: 'vta', name: 'Test' });
  const row = await identitiesRepo.findByUuid(ds, id);
  assert.ok(id);
  assert.strictEqual(row!.custody, 'remote');
  await ds.close();
});

test('identities-repo: findByRole and findByPeerId', async () => {
  const ds = makeDb();
  await identitiesRepo.create(ds, { realDid: 'did:peer:4zA', role: 'vta', peerId: 'peer-A' });
  await identitiesRepo.create(ds, { realDid: 'did:peer:4zB', role: 'vtc', peerId: 'peer-B' });
  const vtas = await identitiesRepo.findByRole(ds, 'vta');
  assert.ok(vtas.length >= 1);
  const byPeer = await identitiesRepo.findByPeerId(ds, 'peer-A');
  assert.ok(byPeer);
  await ds.close();
});

test('identities-repo: upsertFromReplication creates and is idempotent', async () => {
  const ds = makeDb();
  const realDid = 'did:peer:4zUpsert';
  const id1 = await identitiesRepo.upsertFromReplication(ds, { realDid, role: 'vta', name: 'V1', recordedByNode: 'n1', replicatedAt: 1000 });
  const id2 = await identitiesRepo.upsertFromReplication(ds, { realDid, role: 'vta', name: 'V2', recordedByNode: 'n2', replicatedAt: 2000 });
  assert.strictEqual(id2, id1);
  await ds.close();
});