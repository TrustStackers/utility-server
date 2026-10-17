// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Route-level tests for VTN affiliation (`PATCH /vtcs/:uuid/affiliate`,
 * `POST /vtcs/:uuid/unaffiliate`).
 *
 * Why this file exists: the ruling of 2026-09-25 established that **a VTC depends
 * on a single VTN**, so `governance.parent_community_uuid` is the affiliate model
 * by design. These two routes are the only way to change it, they are reachable in
 * the running server (`layer5-applications/index.ts:60` → `registerVtnRoutes`),
 * and `grep -rl affiliate test/` previously found **nothing** — no test in either
 * suite touched them.
 *
 * The handlers were written with an error taxonomy (409 cycle, 400 validation,
 * 404 not-found) but called the service **without `await`**, so `reply.send()`
 * received a Promise and the `try/catch` could never observe a rejection. These
 * tests assert the documented contract, which is what exposed it.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs --test test/routes/vtn-affiliate.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify, { type FastifyInstance } from 'fastify';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as governanceRepo from '@p2p-trust-stack/core/db/repositories/governance-repo.js';
import { registerVtnRoutes } from '../../src/routes/layer5-applications/vtns.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

/** A VTC and a VTN, each with a primary DID document (the guard/routes join on it). */
async function seed(): Promise<{
  app: FastifyInstance;
  ds: SqliteDataSource;
  clubUuid: string;
  vtnUuid: string;
  outsiderUuid: string;
}> {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);

  const mk = async (did: string, role: 'vtc' | 'vtn' | 'vta', name: string) => {
    const uuid = generateUuid();
    await identitiesRepo.create(ds, { uuid, realDid: did, role, name, recordedByNode: 'test' });
    await didDocumentsRepo.create(ds, {
      identityUuid: uuid, did, method: 'did:scid:vh', isPrimary: true, recordedByNode: 'test',
    });
    return uuid;
  };

  const clubUuid = await mk('did:scid:vh:clubForAffiliation', 'vtc', 'Chess Club');
  const vtnUuid = await mk('did:scid:vh:vtnForAffiliation', 'vtn', 'Chess Network');
  // A third identity that is *not* a VTN, to exercise the validation branch.
  const outsiderUuid = await mk('did:scid:vh:notAVtn', 'vta', 'Not A Vtn');

  const app = Fastify();
  registerVtnRoutes(app, ds);
  await app.ready();
  return { app, ds, clubUuid, vtnUuid, outsiderUuid };
}

// ── PATCH /vtcs/:uuid/affiliate ─────────────────────────────────────────────

test('affiliate: 200 with the affiliation result, and it is persisted', async () => {
  const { app, ds, clubUuid, vtnUuid } = await seed();

  const res = await app.inject({
    method: 'PATCH',
    url: `/vtcs/${clubUuid}/affiliate`,
    payload: { parentCommunityUuid: vtnUuid },
  });

  assert.equal(res.statusCode, 200, `expected 200, got ${res.statusCode}: ${res.body}`);
  const body = res.json() as { child?: { uuid?: string }; childGovernance?: { parentCommunityUuid?: string } };
  assert.equal(body.child?.uuid, clubUuid, 'the response must carry the child identity');
  assert.equal(body.childGovernance?.parentCommunityUuid, vtnUuid, 'and the new parent');

  // The write must have happened, not just been reported.
  const gov = await governanceRepo.findForCommunity(ds, clubUuid);
  assert.equal(gov?.parentCommunityUuid, vtnUuid);
});

test('affiliate: a non-existent parent VTN is mapped to 404', async () => {
  const { app, clubUuid } = await seed();

  const res = await app.inject({
    method: 'PATCH',
    url: `/vtcs/${clubUuid}/affiliate`,
    payload: { parentCommunityUuid: generateUuid() },
  });

  assert.equal(res.statusCode, 404, `expected 404, got ${res.statusCode}: ${res.body}`);
});

test('affiliate: a parent that is not a VTN is mapped to 400', async () => {
  const { app, clubUuid, outsiderUuid } = await seed();

  const res = await app.inject({
    method: 'PATCH',
    url: `/vtcs/${clubUuid}/affiliate`,
    payload: { parentCommunityUuid: outsiderUuid },
  });

  assert.equal(res.statusCode, 400, `expected 400, got ${res.statusCode}: ${res.body}`);
});

// ── POST /vtcs/:uuid/unaffiliate ────────────────────────────────────────────

test('unaffiliate: an unaffiliated VTC is mapped to 400, not a crash', async () => {
  const { app, clubUuid } = await seed();

  const res = await app.inject({ method: 'POST', url: `/vtcs/${clubUuid}/unaffiliate` });

  assert.equal(res.statusCode, 400, `expected 400, got ${res.statusCode}: ${res.body}`);
});

test('unaffiliate: clears the parent and reports it', async () => {
  const { app, ds, clubUuid, vtnUuid } = await seed();

  const affiliated = await app.inject({
    method: 'PATCH',
    url: `/vtcs/${clubUuid}/affiliate`,
    payload: { parentCommunityUuid: vtnUuid },
  });
  assert.equal(affiliated.statusCode, 200, `setup affiliate failed: ${affiliated.body}`);

  const res = await app.inject({ method: 'POST', url: `/vtcs/${clubUuid}/unaffiliate` });

  assert.equal(res.statusCode, 200, `expected 200, got ${res.statusCode}: ${res.body}`);
  const body = res.json() as { childGovernance?: { parentCommunityUuid?: string | null } };
  assert.equal(body.childGovernance?.parentCommunityUuid, null, 'the response must report the cleared parent');
  assert.equal((await governanceRepo.findForCommunity(ds, clubUuid))?.parentCommunityUuid, null);
});

