// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Phase B follow-up — VTN governance routes (`/vtns/:uuid/governance[...]`).
 *
 * The utility server manages VTN rules but NEVER signs for a member admin, so these
 * routes only (a) show the VTN's rules + pending proposals and (b) PROPOSE a change —
 * both gated to VTN admins/founding_admins (session → membership role). Co-signatures
 * come from the admins' agent apps.
 *
 * Run:
 *   cd utility-server && node --experimental-strip-types --loader ../test-loader.mjs \
 *     --test test/routes/vtn-governance.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify, { type FastifyInstance } from 'fastify';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { TX_SCHEMA_SQL, applyTxSchemaAdditions } from '@p2p-trust-stack/core/tx/schema.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import * as governanceRepo from '@p2p-trust-stack/core/db/repositories/governance-repo.js';
import { seedDefaultBindings } from '@p2p-trust-stack/core/services/policy-bindings.js';
import { GovernanceChangeStore } from '@p2p-trust-stack/core/tx/governance-change-store.js';
import { registerVtnRoutes } from '../../src/routes/layer5-applications/vtns.js';
import { createSession, generateSessionSecret } from '../../src/session.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

async function seed(): Promise<{
  app: FastifyInstance; appDs: SqliteDataSource; txDb: SqliteDataSource;
  vtnUuid: string; adminCookie: string; outsiderCookie: string;
}> {
  const appDs = new SqliteDataSource(':memory:');
  runMigrations(appDs.getRawDb(), MIGRATIONS_DIR);
  const txDb = new SqliteDataSource(':memory:');
  await txDb.exec(TX_SCHEMA_SQL);
  await applyTxSchemaAdditions(txDb);

  const mk = async (did: string, role: 'vtc' | 'vtn' | 'vta', name: string) => {
    const uuid = generateUuid();
    await identitiesRepo.create(appDs, { uuid, realDid: did, role, name, recordedByNode: 'test' });
    await didDocumentsRepo.create(appDs, { identityUuid: uuid, did, method: 'did:scid:vh', isPrimary: true, recordedByNode: 'test' });
    return uuid;
  };

  const vtnUuid = await mk('did:scid:vh:chessNet', 'vtn', 'Chess Network');
  const adminUuid = await mk('did:scid:vh:netAdmin', 'vta', 'Net Admin');
  const outsiderUuid = await mk('did:scid:vh:outsider', 'vta', 'Outsider');
  await membershipsRepo.create(appDs, {
    memberIdentityUuid: adminUuid, communityIdentityUuid: vtnUuid, role: 'admin', status: 'active',
  });
  await governanceRepo.create(appDs, { communityIdentityUuid: vtnUuid, adminThresholdM: 1, adminThresholdN: 1 });
  await seedDefaultBindings(appDs, vtnUuid, 'vtn');

  const secret = generateSessionSecret();
  const app = Fastify();
  (app as unknown as { hmacSecret: Buffer }).hmacSecret = secret;
  (app as unknown as { txDb: SqliteDataSource }).txDb = txDb;
  registerVtnRoutes(app, appDs);
  await app.ready();

  return {
    app, appDs, txDb, vtnUuid,
    adminCookie: createSession(adminUuid, secret).cookie,
    outsiderCookie: createSession(outsiderUuid, secret).cookie,
  };
}

test('GET /vtns/:uuid/governance: no session → 401', async () => {
  const { app, vtnUuid } = await seed();
  const res = await app.inject({ method: 'GET', url: `/vtns/${vtnUuid}/governance` });
  assert.equal(res.statusCode, 401);
});

test('GET /vtns/:uuid/governance: a non-admin → 403', async () => {
  const { app, vtnUuid, outsiderCookie } = await seed();
  const res = await app.inject({ method: 'GET', url: `/vtns/${vtnUuid}/governance`, headers: { cookie: outsiderCookie } });
  assert.equal(res.statusCode, 403);
});

test('GET /vtns/:uuid/governance: an admin sees the rules', async () => {
  const { app, vtnUuid, adminCookie } = await seed();
  const res = await app.inject({ method: 'GET', url: `/vtns/${vtnUuid}/governance`, headers: { cookie: adminCookie } });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.equal(body.role, 'vtn');
  assert.equal(body.governance.adminThresholdM, 1);
  assert.deepEqual(body.pending, []);
});

test('POST /vtns/:uuid/governance/propose: an admin proposes; scope resolves to all admins', async () => {
  const { app, txDb, vtnUuid, adminCookie } = await seed();
  const res = await app.inject({
    method: 'POST', url: `/vtns/${vtnUuid}/governance/propose`,
    headers: { cookie: adminCookie, 'content-type': 'application/json' },
    payload: { change: { adminThresholdM: 2 }, scope: 'admins' },
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.equal(body.ok, true);
  assert.ok(body.proposalId);

  const stored = await new GovernanceChangeStore(txDb).getProposal(body.proposalId);
  assert.ok(stored, 'the proposal is stored server-side');
  assert.equal(stored!.scope, 'admins');
  assert.equal(stored!.requiredApproverCount, 1, 'a single-admin VTN requires one approval');
  assert.deepEqual(stored!.change, { adminThresholdM: 2 });
});

test('POST /vtns/:uuid/governance/propose: a non-admin → 403 and nothing is stored', async () => {
  const { app, txDb, vtnUuid, outsiderCookie } = await seed();
  const res = await app.inject({
    method: 'POST', url: `/vtns/${vtnUuid}/governance/propose`,
    headers: { cookie: outsiderCookie, 'content-type': 'application/json' },
    payload: { change: { adminThresholdM: 9 } },
  });
  assert.equal(res.statusCode, 403);
  const all = await txDb.all<{ proposal_id: string }>('SELECT proposal_id FROM governance_change_proposals');
  assert.equal(all.length, 0);
});
