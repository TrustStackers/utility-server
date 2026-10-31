// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `GET /auth/candidates` — the sign-in page's VTA picker, and the boundary around it.
 *
 * Why the route exists: the login page cannot have a session (obtaining one is its job),
 * and F-011 made `/identities` session-protected. A picker built on that read therefore
 * left the operator staring at `Failed: 401` with nothing to select — an identity UUID is
 * never shown to them anywhere. `GET /auth/candidates` is the narrow, deliberate
 * exception: human VTAs only, three fields only.
 *
 * These tests drive the **real auth plugin**, so both claims are tested against the gate
 * rather than asserted:
 *   - `/auth/candidates` answers WITHOUT a session (or sign-in is impossible);
 *   - `/identities` still refuses without one (the exception must not re-open the rest).
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ../test-loader.mjs --test test/routes/auth-candidates.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify, { type FastifyInstance } from 'fastify';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import { registerAuth } from '../../src/plugins/auth.js';
import { registerAuthRoutes } from '../../src/routes/layer3-tasks/auth.js';
import { registerIdentityRoutes } from '../../src/routes/layer1-infrastructure/identities.js';
import { registerConfigRoutes } from '../../src/routes/config-routes.js';
import { setNamespaceConfig } from '../../src/services/namespace-service.js';
import { createSession, generateSessionSecret } from '../../src/session.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

interface Harness { app: FastifyInstance; ds: SqliteDataSource; humanUuid: string; vtnUuid: string; cookie: string }

/**
 * Four identities, one per filter arm:
 *   - human VTA WITH an active endpoint → a real sign-in candidate;
 *   - human VTA WITHOUT one             → excluded (the TSP-bridge-fake rule);
 *   - organisation VTA (this server)    → excluded (not a human signer);
 *   - VTN                               → excluded (wrong role).
 */
async function harness(): Promise<Harness> {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);

  // `namespace_config` is the ONE table the server's schema has that the shared SQLite
  // schema deliberately omits — 0018_namespace_config.sql says so in its own header ("the
  // core src/db/ SQLite schema used by the agent-app intentionally does NOT include this
  // table, so the agent's local identity cache stays schema-version 19"), and the server's
  // dialect is YugabyteDB, so that file cannot be executed here. The fixture therefore
  // mirrors the authoritative definition in the SQLite dialect. If the real table changes,
  // the route-driven assertions below fail loudly on the column names.
  await ds.run(
    `CREATE TABLE IF NOT EXISTS namespace_config (
       uuid              TEXT PRIMARY KEY,
       vtn_identity_uuid TEXT NOT NULL UNIQUE,
       namespace         TEXT NOT NULL UNIQUE,
       created_at        INTEGER NOT NULL,
       updated_at        INTEGER NOT NULL
     )`,
  );

  const humanUuid = generateUuid();
  await identitiesRepo.create(ds, {
    uuid: humanUuid, realDid: 'did:scid:vh:1:zCandidateAlice', role: 'vta', subjectKind: 'human',
    custody: 'remote', name: 'alice', peerId: 'peer-alice', recordedByNode: 'test',
  });
  await identitiesRepo.create(ds, {
    uuid: generateUuid(), realDid: 'did:scid:vh:1:zCandidateNoEndpoint', role: 'vta', subjectKind: 'human',
    custody: 'remote', name: 'ghost', recordedByNode: 'test',
  });
  await identitiesRepo.create(ds, {
    uuid: generateUuid(), realDid: 'did:scid:vh:1:zServerVta', role: 'vta', subjectKind: 'organization',
    custody: 'local', name: 'utility-server', peerId: 'peer-server', recordedByNode: 'test',
  });
  const vtnUuid = generateUuid();
  await identitiesRepo.create(ds, {
    uuid: vtnUuid, realDid: 'did:scid:vh:1:zVtn', role: 'vtn', subjectKind: 'organization',
    custody: 'local', name: 'Trust Stackers', peerId: 'peer-vtn', recordedByNode: 'test',
  });

  const secret = generateSessionSecret();
  const app = Fastify();
  registerIdentityRoutes(app, ds); // the general listing — must stay protected
  registerAuthRoutes(app, ds);     // includes /auth/candidates
  registerConfigRoutes(app, ds);   // includes the public /namespace/status
  registerAuth(app, ds, secret);   // the real gate
  await app.ready();

  return { app, ds, humanUuid, vtnUuid, cookie: createSession(humanUuid, secret).cookie };
}

// ── the exception, and its boundary ─────────────────────────────────────────

test('candidates: 200 WITHOUT a session, listing only the real human VTA', async () => {
  const { app, ds, humanUuid } = await harness();
  try {
    const res = await app.inject({ method: 'GET', url: '/auth/candidates' });

    assert.equal(res.statusCode, 200, `the picker must be reachable pre-session: ${res.body}`);
    const body = res.json() as Array<{ uuid: string; name: string; did: string | null }>;
    assert.equal(body.length, 1, 'exactly one candidate should match every filter arm');
    assert.equal(body[0].uuid, humanUuid);
    assert.equal(body[0].name, 'alice');
  } finally {
    await app.close();
    await ds.close();
  }
});

test('candidates: exposes exactly uuid/name/did — nothing else about the node', async () => {
  const { app, ds } = await harness();
  try {
    const body = (await app.inject({ method: 'GET', url: '/auth/candidates' })).json() as Array<Record<string, unknown>>;
    assert.deepEqual(
      Object.keys(body[0]).sort(),
      ['did', 'name', 'uuid'],
      'the public picker must not leak custody, endpoints, timestamps or counts',
    );
  } finally {
    await app.close();
    await ds.close();
  }
});

test('the exception is narrow: /identities still refuses without a session', async () => {
  const { app, ds } = await harness();
  try {
    // These are the reads the picker used to make — and that F-011 RULED must be
    // authenticated, because they disclose how many identities exist.
    for (const url of ['/identities', '/identities?role=vta&subject_kind=human']) {
      const res = await app.inject({ method: 'GET', url });
      assert.equal(res.statusCode, 401, `${url} must stay protected (got ${res.statusCode})`);
    }
  } finally {
    await app.close();
    await ds.close();
  }
});

test('control: with a session the general listing answers (the gate is not blanket-refusing)', async () => {
  const { app, ds, cookie } = await harness();
  try {
    const res = await app.inject({
      method: 'GET', url: '/identities?role=vta&subject_kind=human',
      headers: { cookie: cookie.split(';')[0] },
    });
    assert.equal(res.statusCode, 200, `a live session must still read: ${res.body}`);
    assert.equal((res.json() as unknown[]).length, 1);
  } finally {
    await app.close();
    await ds.close();
  }
});

// ── the other exact-path exception: the node's published namespace ───────────

test('namespace/status: a public read, so the dashboard shows the namespace pre-sign-in', async () => {
  const { app, ds, vtnUuid } = await harness();
  try {
    await setNamespaceConfig(ds, { vtnIdentityUuid: vtnUuid, namespace: 'test.ns' });

    // No cookie: this is the state an operator is in right after setup + restart, and the
    // dashboard must show the configured namespace rather than claiming "not configured".
    const res = await app.inject({ method: 'GET', url: '/namespace/status' });

    assert.equal(res.statusCode, 200, `must be readable pre-session: ${res.body}`);
    assert.deepEqual(res.json(), { configured: true, namespace: 'test.ns', vtnUuid });
  } finally {
    await app.close();
    await ds.close();
  }
});

test('namespace/status: the same route file keeps its admin surface protected', async () => {
  const { app, ds } = await harness();
  try {
    // `/config` lives beside `/namespace/status` and is founder-admin gated: the
    // exact-path exception must not open the rest of that file.
    const res = await app.inject({ method: 'GET', url: '/config' });
    assert.equal(res.statusCode, 401, `admin config must stay protected (got ${res.statusCode})`);
  } finally {
    await app.close();
    await ds.close();
  }
});
