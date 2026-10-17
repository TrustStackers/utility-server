// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * F-019 / ruling R3-b — revocable-but-stateless sessions, tested at the GATE.
 *
 * The defect this closes: a session token was valid until its `expiresAt` and nothing
 * could end it early. `POST /auth/logout` only deleted the browser's cookie, so a
 * copied token kept full write access for the rest of its 8-hour life, and there was no
 * way to terminate one session — only rotating the global secret, which signs out
 * everyone.
 *
 * R3-b adds the *minimum* state that makes termination real:
 *   - a per-session id in the token → `revokeSession()` kills one session;
 *   - an `issuedAt` + a per-identity cutoff → `revokeAllBefore()` kills every session
 *     issued before a moment, including ones never recorded.
 *
 * These tests drive the REAL auth plugin over a real (in-memory) database, because the
 * claim being tested is "the gate refuses a terminated session" — not "a helper returns
 * a boolean". A store-only test would pass even if the plugin never consulted it.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs --test test/services/session-revocation.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import { registerAuth } from '../../src/plugins/auth.js';
import { createSession, generateSessionSecret } from '../../src/session.js';
import { revokeSession, revokeAllBefore, isRevoked, pruneExpired } from '../../src/session-store.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

/** A VTA identity (the gate requires role='vta') plus a secret and a ready app. */
async function harness() {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);

  const identityUuid = generateUuid();
  await identitiesRepo.create(ds, {
    uuid: identityUuid, realDid: 'did:scid:vh:1:zSessionVta', role: 'vta', subjectKind: 'human',
    custody: 'local', name: 'session-test-vta', recordedByNode: 'test',
  });

  const secret = generateSessionSecret();
  const app = Fastify();
  // A write route behind the gate — the thing a stolen cookie could reach.
  app.post('/protected', async () => ({ ok: true }));
  registerAuth(app, ds, secret);
  await app.ready();

  return { ds, app, secret, identityUuid };
}

function cookieHeader(token: string): string {
  return `p2pts_session=${token}`;
}

/** Status of a POST to the protected route with the given token. */
async function postWith(app: Awaited<ReturnType<typeof harness>>['app'], token: string): Promise<number> {
  const res = await app.inject({ method: 'POST', url: '/protected', headers: { cookie: cookieHeader(token) } });
  return res.statusCode;
}

test('a fresh session passes the gate (control — the gate is not refusing everything)', async () => {
  const h = await harness();
  const { token } = createSession(h.identityUuid, h.secret);

  assert.equal(await postWith(h.app, token), 200, 'a live session must work');

  await h.app.close();
  await h.ds.close();
});

test('R3-b: after revokeSession the SAME valid token is refused (the logout that never was)', async () => {
  const h = await harness();
  const session = createSession(h.identityUuid, h.secret);

  // The token is cryptographically valid and unexpired…
  assert.equal(await postWith(h.app, session.token), 200);

  // …then the session is terminated, exactly as POST /auth/logout now does.
  await revokeSession(h.ds, {
    sessionId: session.sessionId,
    identityUuid: h.identityUuid,
    expiresAt: session.expiresAt,
  });

  const after = await h.app.inject({
    method: 'POST', url: '/protected', headers: { cookie: cookieHeader(session.token) },
  });
  assert.equal(after.statusCode, 401, 'a terminated session must not survive on a copied cookie');
  assert.equal(after.json().reason, 'session_terminated');

  await h.app.close();
  await h.ds.close();
});

test('R3-b: revoke-all retires sessions issued earlier — and legacy v1 tokens too', async () => {
  const h = await harness();
  const past = Math.floor(Date.now() / 1000) - 600;
  const oldSession = createSession(h.identityUuid, h.secret, { issuedAt: past });
  assert.equal(await postWith(h.app, oldSession.token), 200);

  const cutoff = Math.floor(Date.now() / 1000);
  const { revokedBefore } = await revokeAllBefore(h.ds, h.identityUuid, cutoff);
  assert.equal(revokedBefore, cutoff);

  const after = await h.app.inject({
    method: 'POST', url: '/protected', headers: { cookie: cookieHeader(oldSession.token) },
  });
  assert.equal(after.statusCode, 401);
  assert.equal(after.json().reason, 'revoked_by_logout_all');

  await h.app.close();
  await h.ds.close();
});

test('R3-b: a revoke-all is SCOPED to its identity (it must not sign out the world)', async () => {
  const h = await harness();
  const other = generateUuid();
  await identitiesRepo.create(h.ds, {
    uuid: other, realDid: 'did:scid:vh:1:zOtherVta', role: 'vta', subjectKind: 'human',
    custody: 'local', name: 'other-vta', recordedByNode: 'test',
  });

  const mine = createSession(h.identityUuid, h.secret);
  // The other identity's session is issued BEFORE the cutoff below and is still well
  // inside its TTL. If the cutoff were applied globally rather than per identity, this
  // session would be killed and this assertion would fail — that is what it catches.
  const cutoff = Math.floor(Date.now() / 1000);
  const theirs = createSession(other, h.secret, { sessionId: 'other-session-id', issuedAt: cutoff - 600 });

  await revokeAllBefore(h.ds, h.identityUuid, cutoff);

  assert.equal(await postWith(h.app, theirs.token), 200, 'another identity must be unaffected');
  assert.equal(await postWith(h.app, mine.token), 401, 'mine is terminated');

  await h.app.close();
  await h.ds.close();
});

test('R3-b: the revocation list stays BOUNDED — expired rows are pruned', async () => {
  const h = await harness();
  const now = Math.floor(Date.now() / 1000);

  // One session already past its expiry when revoked, one still live.
  await revokeSession(h.ds, { sessionId: 'dead-already', identityUuid: h.identityUuid, expiresAt: now - 10, now });
  await revokeSession(h.ds, { sessionId: 'still-live', identityUuid: h.identityUuid, expiresAt: now + 3600, now });

  const rows = await h.ds.all<{ session_id: string }>('SELECT session_id FROM revoked_sessions ORDER BY session_id');
  assert.deepEqual(
    rows.map((r) => r.session_id), ['still-live'],
    'a row whose token can no longer validate proves nothing and is dropped',
  );
  assert.equal(await isRevoked(h.ds, 'still-live'), true);
  assert.equal(await pruneExpired(h.ds, now), 0, 'pruning is idempotent');

  await h.app.close();
  await h.ds.close();
});
