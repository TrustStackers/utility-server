// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * F-011 / ruling Y4 — the read surface is no longer blanket-open.
 *
 * The finding: *"existence of identities, documents and credentials is disclosed to
 * unauthenticated callers."* The gate made it total — it was
 * `if (req.method === 'GET' || isPublicPath(url)) return;`, so **every** read was
 * unauthenticated: counts, known DIDs, held credentials, and (via 404-vs-200) whether a
 * given identifier exists at all.
 *
 * These tests drive the REAL plugin over an in-memory database, because the claim is
 * about what the gate does — not about a helper's return value.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ../test-loader.mjs --test test/services/read-auth.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Fastify from 'fastify';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import { registerAuth, resolveReadAuthPolicy, READ_AUTH_POLICY_ENV } from '../../src/plugins/auth.js';
import { registerHealthRoute } from '../../src/routes/health.js';
import { shouldStoreUnrecognisedProtocol, describeUnrecognisedProtocolRefusal } from '../../src/node/protocol-rejection.js';
import { createSession, generateSessionSecret } from '../../src/session.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

async function harness(policy?: string) {
  // Pin an UNCONFIGURED data dir. `/setup/*` is public only before first-run
  // provisioning completes (F-06/SYN-014), so the Y4 setup assertions below need an
  // unconfigured instance — and this keeps the suite hermetic instead of reading the
  // developer's real data/config.json.
  const prevDataDir = process.env.UTILITY_DATA_DIR;
  process.env.UTILITY_DATA_DIR = mkdtempSync(join(tmpdir(), 'p2pts-read-auth-'));

  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);

  const identityUuid = generateUuid();
  await identitiesRepo.create(ds, {
    uuid: identityUuid, realDid: 'did:scid:vh:1:zReadAuthVta', role: 'vta', subjectKind: 'human',
    custody: 'local', name: 'read-auth-vta', recordedByNode: 'test',
  });

  const secret = generateSessionSecret();
  const app = Fastify();
  // A disclosure route of the kind F-011 names: it answers 404-vs-200 per identifier.
  app.get('/did-documents/:uuid', async (req) => {
    const row = await identitiesRepo.findByUuid(ds, (req.params as { uuid: string }).uuid);
    return row ? { found: true } : { found: false };
  });
  app.post('/protected', async () => ({ ok: true }));
  // The REAL liveness/state pair, so the /health assertions below are about the
  // deployed routes rather than about 404s from an unregistered path.
  registerHealthRoute(app);
  registerAuth(app, ds, secret);
  await app.ready();

  const prev = process.env[READ_AUTH_POLICY_ENV];
  if (policy === undefined) delete process.env[READ_AUTH_POLICY_ENV];
  else process.env[READ_AUTH_POLICY_ENV] = policy;

  return {
    ds, app, identityUuid, secret,
    restore: () => {
      if (prev === undefined) delete process.env[READ_AUTH_POLICY_ENV];
      else process.env[READ_AUTH_POLICY_ENV] = prev;
      if (prevDataDir === undefined) delete process.env.UTILITY_DATA_DIR;
      else process.env.UTILITY_DATA_DIR = prevDataDir;
    },
  };
}

test('Y4: an unauthenticated READ of a disclosure route is refused (default enforce)', async () => {
  const h = await harness();
  try {
    const res = await h.app.inject({ method: 'GET', url: `/did-documents/${h.identityUuid}` });
    assert.equal(res.statusCode, 401, 'existence must not be disclosed to an unauthenticated caller');
    assert.equal(res.json().found, undefined, 'and no existence signal leaks in the body');
  } finally {
    h.restore();
    await h.app.close();
    await h.ds.close();
  }
});

test('Y4: with a live session the same read succeeds (the gate is not refusing everything)', async () => {
  const h = await harness();
  try {
    const { token } = createSession(h.identityUuid, h.secret);
    const res = await h.app.inject({
      method: 'GET', url: `/did-documents/${h.identityUuid}`, headers: { cookie: `p2pts_session=${token}` },
    });
    assert.equal(res.statusCode, 200, res.body);
    assert.equal(res.json().found, true);
  } finally {
    h.restore();
    await h.app.close();
    await h.ds.close();
  }
});

test('Y4: the login page, its assets and first-run setup stay reachable without a session', async () => {
  const h = await harness();
  try {
    // These must NOT be refused, or an operator could never obtain a session — the 401
    // would be a permanent lockout, which is the failure mode worth testing for.
    for (const url of ['/auth/status', '/ui/login.html', '/ui/app.js', '/setup/state', '/favicon.ico',
                       // The sign-in picker: without it the operator has no identity to select,
                        // since a UUID is never shown to them (see auth-candidates.test.ts).
                       '/auth/candidates',
                       // The node's published network name — how an agent discovers which
                       // namespace to register names against. Not this node's private data.
                       '/namespace/status',
                       // The liveness probe: `{status, service, time}`, nothing about this
                       // node's data. A probe that needs a session cannot be used by an
                       // orchestrator, a load balancer, or `curl` — which is its whole purpose.
                       // F-011 moved the hook to an allow-list without naming it, so it started
                       // answering 401. Pinned here; the gated sibling is tested separately.
                       '/health']) {
      const res = await h.app.inject({ method: 'GET', url });
      assert.notEqual(res.statusCode, 401, `${url} must remain public (got ${res.statusCode})`);
    }
  } finally {
    h.restore();
    await h.app.close();
    await h.ds.close();
  }
});

test('Y4: /health is public but /health/connectivity is NOT (the disclosure boundary)', async () => {
  const h = await harness();
  try {
    // The liveness/state pair is the whole point: one is a probe, the other is an
    // operator audit of this node's members and peers. Adding `/health` to the
    // allow-list must not drag `/health/connectivity` along with it — which is exactly
    // why the allow-list matches EXACT paths rather than prefixes.
    const liveness = await h.app.inject({ method: 'GET', url: '/health' });
    assert.equal(liveness.statusCode, 200, 'the liveness probe must answer');
    assert.deepEqual(
      Object.keys(liveness.json()).sort(),
      ['service', 'status', 'time'],
      'the liveness probe must disclose nothing beyond status/service/time',
    );

    const connectivity = await h.app.inject({ method: 'GET', url: '/health/connectivity' });
    assert.equal(
      connectivity.statusCode,
      401,
      "/health/connectivity reports this node's state and must stay gated",
    );
  } finally {
    h.restore();
    await h.app.close();
    await h.ds.close();
  }
});

test('Y4: the rollout valve — warn reports and allows, off restores the old behaviour', async () => {
  // warn: a read that WOULD be refused is allowed, so an operator can find consumers first.
  const warned = await harness('warn');
  try {
    const res = await warned.app.inject({ method: 'GET', url: `/did-documents/${warned.identityUuid}` });
    assert.equal(res.statusCode, 200, 'warn must not block');
  } finally {
    warned.restore();
    await warned.app.close();
    await warned.ds.close();
  }

  // off: pre-F-011 behaviour, for an operator mid-migration.
  const off = await harness('off');
  try {
    const res = await off.app.inject({ method: 'GET', url: `/did-documents/${off.identityUuid}` });
    assert.equal(res.statusCode, 200);
  } finally {
    off.restore();
    await off.app.close();
    await off.ds.close();
  }

  // A typo must never silently disable the protection: unknown → enforce.
  assert.equal(resolveReadAuthPolicy('nonsense'), 'enforce');
  assert.equal(resolveReadAuthPolicy(undefined), 'enforce');
  assert.equal(resolveReadAuthPolicy(' warn '), 'warn');
});

test('Y5-reject: an unrecognised protocol message is never stored', () => {
  // Pinned here because the call site sits behind libp2p and cannot be driven from a unit
  // test: this predicate is the seam that keeps the refusal explicit and revert-proof.
  for (const protocol of ['acme_custom_op', 'tx_', 'name_register_v2', '']) {
    assert.equal(
      shouldStoreUnrecognisedProtocol(protocol), false,
      `"${protocol}" must not be stored — an unrecognised protocol is a statement about the sender`,
    );
  }

  // And the refusal names the protocol, the sender and the size, so an operator can act.
  const line = describeUnrecognisedProtocolRefusal('acme_custom_op', {
    fromDidDocumentUuid: 'abcdefgh-1234', bodyLength: 42,
  });
  assert.match(line, /acme_custom_op/);
  assert.match(line, /doc=abcdefgh/);
  assert.match(line, /len=42/);
  assert.match(line, /not stored/);
});

