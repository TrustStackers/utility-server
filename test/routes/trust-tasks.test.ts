/**
 * Route-level tests for the Trust Task bridge (`POST /trust-tasks`, P5.5).
 *
 * Pins the bridge's contract against a live app + DB:
 *
 *  1. **An inbound envelope is parsed, routed by its `task:p2pts:…` type, dispatched,
 *     and wrapped back into a `#response`** (threadId echoed, issuer/recipient swapped).
 *  2. **Unknown / malformed / response documents are refused** with a distinct code.
 *  3. **A proof whose issuer is not transport-authenticated is INDETERMINATE** —
 *     401 `proof/unattributable`, never silently allowed. The crypto of the proof is
 *     NOT checked here (crypto lives in the guard); only the session binding is.
 *  4. **`upsert` persists and `validate`/`evaluate`/`test` do not** (read the row back).
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs --test test/routes/trust-tasks.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify, { type FastifyInstance } from 'fastify';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import * as governanceRepo from '@p2p-trust-stack/core/db/repositories/governance-repo.js';
import { seedDefaultBindings } from '@p2p-trust-stack/core/services/policy-bindings.js';
import { POLICY_EVALUATE_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/index.js';
import {
  CEREMONY_PROPOSE_TYPE,
  CEREMONY_CO_SIGN_TYPE,
} from '@p2p-trust-stack/core/services/trust-tasks/type-uris.js';
import { registerTrustTaskRoutes } from '../../src/routes/layer3-tasks/trust-tasks.js';
import { createSession, generateSessionSecret } from '../../src/session.js';
import * as trustTasksRepo from '@p2p-trust-stack/core/db/repositories/trust-tasks-repo.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();
const CLUB_DID = 'did:scid:vh:club';
const ADMIN_DID = 'did:scid:vh:admin';

async function seed(): Promise<{ app: FastifyInstance; ds: SqliteDataSource; clubUuid: string; adminUuid: string; secret: Buffer; adminCookie: string }> {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);

  const mk = async (did: string, role: 'vtc' | 'vtn' | 'vta', name: string) => {
    const uuid = generateUuid();
    await identitiesRepo.create(ds, { uuid, realDid: did, role, name, recordedByNode: 'test' });
    await didDocumentsRepo.create(ds, { identityUuid: uuid, did, method: 'did:scid:vh', isPrimary: true, recordedByNode: 'test' });
    return uuid;
  };

  const clubUuid = await mk(CLUB_DID, 'vtc', 'Chess Club');
  const adminUuid = await mk(ADMIN_DID, 'vta', 'Admin');
  await membershipsRepo.create(ds, { memberIdentityUuid: adminUuid, communityIdentityUuid: clubUuid, role: 'founding_admin', status: 'active' });
  await governanceRepo.create(ds, { communityIdentityUuid: clubUuid, adminThresholdM: 2, adminThresholdN: 3 });
  await seedDefaultBindings(ds, clubUuid, 'vtc');

  const secret = generateSessionSecret();
  const app = Fastify();
  (app as unknown as { hmacSecret: Buffer }).hmacSecret = secret;
  registerTrustTaskRoutes(app, ds);
  await app.ready();

  const adminCookie = createSession(adminUuid, secret).cookie;
  return { app, ds, clubUuid, adminUuid, secret, adminCookie };
}

function env(type: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'doc-1',
    type,
    threadId: 'thread-1',
    issuer: ADMIN_DID,
    recipient: CLUB_DID,
    issuedAt: new Date().toISOString(),
    payload: {},
    ...over,
  };
}

async function post(app: FastifyInstance, body: unknown, cookie?: string) {
  return app.inject({
    method: 'POST',
    url: '/trust-tasks',
    headers: { ...(cookie ? { cookie } : {}) },
    payload: body as object,
  });
}

// ── routing + envelope ──────────────────────────────────────────────────────

test('evaluate: routes by type and wraps the decision in a #response', async () => {
  const { app } = await seed();
  const res = await post(app, env(POLICY_EVALUATE_TYPE, { payload: { action: 'register_name' } }));
  assert.equal(res.statusCode, 200);
  const doc = res.json();
  assert.equal(doc.type, `${POLICY_EVALUATE_TYPE}#response`);
  assert.equal(doc.threadId, 'thread-1');
  assert.equal(doc.issuer, CLUB_DID); // swapped
  assert.equal(doc.recipient, ADMIN_DID);
  assert.equal(doc.payload.query.action, 'register_name');
  assert.equal(typeof doc.payload.result.allowed, 'boolean');
});

test('unknown task type is refused with endpointNotFound', async () => {
  const { app } = await seed();
  const res = await post(app, env('task:p2pts:unknown:foo:0.1', { payload: {} }));
  assert.equal(res.statusCode, 404);
  assert.equal(res.json().payload.code, 'endpointNotFound');
});

test('a malformed envelope (missing id) is rejected with malformedRequest', async () => {
  const { app } = await seed();
  const res = await post(app, { type: POLICY_EVALUATE_TYPE, payload: {} });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().payload.code, 'malformedRequest');
});

test('a #response document is refused as not-a-request', async () => {
  const { app } = await seed();
  const res = await post(app, env(`${POLICY_EVALUATE_TYPE}#response`, { payload: {} }));
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().payload.code, 'malformedRequest');
});

// ── proof / transport attribution ───────────────────────────────────────────

test('a proof with no authenticated issuer is INDETERMINATE (401, never allow)', async () => {
  const { app } = await seed();
  const res = await post(app, env(POLICY_EVALUATE_TYPE, {
    payload: { action: 'register_name' },
    proof: { type: 'Ed25519Signature2020' },
  }));
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().payload.code, 'proof/unattributable');
});

test('a proof whose issuer IS the session identity is accepted', async () => {
  const { app, adminCookie } = await seed();
  const res = await post(app, env(POLICY_EVALUATE_TYPE, {
    payload: { action: 'register_name' },
    proof: { type: 'Ed25519Signature2020' },
  }), adminCookie);
  assert.equal(res.statusCode, 200);
  assert.equal(typeof res.json().payload.result.allowed, 'boolean');
});

// ── operations ──────────────────────────────────────────────────────────────

// The document-writing ops (validate/test/upsert) were the utility server's developer
// policy API and are removed — a document op is now refused as endpointNotFound.
test('a document-write op (upsert) is no longer routed', async () => {
  const { app } = await seed();
  const res = await post(app, env('task:p2pts:policy:upsert:0.1', { payload: { policy: {} } }));
  assert.equal(res.statusCode, 404);
  assert.equal(res.json().payload.code, 'endpointNotFound');
});

test('GET /trust-tasks/:threadId returns the recorded ceremony thread in order', async () => {
  const { app, ds } = await seed();
  await trustTasksRepo.record(ds, {
    uuid: 'doc-req',
    threadId: 'thread-9',
    type: 'task:p2pts:vtc:establish:0.1',
    direction: 'request',
    payload: { name: 'Chess Club' },
  });
  await trustTasksRepo.record(ds, {
    uuid: 'doc-res',
    threadId: 'thread-9',
    type: 'task:p2pts:vtc:establish:0.1',
    direction: 'response',
    recipientDid: CLUB_DID,
    payload: { communityUuid: 'club-uuid' },
    status: 'crystallized',
  });

  const res = await app.inject({ method: 'GET', url: '/trust-tasks/thread-9' });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.equal(body.threadId, 'thread-9');
  assert.equal(body.tasks.length, 2);
  assert.equal(body.tasks[0].direction, 'request');
  assert.equal(body.tasks[1].status, 'crystallized');
  assert.deepEqual(body.tasks[1].payload, { communityUuid: 'club-uuid' });
});

test('GET /trust-tasks/:threadId returns an empty list for an unknown thread', async () => {
  const { app } = await seed();
  const res = await app.inject({ method: 'GET', url: '/trust-tasks/nope' });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.json().tasks, []);
});

test('GET /trust-tasks/threads indexes ceremonies and names them from their steps', async () => {
  const { app, ds } = await seed();

  // A founding ceremony: its PROPOSAL and CO-SIGNATURE coordination events name it
  // (neither is a catalog step).
  await trustTasksRepo.record(ds, {
    uuid: generateUuid(), threadId: 'thread-founding',
    type: CEREMONY_PROPOSE_TYPE, direction: 'request',
    payload: { name: 'Chess Club' },
  });
  await trustTasksRepo.record(ds, {
    uuid: generateUuid(), threadId: 'thread-founding',
    type: CEREMONY_CO_SIGN_TYPE, direction: 'response', status: 'allowed',
    payload: { coSignaturesReceived: 1, coSignaturesRequired: 2 },
  });
  // A member onboarding: no coordination events, named by its catalog step.
  await trustTasksRepo.record(ds, {
    uuid: generateUuid(), threadId: 'thread-onboard',
    type: 'task:p2pts:credential:onboarding-vmc:0.1', direction: 'response',
    status: 'completed', payload: { result: { credentialUuid: 'cred-1' } },
  });

  const res = await app.inject({ method: 'GET', url: '/trust-tasks/threads' });
  assert.equal(res.statusCode, 200);
  const threads = res.json().threads as Array<Record<string, unknown>>;
  const byId: Record<string, Record<string, unknown>> = {};
  for (const thread of threads) byId[thread.threadId as string] = thread;

  assert.equal(byId['thread-founding'].ceremony, 'vtc-establish');
  assert.equal(byId['thread-founding'].documentCount, 2);
  assert.deepEqual((byId['thread-founding'].statuses as string[]).sort(), ['allowed', 'recorded']);

  assert.equal(byId['thread-onboard'].ceremony, 'member-onboarding');
  assert.equal(byId['thread-onboard'].documentCount, 1);
  assert.deepEqual(byId['thread-onboard'].types, ['task:p2pts:credential:onboarding-vmc:0.1']);

  // The wording travels with the data: the thread carries the ceremony's own title and
  // description, and each step carries its catalog label + sentences. This is what lets
  // the agent app and this server share one UI with no label table of their own.
  assert.equal(byId['thread-onboard'].ceremonyLabel, 'Onboard a member');
  assert.ok(byId['thread-onboard'].ceremonyDescription);

  const threadRes = await app.inject({ method: 'GET', url: '/trust-tasks/thread-onboard' });
  assert.equal(threadRes.statusCode, 200);
  const task = (threadRes.json().tasks as Array<Record<string, any>>)[0];
  assert.equal(task.display.label, 'Issue the membership credential');
  assert.match(String(task.display.response), /Membership credential issued/);
});

test('the static /trust-tasks/threads route is not shadowed by /trust-tasks/:threadId', async () => {
  const { app } = await seed();
  const res = await app.inject({ method: 'GET', url: '/trust-tasks/threads' });
  assert.equal(res.statusCode, 200);
  assert.ok(Array.isArray(res.json().threads), 'the index must win over the param route');
});
