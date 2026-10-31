// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests for the operator connectivity route — `GET /health/connectivity` (H14).
 *
 * Why this route exists: the utility server is the component whose missing relay
 * reservation caused this project's outage class, and it had the least
 * visibility — diagnosing a NAT'd agent that could not reach it meant reading
 * logs. `ConnectivitySupervisor.getStatus()` held the state but had NO production
 * caller, so none of it was reachable.
 *
 * These tests pin the two behaviours that matter: the payload is the live snapshot
 * (not a placeholder), and a process WITHOUT a supervisor says so (503) instead of
 * reporting an empty object as if everything were fine.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ../test-loader.mjs --test test/routes/health-connectivity.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import { registerHealthRoute } from '../../src/routes/health.js';
import type { SupervisorStatus } from '../../src/services/connectivity-supervisor.js';

/** A realistic snapshot: one member stuck, one connected, no relay advertised. */
const STATUS: SupervisorStatus = {
  running: true,
  bootstrapConnected: true,
  relayLabel: 'reservation held',
  membersInBackoff: 1,
  bootstrap: { consecutiveFailures: 0, nextAttemptInMs: 0 },
  relay: {
    reservationHeld: true,
    advertisedAddr: '/dns/relay/tcp/4001/p2p/12D3KooWRELAY/p2p-circuit',
    consecutiveFailures: 0,
    nextAttemptInMs: 0,
  },
  members: [
    {
      peerId: '12D3KooWSTUCK',
      label: 'stuck-agent',
      inBackoff: true,
      nextAttemptInMs: 4_000,
      consecutiveFailures: 2,
      lastResult: { ok: false, at: 1_700_000_000_000, detail: 'no dialable addresses' },
    },
  ],
};

test('GET /health/connectivity returns the supervisor snapshot verbatim', async () => {
  const app = Fastify();
  registerHealthRoute(app, { getConnectivityStatus: () => STATUS });

  const res = await app.inject({ method: 'GET', url: '/health/connectivity' });

  assert.equal(res.statusCode, 200);
  const body = res.json() as { status: string; service: string; connectivity: SupervisorStatus };
  assert.equal(body.status, 'ok');
  assert.equal(body.service, 'utility-server');
  assert.deepEqual(body.connectivity, STATUS, 'the route must not reshape or drop the snapshot');
  // The two fields an operator needs mid-outage, called out explicitly so a
  // future refactor cannot quietly degrade this to a count again.
  assert.equal(body.connectivity.relay.reservationHeld, true);
  assert.equal(body.connectivity.members[0].lastResult?.detail, 'no dialable addresses');

  await app.close();
});

test('GET /health/connectivity answers 503 when no supervisor is running', async () => {
  const app = Fastify();
  registerHealthRoute(app); // no deps — e.g. a build without relay recovery

  const res = await app.inject({ method: 'GET', url: '/health/connectivity' });

  assert.equal(res.statusCode, 503);
  assert.match(
    (res.json() as { error: { message: string } }).error.message,
    /connectivity supervisor is not running/,
  );

  await app.close();
});

test('GET /health still answers without a supervisor (no regression)', async () => {
  const app = Fastify();
  registerHealthRoute(app);

  const res = await app.inject({ method: 'GET', url: '/health' });

  assert.equal(res.statusCode, 200);
  assert.equal((res.json() as { status: string }).status, 'ok');

  await app.close();
});
