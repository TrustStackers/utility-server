// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests: setup-routes — first-launch wizard (login path) + setup guard.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Fastify from 'fastify';

import { registerSetupRoutes } from '../../src/setup/setup-routes.js';
import { requireSetup } from '../../src/setup/setup-guard.js';
import { registerAuth } from '../../src/plugins/auth.js';
import { isConfigured, loadSetupConfig } from '../../src/setup/setup-state.js';
import { createNamespaceVtn } from '../../src/setup/setup-service.js';
import { getNamespaceConfig } from '../../src/services/namespace-service.js';
import { onShutdownRequested } from '../../src/services/shutdown.js';
import { makeTestDb, seedLocalVtaDb, seedRealVta } from './helpers.js';

/** Write a minimal configured setup block so `isConfigured()` returns true. */
function markConfigured(dir: string): void {
  writeFileSync(join(dir, 'config.json'), JSON.stringify({ setup: { configured: true } }));
}

function tempDataDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'p2pts-setup-routes-'));
  process.env.UTILITY_DATA_DIR = dir;
  return dir;
}

test('setup wizard happy path: network + login with existing VTA + create VTN + confirm', async () => {
  const ds = makeTestDb();
  const app = Fastify();
  registerSetupRoutes(app, { getDb: () => ds });
  tempDataDir();
  const home = mkdtempSync(join(tmpdir(), 'p2pts-vta-routes-'));
  process.env.P2PTS_HOME = home;
  try {
    await seedLocalVtaDb(home, { uuid: 'vta-x', did: 'did:scid:vh:vta-x', name: 'alice' });

    // Reset the shared wizard state before each run.
    await app.inject({ method: 'POST', url: '/setup/reset' });

    // Candidates endpoint finds the existing local VTA (no forced creation).
    const cand = await app.inject({ method: 'GET', url: '/setup/candidates' });
    assert.equal(cand.statusCode, 200, cand.body);
    const scan = cand.json();
    assert.equal(scan.localDbExists, true);
    assert.equal(scan.vtas[0].did, 'did:scid:vh:vta-x');

    let r = await app.inject({
      method: 'POST', url: '/setup/network',
      payload: { advertisedHost: '203.0.113.5', httpPort: 8790, libp2pPort: 4005 },
    });
    assert.equal(r.statusCode, 200, r.body);

    r = await app.inject({ method: 'POST', url: '/setup/identity', payload: { action: 'login', did: 'did:scid:vh:vta-x', passphrase: 'test-passphrase' } });
    assert.equal(r.statusCode, 200, r.body);
    assert.equal(r.json().founder.did, 'did:scid:vh:vta-x');

    r = await app.inject({
      method: 'POST', url: '/setup/vtn',
      payload: { action: 'create', name: 'My Net', namespace: 'p2pts.mainnet' },
    });
    assert.equal(r.statusCode, 200, r.body);
    assert.equal(r.json().vtn.namespace, 'p2pts.mainnet');

    r = await app.inject({ method: 'POST', url: '/setup/confirm' });
    assert.equal(r.statusCode, 200, r.body);
    assert.equal(r.json().ok, true);

    assert.equal(isConfigured(), true);
    const cfg = loadSetupConfig();
    assert.equal(cfg.namespace, 'p2pts.mainnet');
    assert.equal(cfg.network.advertisedHost, '203.0.113.5');
    assert.equal(cfg.network.httpPort, 8790);
  } finally {
    await app.close();
    await ds.close();
    delete process.env.UTILITY_DATA_DIR;
    delete process.env.P2PTS_HOME;
  }
});

test('setup wizard rejects confirm before identity', async () => {
  const ds = makeTestDb();
  const app = Fastify();
  registerSetupRoutes(app, { getDb: () => ds });
  tempDataDir();
  try {
    await app.inject({ method: 'POST', url: '/setup/reset' });
    const r = await app.inject({ method: 'POST', url: '/setup/confirm' });
    assert.equal(r.statusCode, 400);
  } finally {
    await app.close();
    await ds.close();
    delete process.env.UTILITY_DATA_DIR;
  }
});

test('auth plugin permits /setup/* POSTs without a session (wizard), but still guards other writes', async () => {
  const ds = makeTestDb();
  const app = Fastify();
  registerAuth(app, ds, Buffer.alloc(32, 1));
  app.post('/setup/network', async () => ({ ok: true }));
  app.post('/identities', async () => ({ ok: true }));
  // Unconfigured instance: the wizard paths are public. The exemption is withdrawn
  // once the instance is configured — see the F-06/SYN-014 test below.
  tempDataDir();
  try {
    const setup = await app.inject({ method: 'POST', url: '/setup/network', payload: {} });
    assert.equal(setup.statusCode, 200, setup.body);

    const guarded = await app.inject({ method: 'POST', url: '/identities', payload: {} });
    assert.equal(guarded.statusCode, 401, guarded.body);
  } finally {
    await app.close();
    await ds.close();
    delete process.env.UTILITY_DATA_DIR;
  }
});

test('setup guard redirects unconfigured browser requests to the wizard', async () => {
  tempDataDir();
  const app = Fastify();
  app.get('/ui/index.html', async () => 'dashboard');
  app.post('/identities', async () => ({ ok: true }));
  app.addHook('onRequest', requireSetup);
  try {
    const page = await app.inject({ method: 'GET', url: '/ui/index.html' });
    assert.equal(page.statusCode, 302);
    assert.equal(page.headers.location, '/ui/setup.html');

    const api = await app.inject({ method: 'POST', url: '/identities', payload: {} });
    assert.equal(api.statusCode, 503);

    // Setup + auth + health stays reachable.
    const setup = await app.inject({ method: 'GET', url: '/setup/state' });
    assert.notEqual(setup.statusCode, 302);
  } finally {
    await app.close();
    delete process.env.UTILITY_DATA_DIR;
  }
});

// ── F-06 / SYN-014: setup access closes in the completing process ──────

test('setup actions are denied in the same process once configured, and the process self-terminates', async () => {
  const ds = makeTestDb();
  const app = Fastify();
  registerSetupRoutes(app, { getDb: () => ds });
  tempDataDir();
  const home = mkdtempSync(join(tmpdir(), 'p2pts-vta-routes-'));
  process.env.P2PTS_HOME = home;

  const shutdowns: string[] = [];
  onShutdownRequested((reason) => shutdowns.push(reason));

  try {
    await seedLocalVtaDb(home, { uuid: 'vta-x', did: 'did:scid:vh:vta-x', name: 'alice' });

    // Complete the wizard (mode defaults to vtn_host; identity + confirm suffice).
    let r = await app.inject({ method: 'POST', url: '/setup/reset' });
    assert.equal(r.statusCode, 200, r.body);
    r = await app.inject({
      method: 'POST', url: '/setup/identity',
      payload: { action: 'login', did: 'did:scid:vh:vta-x', passphrase: 'test-passphrase' },
    });
    assert.equal(r.statusCode, 200, r.body);
    r = await app.inject({ method: 'POST', url: '/setup/confirm' });
    assert.equal(r.statusCode, 200, r.body);
    assert.equal(isConfigured(), true);

    // The setup process asks to shut down once the confirm response is flushed.
    await new Promise((res) => setImmediate(res));
    assert.deepEqual(shutdowns, ['setup-complete']);

    // Every setup action is denied in THIS process — mutations and reads alike.
    const attempts: Array<{ method: 'GET' | 'POST'; url: string; payload?: object }> = [
      { method: 'POST', url: '/setup/mode', payload: { mode: 'vtn_host' } },
      { method: 'POST', url: '/setup/network', payload: { advertisedHost: '10.0.0.1' } },
      { method: 'POST', url: '/setup/identity', payload: { action: 'login', did: 'did:scid:vh:vta-x', passphrase: 'test-passphrase' } },
      { method: 'POST', url: '/setup/vtn', payload: { action: 'create', name: 'X', namespace: 'x.y' } },
      { method: 'POST', url: '/setup/confirm' },
      { method: 'POST', url: '/setup/reset' },
      { method: 'GET', url: '/setup/state' },
    ];
    for (const attempt of attempts) {
      const res = await app.inject(attempt);
      assert.equal(res.statusCode, 409, `${attempt.method} ${attempt.url} → ${res.statusCode}: ${res.body}`);
    }

    // A replayed confirm did not request a second shutdown.
    assert.deepEqual(shutdowns, ['setup-complete']);
  } finally {
    onShutdownRequested(() => {});
    await app.close();
    await ds.close();
    delete process.env.UTILITY_DATA_DIR;
    delete process.env.P2PTS_HOME;
  }
});

test('simultaneous setup requests: exactly one confirm succeeds, the other is denied', async () => {
  const ds = makeTestDb();
  const app = Fastify();
  registerSetupRoutes(app, { getDb: () => ds });
  tempDataDir();
  const home = mkdtempSync(join(tmpdir(), 'p2pts-vta-routes-'));
  process.env.P2PTS_HOME = home;
  onShutdownRequested(() => {});

  try {
    await seedLocalVtaDb(home, { uuid: 'vta-x', did: 'did:scid:vh:vta-x', name: 'alice' });
    await app.inject({ method: 'POST', url: '/setup/reset' });
    const id = await app.inject({
      method: 'POST', url: '/setup/identity',
      payload: { action: 'login', did: 'did:scid:vh:vta-x', passphrase: 'test-passphrase' },
    });
    assert.equal(id.statusCode, 200, id.body);

    const [a, b] = await Promise.all([
      app.inject({ method: 'POST', url: '/setup/confirm' }),
      app.inject({ method: 'POST', url: '/setup/confirm' }),
    ]);
    const codes = [a.statusCode, b.statusCode].sort();
    assert.deepEqual(codes, [200, 409], `got ${JSON.stringify([a.body, b.body])}`);
  } finally {
    onShutdownRequested(() => {});
    await app.close();
    await ds.close();
    delete process.env.UTILITY_DATA_DIR;
    delete process.env.P2PTS_HOME;
  }
});

test('auth plugin no longer exempts /setup/* once the instance is configured', async () => {
  const ds = makeTestDb();
  const dir = tempDataDir();
  markConfigured(dir);
  const app = Fastify();
  registerAuth(app, ds, Buffer.alloc(32, 1));
  app.post('/setup/network', async () => ({ ok: true }));
  try {
    const r = await app.inject({ method: 'POST', url: '/setup/network', payload: {} });
    assert.equal(r.statusCode, 401, r.body);
  } finally {
    await app.close();
    await ds.close();
    delete process.env.UTILITY_DATA_DIR;
  }
});


// ── Resume an already-provisioned DB (config.json lost) ───────────────

test('setup/vtn resumes an existing namespace instead of dead-ending', async () => {
  const ds = makeTestDb();
  const app = Fastify();
  registerSetupRoutes(app, { getDb: () => ds });
  tempDataDir();
  const home = mkdtempSync(join(tmpdir(), 'p2pts-vta-routes-'));
  process.env.P2PTS_HOME = home;
  onShutdownRequested(() => {});
  try {
    await seedLocalVtaDb(home, { uuid: 'vta-x', did: 'did:scid:vh:vta-x', name: 'alice' });

    // A PRIOR setup run already provisioned the DB (namespace + VTN + founding admin),
    // even though the local config.json is gone (wiped data dir). This is the state
    // that used to dead-end the wizard with "A namespace is already configured".
    const founder = await seedRealVta(ds, { uuid: 'founder-1', name: 'alice' });
    const first = await createNamespaceVtn(ds, { name: 'My Net', namespace: 'p2pts', founderUuid: founder });

    // Re-run the wizard up to the VTN step.
    await app.inject({ method: 'POST', url: '/setup/reset' });
    const id = await app.inject({
      method: 'POST', url: '/setup/identity',
      payload: { action: 'login', did: 'did:scid:vh:vta-x', passphrase: 'test-passphrase' },
    });
    assert.equal(id.statusCode, 200, id.body);

    const r = await app.inject({
      method: 'POST', url: '/setup/vtn',
      payload: { action: 'create', name: 'My Net', namespace: 'p2pts' },
    });
    assert.equal(r.statusCode, 200, r.body);
    assert.equal(r.json().vtn.namespace, 'p2pts');
    assert.equal(r.json().vtn.vtnUuid, first.vtnUuid, 'must adopt the existing VTN, not create a new one');

    // Adopted the existing binding — no second namespace row.
    const ns = await getNamespaceConfig(ds);
    assert.equal(ns?.namespace, 'p2pts');
    assert.equal(ns?.vtnIdentityUuid, first.vtnUuid);

    // And the wizard can now finish.
    const confirm = await app.inject({ method: 'POST', url: '/setup/confirm' });
    assert.equal(confirm.statusCode, 200, confirm.body);
    assert.equal(isConfigured(), true);
  } finally {
    onShutdownRequested(() => {});
    await app.close();
    await ds.close();
    delete process.env.UTILITY_DATA_DIR;
    delete process.env.P2PTS_HOME;
  }
});


// ── Bootstrap address + peer ID (the network step's new fields) ────────────
//
// The wizard pre-fills both from this component's `.env` and lets the operator
// accept or replace them. Empty is legitimate ("use the .env value"); malformed
// is not — a bad peer ID otherwise surfaces much later as an opaque dial timeout.

const VALID_PEER_ID = '12D3KooWKF2Tmh21NNSH5gWazfbmFEtTZS9XT1uXk8njFAy5jUda';

test('setup network step accepts a replacement bootstrap host + peer ID', async () => {
  const ds = makeTestDb();
  const app = Fastify();
  registerSetupRoutes(app, { getDb: () => ds });
  tempDataDir();
  try {
    await app.inject({ method: 'POST', url: '/setup/reset' });
    const r = await app.inject({
      method: 'POST', url: '/setup/network',
      payload: {
        advertisedHost: '203.0.113.5',
        httpPort: 8790,
        libp2pPort: 4005,
        bootstrapHost: 'bootstrap.example.com',
        bootstrapPeerId: VALID_PEER_ID,
      },
    });
    assert.equal(r.statusCode, 200, r.body);
    assert.equal(r.json().network.bootstrapHost, 'bootstrap.example.com');
    assert.equal(r.json().network.bootstrapPeerId, VALID_PEER_ID);
  } finally {
    await app.close();
    await ds.close();
    delete process.env.UTILITY_DATA_DIR;
  }
});

test('setup network step accepts empty bootstrap fields (means "use the .env")', async () => {
  const ds = makeTestDb();
  const app = Fastify();
  registerSetupRoutes(app, { getDb: () => ds });
  tempDataDir();
  try {
    await app.inject({ method: 'POST', url: '/setup/reset' });
    const r = await app.inject({
      method: 'POST', url: '/setup/network',
      payload: { advertisedHost: '203.0.113.5', httpPort: 8790, libp2pPort: 4005 },
    });
    assert.equal(r.statusCode, 200, r.body);
    assert.equal(r.json().network.bootstrapHost, '');
    assert.equal(r.json().network.bootstrapPeerId, '');
  } finally {
    await app.close();
    await ds.close();
    delete process.env.UTILITY_DATA_DIR;
  }
});

test('setup network step rejects a malformed bootstrap peer ID', async () => {
  const ds = makeTestDb();
  const app = Fastify();
  registerSetupRoutes(app, { getDb: () => ds });
  tempDataDir();
  try {
    await app.inject({ method: 'POST', url: '/setup/reset' });
    const r = await app.inject({
      method: 'POST', url: '/setup/network',
      payload: { bootstrapPeerId: 'not-a-peer-id' },
    });
    assert.equal(r.statusCode, 400, r.body);
    assert.match(r.json().error, /Invalid bootstrap peer ID/);
  } finally {
    await app.close();
    await ds.close();
    delete process.env.UTILITY_DATA_DIR;
  }
});

test('setup network step rejects a malformed bootstrap host', async () => {
  const ds = makeTestDb();
  const app = Fastify();
  registerSetupRoutes(app, { getDb: () => ds });
  tempDataDir();
  try {
    await app.inject({ method: 'POST', url: '/setup/reset' });
    const r = await app.inject({
      method: 'POST', url: '/setup/network',
      payload: { bootstrapHost: 'http://bootstrap.example.com/path' },
    });
    assert.equal(r.statusCode, 400, r.body);
    assert.match(r.json().error, /Invalid bootstrap host/);
  } finally {
    await app.close();
    await ds.close();
    delete process.env.UTILITY_DATA_DIR;
  }
});

test('setup bootstrap endpoint reports the .env defaults (shape is stable either way)', async () => {
  const ds = makeTestDb();
  const app = Fastify();
  registerSetupRoutes(app, { getDb: () => ds });
  tempDataDir();
  try {
    const r = await app.inject({ method: 'GET', url: '/setup/bootstrap' });
    assert.equal(r.statusCode, 200, r.body);
    const d = r.json();
    // Whether or not this checkout has a utility-server/.env, the wizard needs a
    // stable shape to pre-fill from: it must never throw, and must never return
    // undefined for the fields the form binds to.
    assert.equal(typeof d.available, 'boolean');
    assert.equal(typeof d.host, 'string');
    assert.equal(typeof d.peerId, 'string');
    assert.equal(typeof d.tcpPort, 'number');
    assert.equal(typeof d.wsPort, 'number');
  } finally {
    await app.close();
    await ds.close();
    delete process.env.UTILITY_DATA_DIR;
  }
});

