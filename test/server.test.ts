// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests: buildServer — the first-run setup UI is not reachable once configured.
 *
 * `setup.html` is a STATIC asset (`@fastify/static`), so unlike the `/setup/*`
 * API routes it survives a configured restart. In operational mode it must not be
 * served: it is a dead form by then (its API is unregistered) and the operator
 * should land on the dashboard instead. In setup mode it must stay live.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { buildServer } from '../src/server.js';

// Route registration only stores these references — no method is called at boot.
const stubDb = {} as never;
const stubNode = {} as never;

function app(setupMode: boolean) {
  return buildServer({
    db: stubDb,
    node: stubNode,
    keyStorePath: '/tmp/none.sqlite',
    setupMode,
  });
}

test('configured instance: GET /ui/setup.html redirects to the dashboard', async () => {
  const server = app(false);
  try {
    const res = await server.inject({ method: 'GET', url: '/ui/setup.html' });
    assert.equal(res.statusCode, 302, res.body);
    assert.equal(res.headers.location, '/ui/index.html');
  } finally {
    await server.close();
  }
});

test('configured instance: GET / redirects to the dashboard', async () => {
  const server = app(false);
  try {
    const res = await server.inject({ method: 'GET', url: '/' });
    assert.equal(res.statusCode, 302, res.body);
    assert.equal(res.headers.location, '/ui/index.html');
  } finally {
    await server.close();
  }
});

test('setup instance: GET /ui/setup.html is served (the wizard stays reachable)', async () => {
  const prevDataDir = process.env.UTILITY_DATA_DIR;
  process.env.UTILITY_DATA_DIR = mkdtempSync(join(tmpdir(), 'p2pts-server-'));
  const server = app(true);
  try {
    const res = await server.inject({ method: 'GET', url: '/ui/setup.html' });
    assert.equal(res.statusCode, 200, res.body);
    assert.match(res.body, /Utility Server Setup/);
  } finally {
    await server.close();
    if (prevDataDir === undefined) delete process.env.UTILITY_DATA_DIR;
    else process.env.UTILITY_DATA_DIR = prevDataDir;
  }
});
