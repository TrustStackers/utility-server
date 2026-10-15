/**
 * Tests: setup-state — configuration model, persistence, isConfigured.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  buildSetupConfig,
  createSetupState,
  isConfigured,
  loadSetupConfig,
  saveSetupConfig,
} from '../../src/setup/setup-state.js';

function withTempDataDir(fn: () => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'p2pts-setup-'));
  process.env.UTILITY_DATA_DIR = dir;
  try {
    fn();
  } finally {
    delete process.env.UTILITY_DATA_DIR;
  }
}

test('isConfigured is false with no config file', async () => {
  withTempDataDir(() => {
    assert.equal(isConfigured(), false);
  });
});

test('buildSetupConfig requires mode + admin VTA', () => {
  assert.throws(() => buildSetupConfig(createSetupState()), /incomplete/);
});

test('save + load round-trips the setup config with default network', async () => {
  withTempDataDir(() => {
    const cfg = buildSetupConfig({
      mode: 'vtn_host',
      adminVtaUuid: 'vta-1',
      adminVtaDid: 'did:scid:vh:abc',
      vtnUuid: 'vtn-1',
      vtnDid: 'did:peer:4:xyz',
      namespace: 'p2pts.mainnet',
      currentStep: 4,
      completed: false,
    });

    saveSetupConfig(cfg);
    assert.equal(isConfigured(), true);

    const loaded = loadSetupConfig();
    assert.equal(loaded.mode, 'vtn_host');
    assert.equal(loaded.adminVtaUuid, 'vta-1');
    assert.equal(loaded.namespace, 'p2pts.mainnet');
    assert.equal(loaded.vtnUuid, 'vtn-1');
    assert.equal(loaded.configured, true);
    assert.equal(loaded.network.advertisedHost, '127.0.0.1');
    assert.equal(loaded.network.httpPort, 8787);
    assert.equal(loaded.network.libp2pPort, 4003);
  });
});

test('saveSetupConfig preserves network overrides', async () => {
  withTempDataDir(() => {
    const cfg = buildSetupConfig({
      mode: 'vtn_host',
      adminVtaUuid: 'vta-1',
      network: { advertisedHost: '203.0.113.5', httpPort: 8790, libp2pPort: 4005 },
      currentStep: 4,
      completed: false,
    });
    saveSetupConfig(cfg);
    const loaded = loadSetupConfig();
    assert.equal(loaded.network.advertisedHost, '203.0.113.5');
    assert.equal(loaded.network.httpPort, 8790);
    assert.equal(loaded.network.libp2pPort, 4005);
  });
});
