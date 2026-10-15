/**
 * Tests: namespace-service — namespace_config binding + admin membership gate.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  getNamespaceConfig,
  setNamespaceConfig,
  isNamespaceServed,
  isNamespaceAdmin,
} from '../../src/services/namespace-service.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import { makeTestDb, seedRealVta } from './helpers.js';

test('getNamespaceConfig returns null when unconfigured', async () => {
  const ds = makeTestDb();
  try {
    assert.equal(await getNamespaceConfig(ds), null);
  } finally {
    await ds.close();
  }
});

test('set + get + isNamespaceServed round-trip', async () => {
  const ds = makeTestDb();
  try {
    const row = await setNamespaceConfig(ds, { vtnIdentityUuid: 'vtn-1', namespace: 'p2pts.mainnet' });
    assert.equal(row.namespace, 'p2pts.mainnet');
    assert.equal(row.vtnIdentityUuid, 'vtn-1');

    assert.equal(await isNamespaceServed(ds, 'p2pts.mainnet'), true);
    assert.equal(await isNamespaceServed(ds, 'p2pts'), false);

    const got = await getNamespaceConfig(ds);
    assert.equal(got?.namespace, 'p2pts.mainnet');
    assert.equal(got?.vtnIdentityUuid, 'vtn-1');
  } finally {
    await ds.close();
  }
});

test('setNamespaceConfig replaces the singleton rather than inserting a second row', async () => {
  const ds = makeTestDb();
  try {
    await setNamespaceConfig(ds, { vtnIdentityUuid: 'vtn-1', namespace: 'first.net' });
    await setNamespaceConfig(ds, { vtnIdentityUuid: 'vtn-2', namespace: 'second.net' });
    const cfg = await getNamespaceConfig(ds);
    assert.equal(cfg?.vtnIdentityUuid, 'vtn-2');
    assert.equal(cfg?.namespace, 'second.net');
    const count = await ds.get<{ n: number }>('SELECT COUNT(*) AS n FROM namespace_config');
    assert.equal(count?.n, 1);
  } finally {
    await ds.close();
  }
});

test('isNamespaceAdmin requires an active founding_admin/admin membership', async () => {
  const ds = makeTestDb();
  try {
    await seedRealVta(ds, { uuid: 'vta-1' });
    await seedRealVta(ds, { uuid: 'vta-2' });
    await setNamespaceConfig(ds, { vtnIdentityUuid: 'vtn-1', namespace: 'net' });

    assert.equal(await isNamespaceAdmin(ds, 'vta-1', 'vtn-1'), false);

    const m = await membershipsRepo.create(ds, {
      memberIdentityUuid: 'vta-1',
      communityIdentityUuid: 'vtn-1',
      role: 'founding_admin',
      status: 'active',
    });
    await membershipsRepo.approve(ds, m, null);

    assert.equal(await isNamespaceAdmin(ds, 'vta-1', 'vtn-1'), true);
    assert.equal(await isNamespaceAdmin(ds, 'vta-2', 'vtn-1'), false);
  } finally {
    await ds.close();
  }
});
