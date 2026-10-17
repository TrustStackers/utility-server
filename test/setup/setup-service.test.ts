// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests: setup-service — real VTN creation + founder validation.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createNamespaceVtn,
  listLocalFounderVtas,
  registerLocalVtaAsFounder,
} from '../../src/setup/setup-service.js';
import { getNamespaceConfig } from '../../src/services/namespace-service.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as governanceRepo from '@p2p-trust-stack/core/db/repositories/governance-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import * as peerEndpointsRepo from '@p2p-trust-stack/core/db/repositories/peer-endpoints-repo.js';
import { makeTestDb, seedRealVta, seedLocalVtaDb } from './helpers.js';

function tempP2ptsHome(): string {
  const dir = mkdtempSync(join(tmpdir(), 'p2pts-vta-'));
  process.env.P2PTS_HOME = dir;
  return dir;
}

test('createNamespaceVtn creates a real VTN + governance + founding_admin + namespace binding', async () => {
  const ds = makeTestDb();
  try {
    const founder = await seedRealVta(ds, { uuid: '11111111-1111-4111-8111-111111111111', name: 'alice' });

    const result = await createNamespaceVtn(ds, {
      name: 'My Network',
      namespace: 'p2pts.mainnet',
      founderUuid: founder,
    });

    assert.ok(result.vtnUuid, 'vtnUuid present');
    assert.ok(result.vtnDid?.startsWith('did:'), 'vtnDid is a DID');
    assert.equal(result.namespace, 'p2pts.mainnet');

    // The VTN is a real governance identity (role='vtn'), not a lone row.
    const vtn = await identitiesRepo.findByUuid(ds, result.vtnUuid);
    assert.equal(vtn?.role, 'vtn');
    assert.equal(vtn?.name, 'My Network');

    const gov = await governanceRepo.findForCommunity(ds, result.vtnUuid);
    assert.ok(gov, 'governance row exists');

    // Founder is the founding_admin with active status.
    const roster = await membershipsRepo.findForCommunity(ds, result.vtnUuid);
    const founderMembership = roster.find((m) => m.memberIdentityUuid === founder);
    assert.equal(founderMembership?.role, 'founding_admin');
    assert.equal(founderMembership?.status, 'active');

    // Namespace string is bound to the VTN.
    const ns = await getNamespaceConfig(ds);
    assert.equal(ns?.vtnIdentityUuid, result.vtnUuid);
    assert.equal(ns?.namespace, 'p2pts.mainnet');
  } finally {
    await ds.close();
  }
});

test('listLocalFounderVtas reports no database when P2PTS_HOME/vta is absent', async () => {
  tempP2ptsHome();
  try {
    const scan = await listLocalFounderVtas();
    assert.equal(scan.localDbExists, false);
    assert.deepEqual(scan.vtas, []);
  } finally {
    delete process.env.P2PTS_HOME;
  }
});

test('listLocalFounderVtas finds an existing VTA in the agent database', async () => {
  const home = tempP2ptsHome();
  try {
    await seedLocalVtaDb(home, { uuid: 'local-1', did: 'did:scid:vh:local-1', name: 'alice' });
    const scan = await listLocalFounderVtas();
    assert.equal(scan.localDbExists, true);
    assert.equal(scan.vtas.length, 1);
    assert.equal(scan.vtas[0].did, 'did:scid:vh:local-1');
    assert.equal(scan.vtas[0].name, 'alice');
  } finally {
    delete process.env.P2PTS_HOME;
  }
});

test('registerLocalVtaAsFounder registers the local VTA + its REAL endpoint into the server DB', async () => {
  const ds = makeTestDb();      // the utility server (Yugabyte) DB
  const home = tempP2ptsHome();  // the agent-app local SQLite DB
  try {
    await seedLocalVtaDb(home, { uuid: 'local-2', did: 'did:scid:vh:local-2', name: 'bob', peerId: '12D3KooWluna' });

    const founder = await registerLocalVtaAsFounder(ds, { did: 'did:scid:vh:local-2', passphrase: 'test-passphrase' });

    assert.equal(founder.did, 'did:scid:vh:local-2');
    const identity = await identitiesRepo.findByUuid(ds, founder.identityUuid);
    assert.equal(identity?.role, 'vta');
    assert.equal(identity?.subjectKind, 'human');
    assert.equal(identity?.name, 'bob');

    const ep = await peerEndpointsRepo.findActive(ds, founder.identityUuid);
    assert.equal(ep?.peerId, '12D3KooWluna');
  } finally {
    await ds.close();
    delete process.env.P2PTS_HOME;
  }
});

test('registerLocalVtaAsFounder rejects a wrong passphrase', async () => {
  const ds = makeTestDb();
  const home = tempP2ptsHome();
  try {
    await seedLocalVtaDb(home, { uuid: 'local-3', did: 'did:scid:vh:local-3', name: 'alice' });
    await assert.rejects(
      () => registerLocalVtaAsFounder(ds, { did: 'did:scid:vh:local-3', passphrase: 'wrong-passphrase' }),
      /Incorrect passphrase/,
    );
  } finally {
    await ds.close();
    delete process.env.P2PTS_HOME;
  }
});

test('registerLocalVtaAsFounder rejects a VTA with no recorded endpoint', async () => {
  const ds = makeTestDb();
  const home = tempP2ptsHome();
  try {
    await seedLocalVtaDb(home, { uuid: 'local-4', did: 'did:scid:vh:local-4', name: 'carol', withEndpoint: false });
    await assert.rejects(
      () => registerLocalVtaAsFounder(ds, { did: 'did:scid:vh:local-4', passphrase: 'test-passphrase' }),
      /no recorded peer endpoint/,
    );
  } finally {
    await ds.close();
    delete process.env.P2PTS_HOME;
  }
});

test('registerLocalVtaAsFounder rejects a non-human local VTA', async () => {
  const ds = makeTestDb();
  const home = tempP2ptsHome();
  try {
    await seedLocalVtaDb(home, { uuid: 'local-ai', did: 'did:scid:vh:local-ai', name: 'bot', subjectKind: 'ai_agent' });
    await assert.rejects(
      () => registerLocalVtaAsFounder(ds, { did: 'did:scid:vh:local-ai', passphrase: 'test-passphrase' }),
      /human/,
    );
  } finally {
    await ds.close();
    delete process.env.P2PTS_HOME;
  }
});

test('createNamespaceVtn rejects a second namespace config (one server, one namespace)', async () => {
  const ds = makeTestDb();
  try {
    const founder = await seedRealVta(ds, { uuid: 'f1', name: 'alice' });
    await createNamespaceVtn(ds, { name: 'Net 1', namespace: 'first.net', founderUuid: founder });
    await assert.rejects(
      () => createNamespaceVtn(ds, { name: 'Net 2', namespace: 'second.net', founderUuid: founder }),
      /already configured/,
    );
  } finally {
    await ds.close();
  }
});
