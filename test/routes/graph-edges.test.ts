// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Regression tests: trust-graph viewer route — GET /graph/edges?format=graph.
 *
 * Reproduced glitch (after the uuid-first database refactor, migrations
 * 0018/0019): the _id refactor removed the integer `id` columns from the
 * `credentials` and `relationships` tables (replaced by the `uuid` PRIMARY
 * KEY). The graph route in graph-edges.ts still ran `SELECT id, ...` from
 * both tables, so PostgreSQL/Yugabyte threw `column "id" does not exist`,
 * /graph/edges?format=graph returned 500, and ui/graph.html showed the error
 * banner instead of the two VTA nodes + their VRC edge — even though real
 * VRC data was present.
 *
 * These tests seed two real VTA identities, a VRC credential from one to the
 * other, and a Layer-2 peer relationship, then assert the graph payload
 * returns exactly those two nodes plus the credential ('vrc') and 'peer'
 * edges. They run against an in-memory SQLite DB with the real migrations;
 * the only Postgres-only piece of the route's SQL — `encode(bytea,'hex')` —
 * is emulated with a SQLite custom function so the exact production query
 * executes verbatim.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs --test test/routes/graph-edges.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import { registerGraphEdgesRoute } from '../../src/routes/layer5-applications/graph-edges.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

function makeAppDb() {
  const ds = new SqliteDataSource(':memory:');

  // Emulate PostgreSQL's encode(bytea, 'hex') — used verbatim by
  // buildCanonicalizationMap — as a SQLite custom function so the production
  // SQL compiles and runs against the in-memory test DB. (The agent-app's
  // SQLite twin of this query uses SQLite's native hex() instead.)
  const raw = ds.getRawDb() as unknown as {
    function(
      name: string,
      opts: { deterministic?: boolean },
      fn: (blob: unknown, format: unknown) => unknown,
    ): void;
  };
  raw.function('encode', { deterministic: true }, (blob, format) => {
    if (format !== 'hex') throw new Error(`unexpected encode format: ${String(format)}`);
    return Buffer.from(blob as Uint8Array).toString('hex');
  });

  runMigrations(raw as never, MIGRATIONS_DIR);
  return ds;
}

interface Seed {
  aUuid: string;
  bUuid: string;
  credUuid: string;
  relUuid: string;
}

async function seedTwoAgentsWithVrc(ds: SqliteDataSource): Promise<Seed> {
  const aUuid = '11111111-1111-4111-8111-111111111111';
  const bUuid = '22222222-2222-4222-8222-222222222222';
  const now = Math.floor(Date.now() / 1000);

  // Two real VTA identities (each with a non-ephemeral did:key doc, so
  // is_ephemeral_peer4 = 0 → no canonicalization collapse).
  await ds.run(
    `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
     VALUES (?, 'vta', 'human', 'remote', 'alice-agent', ?, ?)`,
    aUuid, now, now,
  );
  await ds.run(
    `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
     VALUES (?, 'vta', 'human', 'remote', 'bob-agent', ?, ?)`,
    bUuid, now, now,
  );

  await ds.run(
    `INSERT INTO did_documents (uuid, identity_uuid, did, method, is_primary, recorded_by_node, created_at)
     VALUES (?, ?, ?, 'did:key', 1, 'agent-push', ?)`,
    generateUuid(), aUuid, 'did:key:zAlice', now,
  );
  await ds.run(
    `INSERT INTO did_documents (uuid, identity_uuid, did, method, is_primary, recorded_by_node, created_at)
     VALUES (?, ?, ?, 'did:key', 1, 'agent-push', ?)`,
    generateUuid(), bUuid, 'did:key:zBob', now,
  );

  // Distinct Ed25519 public keys so the two agents stay distinct nodes.
  await ds.run(
    `INSERT INTO keys (uuid, identity_uuid, key_type, public_key, rotation_version, created_at)
     VALUES (?, ?, 'ed25519', ?, 0, ?)`,
    generateUuid(), aUuid, Buffer.from('aa'.repeat(32), 'hex'), now,
  );
  await ds.run(
    `INSERT INTO keys (uuid, identity_uuid, key_type, public_key, rotation_version, created_at)
     VALUES (?, ?, 'ed25519', ?, 0, ?)`,
    generateUuid(), bUuid, Buffer.from('bb'.repeat(32), 'hex'), now,
  );

  // A VRC credential: Alice verifies/resolves Bob.
  const credUuid = generateUuid();
  await ds.run(
    `INSERT INTO credentials (uuid, vc_type, issuer_identity_uuid, subject_identity_uuid, status, valid_from, created_at)
     VALUES (?, 'vrc', ?, ?, 'issued', ?, ?)`,
    credUuid, aUuid, bUuid, now, now,
  );

  // A Layer-2 peer relationship so a 'peer' edge is surfaced too.
  const relUuid = generateUuid();
  await ds.run(
    `INSERT INTO relationships (uuid, local_identity_uuid, remote_identity_uuid, direction, status, created_at, updated_at)
     VALUES (?, ?, ?, 'bidirectional', 'established', ?, ?)`,
    relUuid, aUuid, bUuid, now, now,
  );

  return { aUuid, bUuid, credUuid, relUuid };
}

test('GET /graph/edges?format=graph returns both agents plus the VRC and peer edges (post-_id-refactor)', async () => {
  const ds = makeAppDb();
  const app = Fastify();
  registerGraphEdgesRoute(app, ds);
  try {
    const { aUuid, bUuid, credUuid, relUuid } = await seedTwoAgentsWithVrc(ds);

    const res = await app.inject({ method: 'GET', url: '/graph/edges?format=graph' });
    assert.equal(res.statusCode, 200, res.body);

    const body = res.json();
    assert.ok(Array.isArray(body.nodes), 'nodes must be an array');
    assert.ok(Array.isArray(body.edges), 'edges must be an array');

    // Exactly the two VTA agents — no throwaway did:peer:4 nodes.
    assert.equal(body.nodes.length, 2);
    const nodeIds = body.nodes.map((n: { id: string }) => n.id).sort();
    assert.deepEqual(nodeIds, [aUuid, bUuid].sort());
    const names = body.nodes.map((n: { label: string }) => n.label);
    assert.ok(names.includes('alice-agent') && names.includes('bob-agent'),
      `expected both agents labelled, got ${names.join(', ')}`);

    // Each node exposes its primary DID (did_documents.did).
    const didByUuid = new Map(body.nodes.map((n: { id: string; did: string | null }) => [n.id, n.did]));
    assert.equal(didByUuid.get(aUuid), 'did:key:zAlice');
    assert.equal(didByUuid.get(bUuid), 'did:key:zBob');

    // One credential ('vrc') edge + one 'peer' edge.
    const credEdges = body.edges.filter((e: { kind: string }) => e.kind === 'credential');
    const peerEdges = body.edges.filter((e: { kind: string }) => e.kind === 'peer');
    assert.equal(body.edges.length, 2);
    assert.equal(credEdges.length, 1);
    assert.equal(peerEdges.length, 1);

    const vrc = credEdges[0];
    assert.equal(vrc.vcType, 'vrc');
    assert.equal(vrc.source, aUuid);
    assert.equal(vrc.target, bUuid);
    assert.equal(vrc.id, `credential:${credUuid}`);

    const peer = peerEdges[0];
    assert.equal(peer.source, aUuid);
    assert.equal(peer.target, bUuid);
    assert.equal(peer.id, `peer:${relUuid}`);
    assert.equal(peer.direction, 'bidirectional');
  } finally {
    await app.close();
    await ds.close();
  }
});

test('VTC nodes expose active members and credential edges expose public details', async () => {
  const ds = makeAppDb();
  const app = Fastify();
  registerGraphEdgesRoute(app, ds);
  try {
    const { aUuid } = await seedTwoAgentsWithVrc(ds);
    const now = Math.floor(Date.now() / 1000);
    const vtcUuid = '33333333-3333-4333-8333-333333333333';

    // A VTC community identity with its own primary DID.
    await ds.run(
      `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
       VALUES (?, 'vtc', 'organization', 'remote', 'alpha-community', ?, ?)`,
      vtcUuid, now, now,
    );
    await ds.run(
      `INSERT INTO did_documents (uuid, identity_uuid, did, method, is_primary, recorded_by_node, created_at)
       VALUES (?, ?, ?, 'did:key', 1, 'agent-push', ?)`,
      generateUuid(), vtcUuid, 'did:key:zCommunity', now,
    );
    await ds.run(
      `INSERT INTO keys (uuid, identity_uuid, key_type, public_key, rotation_version, created_at)
       VALUES (?, ?, 'ed25519', ?, 0, ?)`,
      generateUuid(), vtcUuid, Buffer.from('cc'.repeat(32), 'hex'), now,
    );

    // Alice is an active member of the VTC.
    await ds.run(
      `INSERT INTO memberships (uuid, member_identity_uuid, community_identity_uuid, role, status, issued_at)
       VALUES (?, ?, ?, 'member', 'active', ?)`,
      generateUuid(), aUuid, vtcUuid, now,
    );

    // A VMC membership credential from the VTC to Alice, with public details.
    const vmcUuid = generateUuid();
    await ds.run(
      `INSERT INTO credentials (uuid, vc_type, issuer_identity_uuid, subject_identity_uuid, status, claim, valid_from, valid_until, threshold_required, created_at)
       VALUES (?, 'vmc', ?, ?, 'issued', ?, ?, ?, ?, ?)`,
      vmcUuid, vtcUuid, aUuid, '{"type":"membership","membershipRole":"member"}', now, now + 86400, 2, now,
    );

    const res = await app.inject({ method: 'GET', url: '/graph/edges?format=graph' });
    assert.equal(res.statusCode, 200, res.body);
    const body = res.json();

    const vtcNode = body.nodes.find((n: { id: string }) => n.id === vtcUuid);
    assert.ok(vtcNode, 'VTC node must be present');
    assert.equal(vtcNode.did, 'did:key:zCommunity');
    assert.deepEqual(vtcNode.members, [{ uuid: aUuid, label: 'alice-agent', role: 'member' }]);

    const vmcEdge = body.edges.find((e: { id: string }) => e.id === `credential:${vmcUuid}`);
    assert.ok(vmcEdge, 'VMC credential edge must be present');
    assert.equal(vmcEdge.claim, '{"type":"membership","membershipRole":"member"}');
    assert.equal(vmcEdge.validFrom, now);
    assert.equal(vmcEdge.validUntil, now + 86400);
    assert.equal(vmcEdge.thresholdRequired, 2);
  } finally {
    await app.close();
    await ds.close();
  }
});

test('GET /graph/edges (legacy edge-list format) still works from the uuid-first repos', async () => {
  const ds = makeAppDb();
  const app = Fastify();
  registerGraphEdgesRoute(app, ds);
  try {
    const { aUuid, bUuid, credUuid } = await seedTwoAgentsWithVrc(ds);

    const res = await app.inject({ method: 'GET', url: '/graph/edges' });
    assert.equal(res.statusCode, 200, res.body);

    const body = res.json();
    assert.equal(body.edgeCount, 1, 'legacy format authors only the VRC credential edge');
    const vrc = body.edges[0];
    assert.equal(vrc.vcType, 'vrc');
    assert.equal(vrc.from, aUuid);
    assert.equal(vrc.to, bUuid);
    assert.equal(vrc.id, `credential:${credUuid}`);
    assert.equal(vrc.credentialId, credUuid);
  } finally {
    await app.close();
    await ds.close();
  }
});

