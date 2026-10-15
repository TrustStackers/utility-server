/**
 * Regression tests: the identity push must record the agent's DIALABLE ADDRESSES.
 *
 * Observed defect (utility-server member re-dial stage):
 *
 *   [utility-server:connectivity] warn: reconnect to agent 12D3KooW9yUD… failed
 *     (all 1 address(es) failed) — retrying in 120s        ← forever
 *
 * `ConnectivitySupervisor.listMemberEndpoints()` builds its dial candidates from
 * `peer_endpoints.multiaddrs` (+ the bootstrap relay). `createRemoteVta` recorded
 * the agent's `peerId` but never its `multiaddrs`, so every agent endpoint row
 * carried `multiaddrs = NULL` — leaving exactly ONE candidate (the relay) and a
 * permanent 120s failure loop whenever that relay path was unavailable, even for
 * two peers on the same LAN.
 *
 * The push now carries `multiaddrs` (IdentityPushPayload.multiaddrs →
 * createRemoteVta → setActiveEndpoint), and these tests pin that link at the
 * level the supervisor actually reads.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs \
 *     --test test/db/identity-push-multiaddrs.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { createRemoteVta } from '@p2p-trust-stack/core/services/vta.js';
import { DsIdentityResolver } from '../../src/node/relationship-store-ds.js';
import { buildDidPeer4Document } from '@p2p-trust-stack/core/did/create.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

function makeDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

const ED = new Uint8Array(32).fill(0x11);
const X = new Uint8Array(32).fill(0x22);

function makeDoc(did: string): Record<string, unknown> {
  const doc = buildDidPeer4Document(ED, X, {
    peerId: '12D3KooWTestPeerId',
    multiaddrs: ['/ip4/127.0.0.1/tcp/40003'],
  }) as unknown as Record<string, unknown>;
  doc.id = did;
  return doc;
}

/** The handshake path: creates the identity + endpoint row (no multiaddrs). */
async function seedHandshakeStub(ds: SqliteDataSource, did: string, peerId: string) {
  const resolver = new DsIdentityResolver(ds);
  const resolved = await resolver.resolveRemoteIdentity({
    did,
    method: 'did:scid:vh',
    didDocumentJson: JSON.stringify(makeDoc(did)),
    isPrimary: false,
    recordedByNode: 'tsp-bridge',
    peerId,
  });
  if (!resolved) throw new Error('test setup: handshake stub was not created');
  return resolved;
}

/** The exact read the ConnectivitySupervisor's listMemberEndpoints performs. */
async function endpointRow(ds: SqliteDataSource, peerId: string) {
  return ds.get<{ peer_id: string; multiaddrs: string | null; is_active: number }>(
    'SELECT peer_id, multiaddrs, is_active FROM peer_endpoints WHERE peer_id = ?',
    peerId,
  );
}

test('identity_push: the agent\'s dialable multiaddrs are recorded on its endpoint row', async () => {
  const ds = makeDb();
  const did = 'did:scid:vh:1:zTestPushAddrs1';
  const peerId = '12D3KooWTestPeerId';
  const stub = await seedHandshakeStub(ds, did, peerId);

  const before = await endpointRow(ds, peerId);
  assert.ok(before, 'the handshake must have created the endpoint row');
  assert.equal(before!.multiaddrs, null, 'precondition: the handshake records no addresses');

  const multiaddrs = ['/ip4/192.168.1.9/tcp/24001', '/ip4/127.0.0.1/tcp/24001'];
  await createRemoteVta(ds, {
    realDid: did,
    uuid: stub.identityUuid,
    name: 'alice',
    subjectKind: 'human',
    didDocument: makeDoc(did),
    publicKeys: {
      ed25519: Buffer.from(ED).toString('base64'),
      x25519: Buffer.from(X).toString('base64'),
    },
    peerId,
    multiaddrs,
    recordedByNode: 'agent-push',
  });

  const after = await endpointRow(ds, peerId);
  assert.ok(after, 'the endpoint row must still exist');
  assert.equal(after!.is_active, 1);
  const parsed = JSON.parse(after!.multiaddrs ?? 'null') as string[] | null;
  assert.deepEqual(
    parsed,
    multiaddrs,
    'the supervisor dials these rows: the push must persist the agent\'s addresses',
  );

  await ds.close();
});

test('identity_push: a later push refreshes the recorded addresses', async () => {
  const ds = makeDb();
  const did = 'did:scid:vh:1:zTestPushAddrs2';
  const peerId = '12D3KooWTestPeerId';
  const stub = await seedHandshakeStub(ds, did, peerId);

  const push = (multiaddrs: string[]) =>
    createRemoteVta(ds, {
      realDid: did,
      uuid: stub.identityUuid,
      name: 'alice',
      subjectKind: 'human',
      didDocument: makeDoc(did),
      publicKeys: {
        ed25519: Buffer.from(ED).toString('base64'),
        x25519: Buffer.from(X).toString('base64'),
      },
      peerId,
      multiaddrs,
      recordedByNode: 'agent-push',
    });

  await push(['/ip4/192.168.1.9/tcp/24001']);
  await push(['/ip4/10.0.0.7/tcp/24001']); // network changed

  const row = await endpointRow(ds, peerId);
  assert.deepEqual(
    JSON.parse(row!.multiaddrs ?? 'null'),
    ['/ip4/10.0.0.7/tcp/24001'],
    'a re-push must replace stale addresses (the agent moved networks)',
  );

  await ds.close();
});
