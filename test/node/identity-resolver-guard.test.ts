/**
 * Tests for the identity-materialization guard on
 * `DsIdentityResolver.resolveRemoteIdentity`.
 *
 * The TSP bridge's per-message endpoint recording runs on EVERY inbound envelope,
 * right after `peekEnvelope()` — which only PARSES the envelope and verifies
 * nothing. Materializing an identity from that value meant any sender could make
 * the server INSERT an identity row keyed by `didToUuid(<whatever it put in the
 * envelope's VID field>)`: document-less, key-less, endpoint-less orphan rows.
 * Those orphans are what `createVtc`'s `hasAnyEndpoint` discriminator and
 * `resolveRealVtaForStub` exist to work around (and what produced the
 * "admin identity … has no libp2p endpoint — likely a TSP-bridge fake" 400).
 *
 * `createIfMissing: false` makes that path a no-op for unknown senders, while the
 * handshake (which verifies the signature first and passes the document's `id`)
 * still creates first-contact identities.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs --test test/node/identity-resolver-guard.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { didToUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import { DsIdentityResolver } from '../../src/node/relationship-store-ds.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

function makeDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

async function identityCount(ds: SqliteDataSource, uuid: string): Promise<number> {
  const row = await ds.get<{ n: number }>('SELECT COUNT(*) AS n FROM identities WHERE uuid = ?', uuid);
  return Number(row?.n ?? 0);
}

test('resolveRemoteIdentity: createIfMissing=false leaves an unseen DID unmaterialized', async () => {
  const ds = makeDb();
  const did = 'did:scid:vh:1:zUnverifiedSender';

  const resolved = await new DsIdentityResolver(ds).resolveRemoteIdentity({
    did,
    method: 'did:scid:vh',
    isPrimary: false,
    recordedByNode: 'tsp-bridge',
    peerId: '12D3KooWUnverified',
    createIfMissing: false,
  });

  assert.equal(resolved, null, 'an unknown sender must not be materialized');
  assert.equal(
    await identityCount(ds, didToUuid(did)), 0,
    'no identity row may be created from an unverified VID',
  );
  const docs = await ds.get<{ n: number }>(
    'SELECT COUNT(*) AS n FROM did_documents WHERE did = ?', did,
  );
  assert.equal(Number(docs?.n ?? 0), 0, 'no document row either');

  await ds.close();
});

test('resolveRemoteIdentity: createIfMissing=false still resolves a known DID and records its endpoint', async () => {
  const ds = makeDb();
  const did = 'did:scid:vh:1:zKnownSender';
  const resolver = new DsIdentityResolver(ds);

  // First contact (handshake semantics: the caller verified the message).
  const created = await resolver.resolveRemoteIdentity({
    did, method: 'did:scid:vh', isPrimary: false, recordedByNode: 'tsp-bridge',
  });
  assert.ok(created, 'the default (createIfMissing=true) must create first-contact identities');

  // A later unverified per-message pass must find it, not duplicate it.
  const resolved = await resolver.resolveRemoteIdentity({
    did, method: 'did:scid:vh', isPrimary: false, recordedByNode: 'tsp-bridge',
    peerId: '12D3KooWKnownPeer', createIfMissing: false,
  });
  assert.ok(resolved, 'a known DID must resolve');
  assert.equal(resolved!.identityUuid, created!.identityUuid, 'same identity, no new row');
  assert.equal(await identityCount(ds, didToUuid(did)), 1, 'still exactly one identity row');

  const endpoint = await ds.get<{ peer_id: string }>(
    'SELECT peer_id FROM peer_endpoints WHERE identity_uuid = ? AND is_active = 1',
    created!.identityUuid,
  );
  assert.equal(endpoint?.peer_id, '12D3KooWKnownPeer', 'the live endpoint is still recorded');

  await ds.close();
});

test('resolveRemoteIdentity: adopts a document-less identity row instead of colliding on the uuid', async () => {
  const ds = makeDb();
  const did = 'did:scid:vh:1:zDocLessIdentity';
  const uuid = didToUuid(did);

  // An identity that exists WITHOUT a did_documents row (the pre-existing row the
  // old code would have re-INSERTed, violating the identities primary key).
  await ds.run(
    `INSERT INTO identities (uuid, role, subject_kind, custody, name)
     VALUES (?, 'vta', 'human', 'remote', 'pre-existing')`,
    uuid,
  );

  const resolved = await new DsIdentityResolver(ds).resolveRemoteIdentity({
    did, method: 'did:scid:vh', isPrimary: true,
  });

  assert.ok(resolved, 'the existing row must be adopted');
  assert.equal(resolved!.identityUuid, uuid, 'the deterministic uuid is reused, not re-inserted');
  assert.equal(await identityCount(ds, uuid), 1, 'still exactly one row');
  const doc = await ds.get<{ uuid: string }>('SELECT uuid FROM did_documents WHERE did = ?', did);
  assert.ok(doc, 'the missing document row is materialized');

  await ds.close();
});
