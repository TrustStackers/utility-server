/**
 * Contract test for the AGENT-side forced repair push (G4).
 *
 * ## Why the forced path is needed
 *
 * The agent's identity push is **ack-gated by payload digest**
 * (`ExchangeEngine.commitPush()` skips an unchanged payload — proven by
 * `test/exchange/exchange.test.ts`, "identical re-push gated (no enqueue)" — and it
 * records the digest as soon as the bytes reach the durable outbox). So a
 * server-side row damaged AFTER a successful sync — the TSPv3 doc-linkage
 * duplicate `keys.ed25519` rows, or a document-derived key the agent does not
 * sign with, surfacing as `tspOpen: signature verification failed` and 30 s
 * timeouts for that one agent — can never be repaired by the regular path: the
 * payload is unchanged, so it is skipped forever.
 *
 * `BaseAgent.forceIdentityPush()` therefore runs the SAME 2PC directly, without
 * the watermark gate:
 *
 *   RemoteParticipant(`peer:${serverDid}`, transport)
 *     enlisted with [{ op: 'exchange:identity', params: { payload } }]
 *
 * This test pins the SERVER end of that contract — the op name and the
 * `params.payload` nesting — and proves the repair lands: after the server's key is
 * damaged (even with a legacy duplicate row present), applying the forced payload
 * restores exactly one active row holding the agent's LIVE key.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs --test test/tx/forced-repair-op.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { TX_SCHEMA_SQL } from '@p2p-trust-stack/core/tx/schema.js';
import { ExchangePushParticipant } from '../../src/tx/exchange-push-participant.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();
const REAL_DID = 'did:scid:vh:1:zForcedRepair';
const IDENTITY_UUID = 'aaaaaaaa-1111-4222-8333-444444444444';
const ED_LIVE = new Uint8Array(32).fill(0x5a);
const ED_DOC = new Uint8Array(32).fill(0x11);
const X_KEY = new Uint8Array(32).fill(0x22);

function makeAppDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

function makeTxDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  ds.getRawDb().exec(TX_SCHEMA_SQL);
  return ds;
}

/** The exact payload shape the agent's forced push sends. */
function pushPayload(): Record<string, unknown> {
  return {
    realDid: REAL_DID,
    identityUuid: IDENTITY_UUID,
    name: 'forced-repair',
    subjectKind: 'human',
    didDocument: { id: REAL_DID },
    publicKeys: {
      ed25519: Buffer.from(ED_LIVE).toString('base64'),
      x25519: Buffer.from(X_KEY).toString('base64'),
    },
    profiles: [],
  };
}

async function ed25519Rows(ds: SqliteDataSource, identityUuid: string) {
  return ds.all<{ uuid: string; public_key: Buffer | Uint8Array }>(
    `SELECT uuid, public_key FROM keys
      WHERE identity_uuid = ? AND key_type = 'ed25519' AND rotation_version = 0`,
    identityUuid,
  );
}

function keyB64(row: { public_key: Buffer | Uint8Array }): string {
  const bytes = row.public_key instanceof Uint8Array ? row.public_key : new Uint8Array(row.public_key);
  return Buffer.from(bytes).toString('base64');
}

test('forced repair: the participant claims the op and applies the LIVE key', async () => {
  const app = makeAppDb();
  const tx = makeTxDb();
  const participant = new ExchangePushParticipant('server:us-1', app, tx);

  assert.equal(
    participant.handlesOperation({ op: 'exchange:identity', params: {} }),
    true,
    'the forced push op must be claimed by ExchangePushParticipant',
  );

  const vote = await participant.prepare('tx-forced-1', [
    { op: 'exchange:identity', params: { payload: pushPayload() } },
  ]);
  assert.equal(vote, 'yes');

  const rows = await ed25519Rows(app, IDENTITY_UUID);
  assert.equal(rows.length, 1, 'one active ed25519 row after the first push');
  assert.equal(keyB64(rows[0]), Buffer.from(ED_LIVE).toString('base64'));

  await app.close();
  await tx.close();
});

test('forced repair: re-applying an UNCHANGED payload repairs a damaged key row (the G4 goal)', async () => {
  const app = makeAppDb();
  const tx = makeTxDb();
  const participant = new ExchangePushParticipant('server:us-1', app, tx);
  const push = pushPayload();

  // 1. A successful push put the LIVE key on the server.
  await participant.prepare('tx-forced-1', [{ op: 'exchange:identity', params: { payload: push } }]);
  assert.equal(keyB64((await ed25519Rows(app, IDENTITY_UUID))[0]), Buffer.from(ED_LIVE).toString('base64'));

  // 2. The damage: the handshake (or the pre-G3a doc-scoped write) left the
  //    DOCUMENT-derived key, plus a legacy duplicate row. The agent's payload has
  //    NOT changed, so the ack-gated regular push skips it forever.
  await app.run(
    `UPDATE keys SET public_key = ? WHERE identity_uuid = ? AND key_type = 'ed25519' AND rotation_version = 0`,
    Buffer.from(ED_DOC), IDENTITY_UUID,
  );
  await app.run(
    `INSERT INTO keys (uuid, identity_uuid, did_document_uuid, key_type, public_key, rotation_version, created_at)
     VALUES ('legacy-duplicate', ?, NULL, 'ed25519', ?, 0, 1)`,
    IDENTITY_UUID, Buffer.from(ED_DOC),
  );
  assert.equal((await ed25519Rows(app, IDENTITY_UUID)).length, 2, 'precondition: damaged + duplicated state');

  // 3. The forced (un-gated) re-apply — what BaseAgent.forceIdentityPush does on
  //    connect/reconnect with the IDENTICAL payload the gate would have skipped.
  const vote = await participant.prepare('tx-forced-2', [
    { op: 'exchange:identity', params: { payload: push } },
  ]);
  assert.equal(vote, 'yes');

  // 4. Repaired for the READER: the row linked to the identity's primary document
  //    is the one `DsRelationshipStore.get()` prefers, and it now holds the key the
  //    agent actually signs with. (The push updates in place; it deliberately does
  //    NOT delete the stale duplicate — that is the reconciliation pass's job.)
  const primary = await app.get<{ uuid: string }>(
    'SELECT uuid FROM did_documents WHERE identity_uuid = ? AND is_primary = 1',
    IDENTITY_UUID,
  );
  const repaired = await ed25519Rows(app, IDENTITY_UUID);
  const primaryLinked = repaired.filter((r) => r.uuid !== 'legacy-duplicate');
  assert.equal(primaryLinked.length, 1, 'the real (non-legacy) key row is updated in place');
  assert.equal(
    keyB64(primaryLinked[0]), Buffer.from(ED_LIVE).toString('base64'),
    'the LIVE keystore key wins over the document-derived key',
  );
  assert.ok(primary, 'the pushed document is the primary');

  // 5. The cleanup completes it: the reconciliation pass removes the stale
  //    duplicate, keeping the primary-linked row (G3c keeper rule).
  const { reconcileIdentities } = await import('@p2p-trust-stack/core/db/reconcile-identities.js');
  const report = await reconcileIdentities(app, { fix: true });
  assert.equal(report.applied.keyFixes, 1, 'the duplicate active key is reported and repaired');
  const finalRows = await ed25519Rows(app, IDENTITY_UUID);
  assert.equal(finalRows.length, 1, 'exactly one active key row remains');
  assert.equal(
    keyB64(finalRows[0]), Buffer.from(ED_LIVE).toString('base64'),
    'the survivor is the LIVE key',
  );

  await app.close();
  await tx.close();
});
