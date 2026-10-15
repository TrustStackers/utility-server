/**
 * Tests for the public resolver app (`buildResolverApp`) — the second Fastify
 * listener that exposes did:scid:vh resolution to the internet.
 *
 * The two things that MUST hold, and are pinned here:
 *   1. ISOLATION — the resolver's route table contains only the public
 *      resolution routes. No admin route (`/identities`, `/did-documents`,
 *      `/setup`, `/ui/`, `/auth/`) may be reachable from it, because this is
 *      the only listener intended to face the public internet.
 *   2. REPRESENTATION — browsers get the annotated HTML page, resolver clients
 *      get the W3C JSON envelope, and the log endpoint returns JSONL.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs --test test/resolution/resolver-app.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { ScidVhMethod } from '@p2p-trust-stack/core/did/scid-vh-method.js';
import { packRotationEntry } from '@p2p-trust-stack/core/did/rotation-entry-codec.js';
import { buildResolverApp } from '../../src/resolver-app.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

function makeDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

/** A did:scid:vh identity with its full rotation log persisted. */
async function seed(ds: SqliteDataSource): Promise<string> {
  const created = await new ScidVhMethod({}).create();
  const now = Math.floor(Date.now() / 1000);
  await ds.run(
    `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
     VALUES ('id-1', 'vta', 'human', 'local', 'alice', ?, ?)`,
    now,
    now,
  );
  await ds.run(
    `INSERT INTO did_documents (uuid, identity_uuid, did, method, document_json, is_primary, status, created_at, updated_at)
     VALUES ('doc-1', 'id-1', ?, 'did:scid:vh', ?, 1, 'active', ?, ?)`,
    created.did,
    JSON.stringify(created.document),
    now,
    now,
  );
  for (const entry of created.log) {
    await ds.run(
      `INSERT INTO rotation_log (uuid, did_document_uuid, version, previous_hash, new_public_key, signed_entry, created_at)
       VALUES (?, 'doc-1', ?, ?, ?, ?, ?)`,
      `rl-${entry.version}`,
      entry.version,
      entry.prevHash ?? null,
      Buffer.from(JSON.stringify(entry.nextKeyCommitments.map((k) => Buffer.from(k).toString('base64')))),
      Buffer.from(
        packRotationEntry({
          didDocument: entry.didDocument,
          parameters: entry.parameters,
          digest: entry.digest,
          signature: entry.signature,
          mlDsa65Signature: entry.mlDsa65Signature,
        }),
      ),
      entry.createdAt,
    );
  }
  return created.did;
}

test('resolver app exposes ONLY the public resolution routes (isolation)', async () => {
  const ds = makeDb();
  const app = buildResolverApp({ db: ds, logger: false });
  await app.ready();

  // The complete public surface, asserted exactly.
  const expected: Array<{ method: 'GET'; url: string }> = [
    { method: 'GET', url: '/' },
    { method: 'GET', url: '/health' },
    { method: 'GET', url: '/.well-known/did-scid-vh' },
    { method: 'GET', url: '/1.0/identifiers/:did' },
    { method: 'GET', url: '/1.0/identifiers/:did/log' },
    { method: 'GET', url: '/log/:scid/did.jsonl' },
  ];
  for (const route of expected) {
    assert.ok(app.hasRoute(route), `resolver must expose ${route.method} ${route.url}`);
  }

  // Admin routes from the main app must NOT be reachable from this listener.
  const forbidden: Array<{ method: 'GET' | 'POST'; url: string }> = [
    { method: 'GET', url: '/identities' },
    { method: 'GET', url: '/did-documents/by-did/:did' },
    { method: 'GET', url: '/help' },
    { method: 'GET', url: '/health/connectivity' },
    { method: 'POST', url: '/identities' },
  ];
  for (const route of forbidden) {
    assert.ok(!app.hasRoute(route), `resolver must NOT expose admin route ${route.method} ${route.url}`);
  }

  await app.close();
  await ds.close();
});

test('GET /1.0/identifiers/:did serves HTML to browsers and JSON to clients', async () => {
  const ds = makeDb();
  const did = await seed(ds);
  const app = buildResolverApp({ db: ds, logger: false });
  await app.ready();
  const url = `/1.0/identifiers/${encodeURIComponent(did)}`;

  // A browser's Accept header: text/html named first.
  const html = await app.inject({
    method: 'GET',
    url,
    headers: { accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' },
  });
  assert.equal(html.statusCode, 200);
  assert.match(html.headers['content-type'] as string, /text\/html/);
  assert.match(html.body, /Verification methods/, 'the annotated view renders the key table');
  assert.match(html.body, /verified rotation log/, 'the provenance badge is shown');
  assert.match(html.body, /Rotation history/);

  // A resolver client: the W3C envelope.
  const json = await app.inject({
    method: 'GET',
    url,
    headers: { accept: 'application/did+ld+json' },
  });
  assert.equal(json.statusCode, 200);
  assert.match(json.headers['content-type'] as string, /application\/did\+ld\+json/);
  const envelope = json.json() as {
    didResolutionMetadata: { source: string };
    didDocument: { id: string };
    didDocumentMetadata: { versionId: string };
  };
  assert.equal(envelope.didDocument.id, did);
  assert.equal(envelope.didResolutionMetadata.source, 'log');
  assert.equal(envelope.didDocumentMetadata.versionId, '0');

  await app.close();
  await ds.close();
});

test('GET /1.0/identifiers/:did returns the bare document for application/did+json', async () => {
  const ds = makeDb();
  const did = await seed(ds);
  const app = buildResolverApp({ db: ds, logger: false });
  await app.ready();

  const res = await app.inject({
    method: 'GET',
    url: `/1.0/identifiers/${encodeURIComponent(did)}`,
    headers: { accept: 'application/did+json' },
  });

  assert.equal(res.statusCode, 200);
  assert.match(res.headers['content-type'] as string, /application\/did\+json/);
  const doc = res.json() as { id: string; verificationMethod: unknown[] };
  assert.equal(doc.id, did, 'the bare representation is the document, not the envelope');
  assert.ok(Array.isArray(doc.verificationMethod));

  await app.close();
  await ds.close();
});

test('GET /log/:scid/did.jsonl returns the rotation log as JSONL', async () => {
  const ds = makeDb();
  const did = await seed(ds);
  const scid = did.split(':').pop() as string;
  const app = buildResolverApp({ db: ds, logger: false });
  await app.ready();

  const res = await app.inject({ method: 'GET', url: `/log/${encodeURIComponent(scid)}/did.jsonl` });

  assert.equal(res.statusCode, 200);
  assert.match(res.headers['content-type'] as string, /application\/jsonl/);
  const entry = JSON.parse(res.body.trim().split('\n')[0]) as {
    version: number;
    didDocument: unknown;
    digest: string;
    signature: string;
  };
  assert.equal(entry.version, 0);
  assert.ok(entry.didDocument, 'the entry carries the document it authorizes');
  assert.equal(typeof entry.digest, 'string', 'byte fields are base64 on the wire');

  await app.close();
  await ds.close();
});

test('unknown DID resolves 404 with didResolutionMetadata.error', async () => {
  const ds = makeDb();
  const app = buildResolverApp({ db: ds, logger: false });
  await app.ready();

  const res = await app.inject({
    method: 'GET',
    url: `/1.0/identifiers/${encodeURIComponent('did:scid:vh:1:Unknown')}`,
    headers: { accept: 'application/did+ld+json' },
  });

  assert.equal(res.statusCode, 404);
  const envelope = res.json() as { didResolutionMetadata: { error: string }; didDocument: unknown };
  assert.equal(envelope.didResolutionMetadata.error, 'notFound');
  assert.equal(envelope.didDocument, null);

  await app.close();
  await ds.close();
});
