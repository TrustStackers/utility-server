/**
 * Test helpers for the utility-server setup / namespace test suites.
 * Builds an in-memory SQLite DataSource with the shared core schema (0001-0019)
 * plus the utility-server-only `namespace_config` table (the SQLite twin of the
 * PG-only migration 0020), and seeds real VTA fixtures.
 */

import { mkdirSync } from 'node:fs';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { encryptSecretKey } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
import { getVtaPaths } from '@p2p-trust-stack/core/platform/p2pts-home.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

export function makeTestDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  const raw = ds.getRawDb() as unknown as { exec(sql: string): void };
  runMigrations(raw as never, MIGRATIONS_DIR);
  // namespace_config is utility-server-only (PG migration 0020) so it has no
  // core/src/db twin; create the SQLite equivalent here for local tests.
  raw.exec(`
    CREATE TABLE IF NOT EXISTS namespace_config (
      uuid              TEXT PRIMARY KEY,
      vtn_identity_uuid TEXT NOT NULL UNIQUE,
      namespace         TEXT NOT NULL UNIQUE,
      created_at        INTEGER NOT NULL DEFAULT (unixepoch()),
      updated_at        INTEGER NOT NULL DEFAULT (unixepoch())
    );
  `);
  return ds;
}

/** Seed a REAL human VTA with a primary DID document and an active endpoint. */
export async function seedRealVta(
  ds: SqliteDataSource,
  opts: { uuid: string; name?: string; did?: string },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const did = opts.did ?? `did:scid:vh:${opts.uuid}`;
  await ds.run(
    `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
     VALUES (?, 'vta', 'human', 'local', ?, ?, ?)`,
    opts.uuid, opts.name ?? 'alice', now, now,
  );
  await ds.run(
    `INSERT INTO did_documents (uuid, identity_uuid, did, method, document_json, is_primary, created_at)
     VALUES (?, ?, ?, 'did:scid:vh', ?, 1, ?)`,
    `${opts.uuid}-doc`, opts.uuid, did, '{}', now,
  );
  await ds.run(
    `INSERT INTO peer_endpoints (uuid, identity_uuid, peer_id, is_active, created_at, updated_at)
     VALUES (?, ?, ?, 1, ?, ?)`,
    `${opts.uuid}-peer`, opts.uuid, `12D3KooW${opts.uuid.replace(/-/g, '')}`, now, now,
  );
  return opts.uuid;
}

/**
 * Create + seed a LOCAL agent-app VTA database at
 * `home/vta/<agentKey>/p2pts-database.db`, the way the agent-app does (shared
 * schema + local-custody VTA + published keys). Each agent owns its own dir.
 */
export async function seedLocalVtaDb(
  home: string,
  opts: {
    uuid: string;
    did: string;
    name?: string;
    subjectKind?: string;
    passphrase?: string;
    peerId?: string;
    withEndpoint?: boolean;
  },
): Promise<void> {
  const passphrase = opts.passphrase ?? 'test-passphrase';
  const peerId = opts.peerId ?? `12D3KooW${opts.uuid.replace(/-/g, '')}`;
  const withEndpoint = opts.withEndpoint !== false;
  const agentPaths = getVtaPaths(opts.name ?? 'alice', home);
  mkdirSync(agentPaths.agentDir, { recursive: true });
  const ds = new SqliteDataSource(agentPaths.dbPath);
  const raw = ds.getRawDb() as unknown as { exec(sql: string): void };
  runMigrations(raw as never, MIGRATIONS_DIR);

  const now = Math.floor(Date.now() / 1000);
  await ds.run(
    `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
     VALUES (?, 'vta', ?, 'local', ?, ?, ?)`,
    opts.uuid, opts.subjectKind ?? 'human', opts.name ?? 'alice', now, now,
  );
  await ds.run(
    `INSERT INTO did_documents (uuid, identity_uuid, did, method, document_json, is_primary, created_at)
     VALUES (?, ?, ?, 'did:scid:vh', ?, 1, ?)`,
    `${opts.uuid}-doc`, opts.uuid, opts.did, JSON.stringify({ id: opts.did }), now,
  );

  // Ed25519 key with an encrypted secret (passphrase-verifiable) + X25519 key.
  const edPub = new Uint8Array(32).fill(1);
  const xPub = new Uint8Array(32).fill(2);
  const edSecret = new Uint8Array(32).fill(9);
  const enc = await encryptSecretKey(edSecret, passphrase);
  await ds.run(
    `INSERT INTO keys (uuid, identity_uuid, key_type, public_key, encrypted_secret_key, salt, nonce, auth_tag, rotation_version, created_at)
     VALUES (?, ?, 'ed25519', ?, ?, ?, ?, ?, 0, ?)`,
    `${opts.uuid}-key-ed`, opts.uuid, edPub, enc.ciphertext, enc.salt, enc.nonce, enc.authTag, now,
  );
  await ds.run(
    `INSERT INTO keys (uuid, identity_uuid, key_type, public_key, rotation_version, created_at)
     VALUES (?, ?, 'x25519', ?, 0, ?)`,
    `${opts.uuid}-key-x`, opts.uuid, xPub, now,
  );

  if (withEndpoint) {
    await ds.run(
      `INSERT INTO peer_endpoints (uuid, identity_uuid, peer_id, is_active, created_at, updated_at)
       VALUES (?, ?, ?, 1, ?, ?)`,
      `${opts.uuid}-peer`, opts.uuid, peerId, now, now,
    );
  }

  await ds.close();
}
