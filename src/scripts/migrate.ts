// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Standalone migration runner for the utility server.
 * Opens the database, runs all pending migrations, then closes.
 *
 * Usage:
 *   npm run migrate           apply pending migrations
 *   npm run migrate -- --reset  DELETE the local dev DB first, then migrate
 *
 * ⚠ This is the SQLite **dev** path: it writes `utility-server/data/utility-server.db`
 * using the ROOT (SQLite) migration set. It is NOT how the server's real YugabyteDB
 * gets its schema — that happens when the server boots (`npm start`).
 *
 * `--reset` exists because the ledger (`schema_migrations`) keys on FILENAME: when a
 * migration file is removed as part of a fold-in (e.g. 0017–0019 into 0001–0016), the
 * deleted name stays recorded, so this local DB keeps that schema marker with no file
 * behind it. Dropping the file and re-migrating from empty is the clean recovery. Only
 * ever run it against a dev database.
 */
import { openDatabase } from '@p2p-trust-stack/core/db/connection.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { existsSync, rmSync } from 'node:fs';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = getMigrationsDir();
const DB_PATH = join(__dirname, '..', '..', 'data', 'utility-server.db');

const reset = process.argv.includes('--reset');
if (reset) {
  // SQLite may leave -wal/-shm siblings; removing the main file alone can resurrect
  // uncommitted state from the journal on the next open.
  for (const suffix of ['', '-wal', '-shm']) {
    const p = `${DB_PATH}${suffix}`;
    if (existsSync(p)) {
      rmSync(p, { force: true });
      console.log(`--reset: removed ${p}`);
    }
  }
}

const db = openDatabase(DB_PATH);
try {
  const applied = runMigrations(db, MIGRATIONS_DIR);
  if (applied.length > 0) {
    console.log(`Applied ${applied.length} migration(s): ${applied.join(', ')}`);
  } else {
    console.log('No pending migrations.');
  }
} finally {
  db.close();
}