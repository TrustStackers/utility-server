// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `namespace_info` — the query that lets an agent name its server's namespace VTN as a parent.
 *
 * The bug this closes: the agent-app's create-community page showed *"Parent VTN: None —
 * standalone VTC"* even though the server had a namespace VTN configured. The picker read
 * only the agent's LOCAL communities, and the VTN is a **server-side identity** that an
 * agent receives only if it is a **member** of it — the agents here belong to a VTC, not to
 * the VTN, so nothing local existed to offer. Meanwhile the server already accepted
 * `parentCommunityUuid` and wired the affiliation; only discovery was missing.
 *
 * Two properties matter and are tested here:
 *   1. the query returns what the picker needs — the configured namespace, the parent's
 *      identity uuid (exactly what `vtc_create.parentCommunityUuid` expects), and the
 *      VTN's own name/DID for display;
 *   2. `handlesOperation` claims it, because the coordinator's `tx_query` dispatch reuses
 *      that predicate to find the answering participant (src/tx/coordinator.ts) — while
 *      the same op sent as an *operation* is refused rather than run as an empty tx.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ../test-loader.mjs --test test/tx/namespace-info-query.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import { setNamespaceConfig } from '../../src/services/namespace-service.js';
import { VtcCreationParticipant } from '../../src/tx/vtc-participant.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();
const VTN_DID = 'did:scid:vh:1:zNamespaceVtn';

async function harness(configured: boolean): Promise<{
  participant: VtcCreationParticipant; ds: SqliteDataSource; vtnUuid: string;
}> {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);

  // `namespace_config` is the one table the server's schema has that the shared SQLite
  // schema deliberately omits (see 0018_namespace_config.sql's own header), and the
  // server's dialect is YugabyteDB — so the fixture mirrors that definition here.
  await ds.run(
    `CREATE TABLE IF NOT EXISTS namespace_config (
       uuid TEXT PRIMARY KEY, vtn_identity_uuid TEXT NOT NULL UNIQUE,
       namespace TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
     )`,
  );

  const vtnUuid = generateUuid();
  await identitiesRepo.create(ds, {
    uuid: vtnUuid, realDid: VTN_DID, role: 'vtn', subjectKind: 'organization',
    custody: 'local', name: 'Trust Stackers', recordedByNode: 'test',
  });
  // The DID lives in did_documents, and `findByUuid` resolves it from there — without this
  // the VTN's `did` comes back null and the picker would have no DID to show.
  await didDocumentsRepo.create(ds, {
    identityUuid: vtnUuid, did: VTN_DID, method: 'did:scid:vh', isPrimary: true, recordedByNode: 'test',
  });
  if (configured) await setNamespaceConfig(ds, { vtnIdentityUuid: vtnUuid, namespace: 'p2pts' });

  return { participant: new VtcCreationParticipant('us-1', ds, ds), ds, vtnUuid };
}

test('namespace_info: returns the namespace AND the parent uuid the picker must submit', async () => {
  const { participant, ds, vtnUuid } = await harness(true);
  try {
    const info = await participant.query('namespace_info', {}) as Record<string, unknown>;

    assert.equal(info.configured, true);
    assert.equal(info.namespace, 'p2pts');
    // This uuid is the value `vtc_create.parentCommunityUuid` carries, and what
    // affiliateVtc() looks the parent up by — so it must be the identity uuid.
    assert.equal(info.vtnUuid, vtnUuid);
    assert.equal(info.vtnName, 'Trust Stackers', 'the VTN name is available for display');
    assert.equal(info.vtnDid, VTN_DID);
  } finally {
    await ds.close();
  }
});

test('namespace_info: an unconfigured node answers plainly instead of throwing', async () => {
  const { participant, ds } = await harness(false);
  try {
    const info = await participant.query('namespace_info', {}) as Record<string, unknown>;
    assert.equal(info.configured, false);
    assert.equal(info.namespace, null);
    assert.equal(info.vtnUuid, null, 'the picker must not be offered a parent that does not exist');
  } finally {
    await ds.close();
  }
});

test('namespace_info is CLAIMED by this participant — that is what routes the tx_query here', async () => {
  const { participant, ds } = await harness(true);
  try {
    // The coordinator dispatches a query through findParticipantForOperations, i.e. this
    // predicate. If it stopped claiming the op, queries would answer
    // "no participant handles the query" and the picker would silently go empty again.
    assert.equal(participant.handlesOperation({ op: 'namespace_info', params: {} } as never), true);
  } finally {
    await ds.close();
  }
});

test('namespace_info as an OPERATION is refused, not run as an empty transaction', async () => {
  const { participant, ds } = await harness(true);
  try {
    const vote = await participant.prepare('tx-namespace-info', [
      { op: 'namespace_info', params: {} } as never,
    ]);
    assert.equal(vote, 'no', 'a read-only query must not be accepted as a write');
  } finally {
    await ds.close();
  }
});
