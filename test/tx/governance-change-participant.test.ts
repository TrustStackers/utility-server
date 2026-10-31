// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Phase B — GovernanceChangeParticipant: begin → signed approvals → crystallize, with
 * the approved change actually APPLIED. Consent is real Ed25519 over the proposal hash,
 * and crystallization runs the cataloged `governance-change` ceremony (policy gate +
 * apply effect) inside one transaction.
 *
 * Run:
 *   cd utility-server && node --experimental-strip-types --loader ../test-loader.mjs \
 *     --test test/tx/governance-change-participant.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { TX_SCHEMA_SQL, applyTxSchemaAdditions } from '@p2p-trust-stack/core/tx/schema.js';
import { GovernanceChangeParticipant } from '../../src/tx/governance-change-participant.js';
import { seedDefaultBindings } from '@p2p-trust-stack/core/services/policy-bindings.js';
import * as governanceRepo from '@p2p-trust-stack/core/db/repositories/governance-repo.js';
import { generateEd25519KeyPair, signEd25519 } from '@p2p-trust-stack/core/crypto/primitives.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();
const COMMUNITY_UUID = 'c0000000-0000-4000-8000-000000000001';
const COMMUNITY_DID = 'did:scid:vh:club';
const ALICE = 'a0000000-0000-4000-8000-000000000001';
const BOB = 'b0000000-0000-4000-8000-000000000002';

async function seed() {
  const appDb = new SqliteDataSource(':memory:');
  runMigrations(appDb.getRawDb(), MIGRATIONS_DIR);
  const txDb = new SqliteDataSource(':memory:');
  await txDb.exec(TX_SCHEMA_SQL);
  await applyTxSchemaAdditions(txDb);

  const now = Math.floor(Date.now() / 1000);
  await appDb.run(
    `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
     VALUES (?, 'vtc', 'organization', 'local', 'Chess Club', ?, ?)`, COMMUNITY_UUID, now, now);
  await appDb.run(
    `INSERT INTO did_documents (uuid, identity_uuid, did, method, document_json, is_primary, created_at)
     VALUES (?, ?, ?, 'did:scid:vh', '{}', 1, ?)`, `${COMMUNITY_UUID}-doc`, COMMUNITY_UUID, COMMUNITY_DID, now);

  const keys: Record<string, ReturnType<typeof generateEd25519KeyPair>> = {};
  for (const [uuid, did, name] of [[ALICE, 'did:scid:vh:alice', 'Alice'], [BOB, 'did:scid:vh:bob', 'Bob']] as const) {
    const kp = generateEd25519KeyPair();
    keys[uuid] = kp;
    await appDb.run(
      `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
       VALUES (?, 'vta', 'human', 'local', ?, ?, ?)`, uuid, name, now, now);
    await appDb.run(
      `INSERT INTO did_documents (uuid, identity_uuid, did, method, document_json, is_primary, created_at)
       VALUES (?, ?, ?, 'did:scid:vh', '{}', 1, ?)`, `${uuid}-doc`, uuid, did, now);
    await appDb.run(
      `INSERT INTO keys (uuid, identity_uuid, key_type, public_key, rotation_version, created_at)
       VALUES (?, ?, 'ed25519', ?, 0, ?)`, `${uuid}-key`, uuid, kp.publicKey, now);
    await appDb.run(
      `INSERT INTO memberships (uuid, member_identity_uuid, community_identity_uuid, role, status, issued_at)
       VALUES (?, ?, ?, 'founding_admin', 'active', ?)`, `${uuid}-mem`, uuid, COMMUNITY_UUID, now);
  }

  await governanceRepo.create(appDb, {
    communityIdentityUuid: COMMUNITY_UUID, adminThresholdM: 1, adminThresholdN: 2,
  });
  await seedDefaultBindings(appDb, COMMUNITY_UUID, 'vtc');

  const participant = new GovernanceChangeParticipant('server:us-1', appDb, txDb);
  return { appDb, keys, participant };
}

test('governance-change: all admins must approve before the change applies', async () => {
  const { appDb, keys, participant } = await seed();
  const proposalId = 'p0000000-0000-4000-8000-000000000001';

  const begun = await participant.prepare('tx-1', [{
    op: 'gov_change_begin',
    params: { proposalId, communityUuid: COMMUNITY_UUID, proposerUuid: ALICE, change: { adminThresholdM: 2, adminThresholdN: 3 } },
  }]);
  assert.equal(begun, 'yes');

  const q = await participant.query('gov_change_query', { proposalId }) as {
    status: string; proposalHash: string; requiredApproverCount: number;
  };
  assert.equal(q.status, 'pending');
  assert.equal(q.requiredApproverCount, 2, 'default scope = all admins');

  // One of two admins approves — NOT enough.
  await participant.prepare('tx-2', [{
    op: 'gov_change_approve', params: { proposalId, approverUuid: ALICE, signature: sign(keys, ALICE, q.proposalHash) },
  }]);
  assert.equal((await participant.query('gov_change_query', { proposalId }) as { status: string }).status, 'pending');
  assert.equal((await governanceRepo.findForCommunity(appDb, COMMUNITY_UUID))?.adminThresholdM, 1, 'unchanged so far');

  // The second admin approves — now it crystallizes and applies.
  await participant.prepare('tx-3', [{
    op: 'gov_change_approve', params: { proposalId, approverUuid: BOB, signature: sign(keys, BOB, q.proposalHash) },
  }]);
  assert.equal((await participant.query('gov_change_query', { proposalId }) as { status: string }).status, 'crystallized');

  const gov = await governanceRepo.findForCommunity(appDb, COMMUNITY_UUID);
  assert.equal(gov?.adminThresholdM, 2, 'threshold M applied');
  assert.equal(gov?.adminThresholdN, 3, 'threshold N applied');
});

test('governance-change: a forged signature does NOT count toward the quorum', async () => {
  const { appDb, keys, participant } = await seed();
  const proposalId = 'p0000000-0000-4000-8000-000000000002';

  await participant.prepare('tx-1', [{
    op: 'gov_change_begin',
    params: { proposalId, communityUuid: COMMUNITY_UUID, proposerUuid: ALICE, change: { adminThresholdM: 4 } },
  }]);
  const q = await participant.query('gov_change_query', { proposalId }) as { proposalHash: string };

  // Alice signs; Bob submits Alice's signature (not verifiable as Bob's) → not counted.
  await participant.prepare('tx-2', [{
    op: 'gov_change_approve', params: { proposalId, approverUuid: ALICE, signature: sign(keys, ALICE, q.proposalHash) },
  }]);
  await participant.prepare('tx-3', [{
    op: 'gov_change_approve', params: { proposalId, approverUuid: BOB, signature: sign(keys, ALICE, q.proposalHash) },
  }]);

  const after = await participant.query('gov_change_query', { proposalId }) as { status: string };
  assert.equal(after.status, 'pending', 'a signature that does not verify must not reach quorum');
  assert.equal((await governanceRepo.findForCommunity(appDb, COMMUNITY_UUID))?.adminThresholdM, 1);
});


/**
 * REGRESSION: an identity may hold a SECOND Ed25519 key — the did:peer:4
 * relationship-handshake stub's — alongside its authoritative did:scid:vh one, both at
 * `rotation_version` 0. `findByIdentityUuid` orders only by `(key_type, rotation_version)`,
 * so "the first Ed25519 key" is arbitrary: verifying against just that one silently drops
 * valid signatures, and a proposal with EVERY required approval recorded then sits below its
 * quorum forever (the change never applies).
 */
test('governance-change: a second (stub) Ed25519 key on an identity must not drop its approval', async () => {
  const { appDb, keys, participant } = await seed();
  const proposalId = 'p0000000-0000-4000-8000-000000000003';
  const now = Math.floor(Date.now() / 1000);

  // Control the tie-break deliberately: re-insert Bob's REAL key so a STALE key is the first
  // Ed25519 row for his identity. A first-match-only verifier rejects his signature here.
  const real = await appDb.get<{ uuid: string; public_key: Uint8Array; did_document_uuid: string }>(
    `SELECT uuid, public_key, did_document_uuid FROM keys WHERE identity_uuid = ? AND key_type = 'ed25519'`,
    BOB,
  );
  assert.ok(real, 'seed must have registered Bob an Ed25519 key');
  await appDb.run('DELETE FROM keys WHERE uuid = ?', real!.uuid);
  await appDb.run(
    `INSERT INTO keys (uuid, identity_uuid, did_document_uuid, key_type, public_key, rotation_version, created_at)
     VALUES (?, ?, ?, 'ed25519', ?, 0, ?)`,
    `${BOB}-stub-key`, BOB, real!.did_document_uuid, generateEd25519KeyPair().publicKey, now,
  );
  await appDb.run(
    `INSERT INTO keys (uuid, identity_uuid, did_document_uuid, key_type, public_key, rotation_version, created_at)
     VALUES (?, ?, ?, 'ed25519', ?, 0, ?)`,
    real!.uuid, BOB, real!.did_document_uuid, real!.public_key, now,
  );

  await participant.prepare('tx-1', [{
    op: 'gov_change_begin',
    params: { proposalId, communityUuid: COMMUNITY_UUID, proposerUuid: ALICE, change: { adminThresholdM: 2 } },
  }]);
  const q = await participant.query('gov_change_query', { proposalId }) as { proposalHash: string };

  await participant.prepare('tx-2', [
    { op: 'gov_change_approve', params: { proposalId, approverUuid: ALICE, signature: sign(keys, ALICE, q.proposalHash) } },
    { op: 'gov_change_approve', params: { proposalId, approverUuid: BOB, signature: sign(keys, BOB, q.proposalHash) } },
  ]);

  const after = await participant.query('gov_change_query', { proposalId }) as {
    status: string; verifiedApproverCount: number;
  };
  assert.equal(after.verifiedApproverCount, 2, 'both signatures verify against SOME registered key');
  assert.equal(after.status, 'crystallized', 'the quorum must be reached despite the extra key');
  assert.equal((await governanceRepo.findForCommunity(appDb, COMMUNITY_UUID))?.adminThresholdM, 2);
});


function sign(keys: Record<string, { secretKey: Uint8Array }>, uuid: string, hash: string): string {
  return Buffer.from(signEd25519(new TextEncoder().encode(hash), keys[uuid].secretKey)).toString('base64');
}
