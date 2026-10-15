/**
 * Governance gap-closure tests for the utility-server ceremony participant.
 *
 * The agent-driven founding path (ceremony_begin / ceremony_approve) is handled by
 * `CeremonyCoordinatorParticipant`, which previously did NOT apply the admin-set
 * check that `GovernanceGuard.validateCrystallization` applies on the core
 * (REST) path — so an arbitrary `approverUuid` was recorded and counted. These
 * tests pin the closure.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs \
 *     --test test/tx/ceremony-participant-governance.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { TX_SCHEMA_SQL } from '@p2p-trust-stack/core/tx/schema.js';
import { CeremonyStore } from '@p2p-trust-stack/core/tx/ceremony-store.js';
import { CeremonyCoordinatorParticipant } from '../../src/tx/ceremony-participant.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as keysRepo from '@p2p-trust-stack/core/db/repositories/keys-repo.js';
import { generateEd25519KeyPair, signEd25519 } from '@p2p-trust-stack/core/crypto/primitives.js';
import * as trustTasksRepo from '@p2p-trust-stack/core/db/repositories/trust-tasks-repo.js';
import {
  CEREMONY_PROPOSE_TYPE,
  CEREMONY_CO_SIGN_TYPE,
} from '@p2p-trust-stack/core/services/trust-tasks/type-uris.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

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

async function seedProposal(
  txDb: SqliteDataSource,
  ceremonyId: string,
  adminUuids: string[],
  proposerUuid: string,
): Promise<CeremonyStore> {
  const store = new CeremonyStore(txDb);
  await store.createProposal({
    proposalId: ceremonyId,
    proposerDid: proposerUuid,
    vtcDid: 'did:example:new-vtc',
    name: `VTC ${ceremonyId}`,
    kind: 'vtc',
    adminDids: adminUuids,
    adminUuids,
    threshold: 2,
    expiresAt: Date.now() + 60_000,
    proposalHash: 'hash',
    proposerUuid,
  });
  return store;
}

test('a ceremony approval from a non-admin is refused and not recorded', async () => {
  const appDb = makeAppDb();
  const txDb = makeTxDb();
  const ceremonyId = 'cer-intruder';
  const store = await seedProposal(txDb, ceremonyId, ['admin-1', 'admin-2'], 'admin-1');
  const participant = new CeremonyCoordinatorParticipant('server:us-1', appDb, txDb);

  const vote = await participant.prepare('tx-intruder', [{
    op: 'ceremony_approve',
    params: { ceremonyId, approverUuid: 'intruder', signature: 'x' },
  }]);

  assert.equal(vote, 'no', 'a non-admin approval must be refused');
  assert.equal(await store.countApprovals(ceremonyId), 0, 'the non-admin approval must not be counted');
  assert.equal((await store.getProposal(ceremonyId))!.status, 'pending', 'the proposal stays pending');
});

test('a ceremony approval from a founding admin is accepted (recorded)', async () => {
  const appDb = makeAppDb();
  const txDb = makeTxDb();
  const ceremonyId = 'cer-admin';
  const store = await seedProposal(txDb, ceremonyId, ['admin-1', 'admin-2'], 'admin-1');
  const participant = new CeremonyCoordinatorParticipant('server:us-1', appDb, txDb);

  // The admin's approval is accepted (recorded). Crystallization then proceeds —
  // it fails here only because the admin identities are not seeded in the app DB,
  // which is expected in this unit test — so the admin approval is what we assert.
  await participant.prepare('tx-admin', [{
    op: 'ceremony_approve',
    params: { ceremonyId, approverUuid: 'admin-1', signature: 'self-approve' },
  }]);

  assert.equal(await store.countApprovals(ceremonyId), 1, 'the founding admin approval is recorded');
});

test('ceremony_pending_for lists pending proposals for a founding admin (co-founder discovery)', async () => {
  const appDb = makeAppDb();
  const txDb = makeTxDb();
  await seedProposal(txDb, 'cer-mine', ['admin-1', 'admin-2'], 'admin-1');
  await seedProposal(txDb, 'cer-other', ['admin-9'], 'admin-9');
  const participant = new CeremonyCoordinatorParticipant('server:us-1', appDb, txDb);

  const rows = await participant.query('ceremony_pending_for', { adminUuid: 'admin-2' }) as Array<Record<string, unknown>>;
  assert.equal(rows.length, 1, 'only proposals the caller is a founding admin of');
  assert.equal(rows[0].ceremonyId, 'cer-mine');
  assert.equal(rows[0].threshold, 2);
  assert.equal(rows[0].approvalCount, 0);

  const none = await participant.query('ceremony_pending_for', { adminUuid: 'nobody' }) as unknown[];
  assert.equal(none.length, 0);
});

test('ceremony_pending_for is refused as an OPERATION (query-only)', async () => {
  const appDb = makeAppDb();
  const txDb = makeTxDb();
  const participant = new CeremonyCoordinatorParticipant('server:us-1', appDb, txDb);

  const vote = await participant.prepare('tx-list', [{
    op: 'ceremony_pending_for',
    params: { adminUuid: 'admin-1' },
  }]);
  assert.equal(vote, 'no', 'a read-only query must not run as an empty transaction');
});

/** Seed a VTA identity + its primary DID document + an Ed25519 key. */
async function seedVtaWithKey(
  appDb: SqliteDataSource,
  did: string,
): Promise<{ uuid: string; keyPair: ReturnType<typeof generateEd25519KeyPair> }> {
  const uuid = await identitiesRepo.create(appDb, { realDid: did, role: 'vta', name: did });
  await didDocumentsRepo.create(appDb, {
    identityUuid: uuid, did, method: 'scid', isPrimary: true,
  });
  const keyPair = generateEd25519KeyPair();
  await keysRepo.create(appDb, {
    identityUuid: uuid, keyType: 'ed25519', publicKey: Buffer.from(keyPair.publicKey),
  });
  return { uuid, keyPair };
}

test('regression: an admin approval is verified against the admin DID (UUID→DID resolution)', async () => {
  // The ceremony stores UUIDs, but GovernanceGuard.validateCrystallization is
  // DID-space — it checks the admin set against an approver's DID and resolves the
  // signing key BY DID. Wiring the guard in without resolving UUID→DID made every
  // real creation fail with "cannot resolve key for <uuid>". This pins the fix.
  const appDb = makeAppDb();
  const txDb = makeTxDb();
  const creator = await seedVtaWithKey(appDb, 'did:scid:vh:reg-creator');
  const cofounder = await seedVtaWithKey(appDb, 'did:scid:vh:reg-cofounder');

  const store = new CeremonyStore(txDb);
  const proposalHash = 'regression-proposal-hash';
  await store.createProposal({
    proposalId: 'cer-regression',
    proposerDid: creator.uuid,
    vtcDid: 'did:p2pts:ceremony:regression',
    name: 'Regression VTC',
    kind: 'vtc',
    adminDids: [creator.uuid, cofounder.uuid],
    adminUuids: [creator.uuid, cofounder.uuid],
    threshold: 1,
    expiresAt: Date.now() + 60_000,
    proposalHash,
    proposerUuid: creator.uuid,
  });

  // A REAL signature over the proposal hash — exactly what the agent now sends.
  const sig = signEd25519(new TextEncoder().encode(proposalHash), creator.keyPair.secretKey);
  const participant = new CeremonyCoordinatorParticipant('server:us-1', appDb, txDb);

  await participant.prepare('tx-regression', [{
    op: 'ceremony_approve',
    params: {
      ceremonyId: 'cer-regression',
      approverUuid: creator.uuid,
      signature: Buffer.from(sig).toString('base64'),
    },
  }]);

  const after = (await store.getProposal('cer-regression'))!;
  // The governance gate must PASS — any failure now comes later (createVtc needs
  // endpoints/VRCs, absent here), never the UUID/key-resolution error.
  assert.doesNotMatch(
    String(after.errorReason),
    /cannot resolve key|Crystallization denied/,
    'the guard must resolve the approver UUID to their DID, not look up a key for a UUID',
  );
});

/**
 * A community is founded only when EVERY declared founding admin has co-signed it.
 *
 * Naming someone an admin is a REQUEST to administer; signing the proposal hash
 * with the named identity's own Ed25519 key is the ACCEPTANCE. The creator's own
 * approval therefore must NOT found the community on the co-admin's behalf — and a
 * ceremony short of that quorum is PENDING, never 'failed'.
 */
test('a founding ceremony stays PENDING until every declared admin has co-signed', async () => {
  const appDb = makeAppDb();
  const txDb = makeTxDb();
  const creator = await seedVtaWithKey(appDb, 'did:scid:vh:cosign-creator');
  const cofounder = await seedVtaWithKey(appDb, 'did:scid:vh:cosign-cofounder');

  const store = new CeremonyStore(txDb);
  const proposalHash = 'cosign-proposal-hash';
  await store.createProposal({
    proposalId: 'cer-cosign',
    proposerDid: creator.uuid,
    vtcDid: 'did:p2pts:ceremony:cosign',
    name: 'Co-sign VTC',
    kind: 'vtc',
    adminDids: [creator.uuid, cofounder.uuid],
    adminUuids: [creator.uuid, cofounder.uuid],
    // M = 1: the CHANGE-approval quorum is deliberately minimal here, to show it is
    // not what governs the founding.
    threshold: 1,
    expiresAt: Date.now() + 60_000,
    proposalHash,
    proposerUuid: creator.uuid,
  });

  const participant = new CeremonyCoordinatorParticipant('server:us-1', appDb, txDb);
  const sign = (kp: ReturnType<typeof generateEd25519KeyPair>) =>
    Buffer.from(signEd25519(new TextEncoder().encode(proposalHash), kp.secretKey)).toString('base64');

  // 1. The creator approves alone.
  const creatorVote = await participant.prepare('tx-cosign-1', [{
    op: 'ceremony_approve',
    params: { ceremonyId: 'cer-cosign', approverUuid: creator.uuid, signature: sign(creator.keyPair) },
  }]);
  assert.equal(creatorVote, 'yes', 'a valid approval is recorded, not refused');
  assert.equal(await store.countApprovals('cer-cosign'), 1);

  const afterCreator = (await store.getProposal('cer-cosign'))!;
  assert.equal(afterCreator.status, 'pending', 'the creator cannot found it on the co-admin\'s behalf');
  assert.equal(afterCreator.errorReason, null, '"not yet" must not be recorded as a failure');

  // 2. The co-admin co-signs, releasing the quorum gate. Crystallization is then
  // attempted and may fail LATER for unrelated reasons — createVtc needs real
  // endpoints and mutual VRCs, which this fixture deliberately does not provide.
  await participant.prepare('tx-cosign-2', [{
    op: 'ceremony_approve',
    params: { ceremonyId: 'cer-cosign', approverUuid: cofounder.uuid, signature: sign(cofounder.keyPair) },
  }]);

  assert.equal(await store.countApprovals('cer-cosign'), 2);
  const afterCoSign = (await store.getProposal('cer-cosign'))!;
  assert.notEqual(afterCoSign.status, 'pending', 'the second co-signature releases the quorum gate');
  assert.doesNotMatch(
    String(afterCoSign.errorReason ?? ''),
    /not every founding admin|quorum/i,
    'any failure must be past the quorum gate, not a quorum shortfall',
  );
});

/**
 * The founding ceremony is ONE auditable thread.
 *
 * `CeremonyCoordinatorParticipant` records the COORDINATION half — the proposal and
 * each named admin's co-signature — into `trust_tasks` under the same `threadId` the
 * driver later uses for the `vtc-establish` steps. So "who was asked", "who accepted"
 * and "what ran" are all inspectable from one place.
 *
 * Assertions are content-based, not positional: `trust_tasks.created_at` is
 * second-resolution, so rows written in the same second tie-break on their random
 * uuid rather than on insertion order.
 */
test('the founding ceremony logs its proposal and every co-signature to the task log', async () => {
  const appDb = makeAppDb();
  const txDb = makeTxDb();
  const creator = await seedVtaWithKey(appDb, 'did:scid:vh:log-creator');
  const cofounder = await seedVtaWithKey(appDb, 'did:scid:vh:log-cofounder');
  const participant = new CeremonyCoordinatorParticipant('server:us-1', appDb, txDb);

  const ceremonyId = 'cer-tasklog';

  const beginVote = await participant.prepare('tx-log-1', [{
    op: 'ceremony_begin',
    params: {
      ceremonyId,
      proposerUuid: creator.uuid,
      name: 'Task Log VTC',
      kind: 'vtc',
      threshold: 1,
      adminUuids: [creator.uuid, cofounder.uuid],
    },
  }]);
  assert.equal(beginVote, 'yes');

  const thread = await trustTasksRepo.listByThread(appDb, ceremonyId);
  const proposeReq = thread.find(
    (r) => r.type === CEREMONY_PROPOSE_TYPE && r.direction === 'request',
  );
  const proposeRes = thread.find(
    (r) => r.type === CEREMONY_PROPOSE_TYPE && r.direction === 'response',
  );
  assert.ok(proposeReq, 'the proposal is logged as a request');
  assert.ok(proposeRes, 'and acknowledged as a response');
  assert.equal(proposeReq.issuerDid, creator.uuid);
  assert.equal(String(proposeRes.status), 'pending', 'the response states what it awaits');
  const proposeAck = JSON.parse(proposeRes.payload!) as { coSignaturesRequired: number };
  assert.equal(proposeAck.coSignaturesRequired, 2, 'every declared admin must co-sign');

  // `createProposal` hashes its own canonical form, so read the stored hash back.
  const storedHash = (await new CeremonyStore(txDb).getProposal(ceremonyId))!.proposalHash;
  const signStored = (kp: ReturnType<typeof generateEd25519KeyPair>) =>
    Buffer.from(signEd25519(new TextEncoder().encode(storedHash), kp.secretKey)).toString('base64');

  // 1. The creator co-signs.
  await participant.prepare('tx-log-2', [{
    op: 'ceremony_approve',
    params: { ceremonyId, approverUuid: creator.uuid, signature: signStored(creator.keyPair) },
  }]);

  const coSigns = () =>
    trustTasksRepo.listByThread(appDb, ceremonyId)
      .then((rows) => rows.filter((r) => r.type === CEREMONY_CO_SIGN_TYPE));

  let rows = await coSigns();
  const creatorAck = rows.find((r) => r.direction === 'response' && r.issuerDid === null
    && r.recipientDid === creator.uuid);
  assert.ok(creatorAck, 'the co-signature is logged as a request + response pair');
  assert.equal(creatorAck.status, 'allowed');
  assert.equal(
    (JSON.parse(creatorAck.payload!) as { coSignaturesReceived: number }).coSignaturesReceived,
    1,
  );
  assert.equal(
    (JSON.parse(creatorAck.payload!) as { quorumMet: boolean }).quorumMet,
    false,
    'the creator alone does not satisfy the quorum',
  );

  // 2. An outsider's attempt is REFUSED — and audited as denied.
  const intruderVote = await participant.prepare('tx-log-3', [{
    op: 'ceremony_approve',
    params: { ceremonyId, approverUuid: 'intruder', signature: 'x' },
  }]);
  assert.equal(intruderVote, 'no');
  rows = await coSigns();
  const denied = rows.find((r) => r.recipientDid === 'intruder' && r.status === 'denied');
  assert.ok(denied, 'a refused co-signature must still be recorded');

  // 3. The co-founder co-signs: the quorum is met.
  await participant.prepare('tx-log-4', [{
    op: 'ceremony_approve',
    params: { ceremonyId, approverUuid: cofounder.uuid, signature: signStored(cofounder.keyPair) },
  }]);
  rows = await coSigns();
  const cofounderAck = rows.find(
    (r) => r.direction === 'response' && r.recipientDid === cofounder.uuid,
  );
  assert.ok(cofounderAck);
  const finalAck = JSON.parse(cofounderAck.payload!) as {
    coSignaturesRequired: number; coSignaturesReceived: number; quorumMet: boolean;
  };
  assert.equal(finalAck.coSignaturesReceived, 2);
  assert.equal(finalAck.coSignaturesRequired, 2);
  assert.equal(finalAck.quorumMet, true, 'the community may now be founded');
});
