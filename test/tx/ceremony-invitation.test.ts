// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The member-INVITATION ceremony (migration 0023): driving `member-invitation` issues a
 * signed VIC — the credential authorizing one named prospective member to onboard — and
 * records every step in the task log.
 *
 * This is where the VIC's signing coverage lives. It used to sit in
 * test/vtc/vic-mint.test.ts against a standalone `mintInvitationVic()` helper; that
 * helper is gone, because a second mint path is exactly what made an invitation
 * impossible to trace through the log.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs --test test/tx/ceremony-invitation.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { driveCeremony } from '@p2p-trust-stack/core/services/trust-tasks/driver.js';
import { guardAuthorizer } from '@p2p-trust-stack/core/services/trust-tasks/authorizer.js';
import {
  CEREMONY_MEMBER_INVITATION,
  INVITATION_VIC_TYPE,
} from '@p2p-trust-stack/core/services/trust-tasks/type-uris.js';
import {
  listCeremonyThreads,
  getCeremonyThread,
} from '@p2p-trust-stack/core/services/trust-tasks/ceremony-log.js';
import { GovernanceGuard } from '@p2p-trust-stack/core/services/governance-guard.js';
import { createPolicyEngine } from '@p2p-trust-stack/core/services/policy-engine-config.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as keysRepo from '@p2p-trust-stack/core/db/repositories/keys-repo.js';
import * as credentialsRepo from '@p2p-trust-stack/core/db/repositories/credentials-repo.js';
import { seedDefaultBindings } from '@p2p-trust-stack/core/services/policy-bindings.js';
import { DidManager, COMMUNITY_KEY_PASSPHRASE } from '@p2p-trust-stack/core/services/did-manager.js';
import { generateEd25519KeyPair } from '@p2p-trust-stack/core/crypto/primitives.js';
import { encryptSecretKey } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
// Importing the participant registers the ceremony's effect executors (server side).
import '../../src/tx/ceremony-participant.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

/** A community with a persisted signing key, plus a prospective member. */
async function seed(): Promise<{
  ds: SqliteDataSource; communityUuid: string; communityDid: string; subjectUuid: string;
  verificationMethod: string; signerSecretKey: Uint8Array; vid: string;
}> {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);

  const communityDid = 'did:scid:vh:invite-club';
  const communityUuid = await identitiesRepo.create(ds, {
    realDid: communityDid, role: 'vtc', custody: 'local', name: 'Invite Club',
  });
  const docUuid = await didDocumentsRepo.create(ds, {
    identityUuid: communityUuid, did: communityDid, method: 'scid', isPrimary: true,
  });
  const kp = generateEd25519KeyPair();
  const enc = await encryptSecretKey(kp.secretKey, COMMUNITY_KEY_PASSPHRASE);
  await keysRepo.createWithSecret(ds, {
    identityUuid: communityUuid, didDocumentUuid: docUuid, keyType: 'ed25519',
    publicKey: kp.publicKey, encryptedSecretKey: enc.ciphertext,
    salt: enc.salt, nonce: enc.nonce, authTag: enc.authTag,
  });

  const subjectUuid = await identitiesRepo.create(ds, {
    realDid: 'did:scid:vh:invite-guest', role: 'vta', custody: 'remote', name: 'Guest',
  });
  await didDocumentsRepo.create(ds, {
    identityUuid: subjectUuid, did: 'did:scid:vh:invite-guest', method: 'scid', isPrimary: true,
  });

  await seedDefaultBindings(ds, communityUuid, 'vtc');

  const key = await new DidManager(ds).resolveCommunitySigningKey(communityUuid);
  assert.ok(key, 'the community signing key must resolve');
  return {
    ds, communityUuid, communityDid, subjectUuid,
    verificationMethod: key.verificationMethod, signerSecretKey: key.signerSecretKey, vid: key.vid,
  };
}

/** The ceremony context the invite producers build (shared by both tests). */
function inviteContext(db: unknown, seeded: Awaited<ReturnType<typeof seed>>, actorDid: string) {
  return {
    db,
    communityUuid: seeded.communityUuid,
    communityDid: seeded.communityDid,
    subjectIdentityUuid: seeded.subjectUuid,
    actorDid,
    params: { kind: 'InvitationCredential', subjectDid: 'did:scid:vh:invite-guest' },
    oobi: {
      vid: seeded.vid, peerId: '12D3KooWTestPeer',
      multiaddrs: ['/ip4/127.0.0.1/tcp/4001'], did: seeded.communityDid,
    },
    taskContext: 'invite:test',
    verificationMethod: seeded.verificationMethod,
    signerSecretKey: seeded.signerSecretKey,
  };
}

test('driving member-invitation issues a signed VIC and logs the ceremony', async () => {
  const seeded = await seed();
  const threadId = 'invite-thread-1';

  const driven = await seeded.ds.transaction((tx) =>
    driveCeremony(tx, CEREMONY_MEMBER_INVITATION, threadId, {
      authorizer: guardAuthorizer(new GovernanceGuard(tx, createPolicyEngine())),
      context: inviteContext(tx, seeded, seeded.communityDid),
    }),
  );

  assert.equal(driven.completed, true, `ceremony halted at ${driven.haltedAt}`);

  // The effect step produced a signed DTG InvitationCredential.
  const issued = driven.outputs[INVITATION_VIC_TYPE] as { credentialUuid?: string; vicJson?: string };
  assert.ok(issued?.credentialUuid, 'the ceremony must produce a credential');
  const vc = JSON.parse(issued!.vicJson!);
  assert.ok(vc.type.includes('InvitationCredential'), 'VC type should include InvitationCredential');
  assert.ok(vc.proof?.proofValue, 'VC should carry a DataIntegrityProof value');
  assert.equal(vc.issuer, seeded.communityDid);

  const row = await credentialsRepo.findByUuid(seeded.ds, issued!.credentialUuid!);
  assert.ok(row, 'credential row should exist');
  assert.equal(row!.vcType, 'vic', 'credential should be stored with vc_type=vic');
  assert.ok(row!.w3cVcJson, 'credential should carry signed W3C VC JSON');

  // …and every step is in the task log, IN ORDER: request + response for the gate,
  // then request + response for the mint.
  const steps = await getCeremonyThread(seeded.ds, threadId);
  assert.deepEqual(steps.map((s) => s.type), [
    'task:p2pts:policy:invitation-vic-authorized:0.1',
    'task:p2pts:policy:invitation-vic-authorized:0.1',
    INVITATION_VIC_TYPE,
    INVITATION_VIC_TYPE,
  ]);
  assert.deepEqual(steps.map((s) => s.direction), ['request', 'response', 'request', 'response']);
  assert.equal(steps[1].status, 'allowed', 'the gate allowed it');
  assert.equal(steps[3].status, 'completed');

  // Each step carries its CATALOG wording — that is what lets the UI render a sentence
  // without a label table of its own.
  assert.equal(steps[0].display?.label, 'Policy check — may this invitation be issued?');
  assert.match(String(steps[3].display?.response), /Invitation credential issued/);

  // The index names the run from its steps, and carries the ceremony's own title.
  const threads = await listCeremonyThreads(seeded.ds);
  const entry = threads.find((t) => t.threadId === threadId);
  assert.equal(entry?.ceremony, CEREMONY_MEMBER_INVITATION);
  assert.equal(entry?.ceremonyLabel, 'Invite a person to join');
  assert.ok(entry?.ceremonyDescription, 'the ceremony description comes from the catalog');
});

test('a denied invitation gate mints nothing (the policy is the only authority)', async () => {
  const seeded = await seed();
  const threadId = 'invite-thread-2';

  // An actor who is neither an admin nor the community: the baseline `vic-issue` rule
  // requires `actor_is_admin`, so the gate must refuse and the mint must never run.
  const driven = await seeded.ds.transaction((tx) =>
    driveCeremony(tx, CEREMONY_MEMBER_INVITATION, threadId, {
      authorizer: guardAuthorizer(new GovernanceGuard(tx, createPolicyEngine())),
      context: inviteContext(tx, seeded, 'did:scid:vh:not-an-admin'),
    }),
  );

  assert.equal(driven.completed, false, 'the gate must halt the ceremony');
  assert.equal(driven.haltedAt, 'task:p2pts:policy:invitation-vic-authorized:0.1');
  assert.equal(driven.outputs[INVITATION_VIC_TYPE], undefined, 'no credential may be minted');

  // The refusal is recorded, not silent — and no mint step was recorded at all.
  const steps = await getCeremonyThread(seeded.ds, threadId);
  assert.equal(steps.length, 2, 'the gate records a request and a denial');
  assert.equal(steps[1].direction, 'response');
  assert.equal(steps[1].status, 'denied');
  assert.equal(steps.filter((s) => s.type === INVITATION_VIC_TYPE).length, 0);
});
