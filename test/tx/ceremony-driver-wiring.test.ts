/**
 * P6.4 wiring test — verifies the real executors are registered by the
 * ceremony-participant module and that their CONTEXT contract matches what
 * crystallize() hands driveCeremony.
 *
 * We do NOT run the full createVtc (it mints credentials + signs governance docs);
 * instead we drive the registered `vtc:establish` executor with a deliberately
 * missing admin and assert it fails with createVtc's OWN not-found error — not a
 * `TypeError` on `undefined.length`. That proves the executor read `name` / `kind` /
 * `adminIdentityUuids` from the context correctly and reached createVtc's validation,
 * so a key mismatch between crystallize and the executor cannot silently pass.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { resolveExecutor } from '@p2p-trust-stack/core/services/trust-tasks/catalog.js';
import { VTC_ESTABLISH_TYPE, MEMBERSHIP_VMC_TYPE, ONBOARDING_VMC_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/type-uris.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

function open() {
  const db = new SqliteDataSource(':memory:');
  runMigrations(db.getRawDb(), MIGRATIONS_DIR);
  return db;
}

test('importing ceremony-participant registers the real effect executors', async () => {
  await import('../../src/tx/ceremony-participant.js');
  assert.equal(typeof resolveExecutor(VTC_ESTABLISH_TYPE), 'function');
  assert.equal(typeof resolveExecutor(MEMBERSHIP_VMC_TYPE), 'function');
  assert.equal(typeof resolveExecutor(ONBOARDING_VMC_TYPE), 'function');
});

test('the vtc:establish executor reads the createVtc context correctly', async () => {
  const db = open();
  await import('../../src/tx/ceremony-participant.js');
  const executor = resolveExecutor(VTC_ESTABLISH_TYPE)!;

  // A missing admin means createVtc got the adminIdentityUuids array and reached
  // its own validation — a key mismatch would instead throw on `undefined.length`.
  await assert.rejects(
    () => executor({
      db,
      name: 'Unused Unique Name',
      kind: 'vtc',
      adminIdentityUuids: ['00000000-0000-0000-0000-00000000dead'],
      threshold: 2,
    }),
    (err: Error) => /not found/.test(err.message) && !/undefined/.test(err.message),
    'expected createVtc to reach admin resolution (context keys wired correctly)',
  );
});

test('the membership-vmc executor documents the already-minted credential + recipient', async () => {
  await import('../../src/tx/ceremony-participant.js');
  const db = open();
  const executor = resolveExecutor(MEMBERSHIP_VMC_TYPE)!;

  // Seed the member identity + primary DID document so recipient resolution works.
  await identitiesRepo.create(db, {
    uuid: 'member-uuid', realDid: 'did:example:member', role: 'vta', subjectKind: 'human',
    name: 'Member', recordedByNode: 'test',
  });
  await didDocumentsRepo.create(db, {
    identityUuid: 'member-uuid', did: 'did:example:member', method: 'did:scid:vh',
    isPrimary: true, recordedByNode: 'test',
  });

  const out = await executor({
    db,
    item: {
      uuid: 'membership-uuid',
      memberIdentityUuid: 'member-uuid',
      membershipCredentialUuid: 'cred-uuid',
      role: 'founding_admin',
    },
  }) as Record<string, unknown>;
  assert.deepEqual(out, {
    membershipUuid: 'membership-uuid',
    memberIdentityUuid: 'member-uuid',
    membershipCredentialUuid: 'cred-uuid',
    role: 'founding_admin',
    recipientDid: 'did:example:member',
  });
});
