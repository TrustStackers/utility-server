// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Regression tests for R-Card ↔ name_registry propagation.
 *
 * Reproduced glitch (G7WIN11 / agent99 investigation):
 *   - A name was registered successfully, and a profile was created, but the
 *     name resolved with NO R-Card on peer agents even though the utility
 *     server could resolve the profile. The name↔profile link in
 *     name_registry was only ever set by a fire-and-forget profile sync; when
 *     that push was dropped (disconnected / tx aborted) or landed before the
 *     registration row existed, profile_uuid stayed NULL forever.
 *   - Additionally the per-profile linkage let the LAST profile in the
 *     payload win, so two profiles flip-flopped the resolved card.
 *
 * Covered here (server side of the fix):
 *   1. identity_push now links name_registry to the CANONICAL (default first)
 *      profile deterministically — not "last profile in the payload wins".
 *   2. name_register commit now resolves the profile by label and writes
 *      profile_id + profile_uuid atomically in the INSERT transaction.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs --test test/tx/name-rcard-linkage.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { TX_SCHEMA_SQL } from '@p2p-trust-stack/core/tx/schema.js';
import { createRemoteVta } from '@p2p-trust-stack/core/services/vta.js';
import * as profilesService from '../../src/services/profiles.js';
import { IdentityPushParticipant } from '../../src/tx/identity-push-participant.js';
import { NameRegistryParticipant } from '../../src/tx/name-registry-participant.js';
import { ExchangeQueryParticipant } from '@p2p-trust-stack/core/exchange/index.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

function makeAppDb() {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  return ds;
}

function makeTxDb() {
  const ds = new SqliteDataSource(':memory:');
  ds.getRawDb().exec(TX_SCHEMA_SQL);
  return ds;
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

interface ClaimPush { claimKey: string; claimValue: string | null; valueType: string; disclosure: string; }
interface ProfilePush { label: string; purpose?: string | null; visibility: string; claims: ClaimPush[]; }

function pushPayload(realDid: string, profiles: ProfilePush[]): Record<string, unknown> {
  return {
    realDid,
    identityUuid: `00000000-0000-4000-8000-${realDid.slice(-12).padStart(12, '0')}`,
    name: `Name-${realDid.slice(-4)}`,
    subjectKind: 'human',
    didDocument: { id: realDid },
    publicKeys: { ed25519: b64(new Uint8Array(32).fill(1)), x25519: b64(new Uint8Array(32).fill(2)) },
    profiles,
  };
}
test('identity_push: name_registry links to the canonical DEFAULT profile, not the last in the payload', async () => {
  const ds = makeAppDb();
  const tx = makeTxDb();
  const push = new IdentityPushParticipant('server:test', ds, tx);
  const realDid = 'did:scid:vh:1:zRCardLink1';
  const identityUuid = pushPayload(realDid, []).identityUuid as string;

  try {
    // First push creates the identity + a first (default) profile.
    const ready = await push.prepare('tx-a', [{
      op: 'identity_push',
      params: pushPayload(realDid, [{
        label: 'alpha',
        purpose: 'primary persona',
        visibility: 'public',
        claims: [],
      }]),
    }]);
    assert.strictEqual(ready, 'yes');

    // Simulate the agent's name registration landing between the pushes:
    // an active name_registry row for this identity with NO profile linkage.
    await ds.run(
      `INSERT INTO name_registry
       (namespace, name, did, identity_uuid, profile_uuid,
        proof_type, proof_reference, claimed_at, uuid)
       VALUES ('vta', 'shanster', ?, ?, NULL, 'alsoKnownAs', NULL, unixepoch(), 'nreg-shanster')`,
      realDid,
      identityUuid,
    );

    // Second push with TWO profiles: "alpha" already exists (default),
    // "breed" is new. Before the fix the LAST profile ("breed") would win the
    // linkage; now the canonical/default profile ("alpha") must win.
    const second = await push.prepare('tx-b', [{
      op: 'identity_push',
      params: pushPayload(realDid, [
        { label: 'alpha', purpose: 'primary', visibility: 'public', claims: [] },
        { label: 'breed', purpose: 'alias', visibility: 'public', claims: [] },
      ]),
    }]);
    assert.strictEqual(second, 'yes');

    const linked = await ds.get<{ profile_uuid: string }>(
      'SELECT profile_uuid FROM name_registry WHERE name = ?',
      'shanster',
    );
    const alpha = await ds.get<{ uuid: string }>(
      'SELECT uuid FROM profiles WHERE identity_uuid = ? AND label = ?',
      identityUuid, 'alpha',
    );
    assert.ok(linked, 'name_registry row must exist');
    assert.ok(alpha, 'default profile alpha must exist');
    assert.strictEqual(linked.profile_uuid, alpha.uuid);

    const beta = await ds.get<{ is_default: number }>(
      'SELECT is_default FROM profiles WHERE identity_uuid = ? AND label = ?',
      identityUuid, 'breed',
    );
    assert.ok(beta);
    assert.strictEqual(beta.is_default, 0, 'newer profile must not be the default');
  } finally {
    await ds.close();
    await tx.close();
  }
});
test('name_register commit: links profile by label at registration-commit time (no later push needed)', async () => {
  const ds = makeAppDb();
  const txDb = makeTxDb();
  const realDid = 'did:scid:vh:1:zBodhiReg';
  const identityUuid = `00000000-0000-4000-8000-${realDid.slice(-12).padStart(12, '0')}`;

  try {
    // Agent's identity_push child trans (same 2PC) wrote the identity + the
    // "breed" profile before the name_register commit runs.
    const created = await createRemoteVta(ds, {
      realDid,
      uuid: identityUuid,
      name: 'bodhi-agent',
      subjectKind: 'human' as const,
      didDocument: { id: realDid },
      publicKeys: { ed25519: b64(new Uint8Array(32).fill(3)), x25519: b64(new Uint8Array(32).fill(4)) },
      recordedByNode: 'agent-push',
    });
    const profile = await profilesService.createProfile(ds, {
      identityUuid: created.identity.uuid,
      label: 'breed',
      purpose: 'alias persona',
      visibility: 'public' as const,
    });

    const registry = new NameRegistryParticipant('server:test', ds, txDb);
    const vote = await registry.prepare('tx-nr', [{
      op: 'name_register',
      params: {
        namespace: 'vta',
        name: 'bodhi',
        did: realDid,
        primaryProfileLabel: 'breed',
      },
    }]);
    assert.strictEqual(vote, 'yes');

    await registry.commit('tx-nr');

    const row = await ds.get<{ profile_uuid: string | null }>(
      'SELECT profile_uuid FROM name_registry WHERE namespace = ? AND name = ?',
      'vta', 'bodhi',
    );
    assert.ok(row, 'name_registry row must exist after commit');
    assert.strictEqual(row.profile_uuid, profile.uuid);
  } finally {
    await ds.close();
    await txDb.close();
  }
});
test('name_lookup: discretionary claims returned only when requestedKeys include them', async () => {
  const ds = makeAppDb();
  const txDb = makeTxDb();
  const realDid = 'did:scid:vh:1:zDiscResolve';
  const identityUuid = `00000000-0000-4000-8000-${realDid.slice(-12).padStart(12, '0')}`;

  try {
    // Identity + a profile with a public claim and a discretionary 'weapon' claim.
    const created = await createRemoteVta(ds, {
      realDid,
      uuid: identityUuid,
      name: 'shanster-agent',
      subjectKind: 'human' as const,
      didDocument: { id: realDid },
      publicKeys: { ed25519: b64(new Uint8Array(32).fill(5)), x25519: b64(new Uint8Array(32).fill(6)) },
      recordedByNode: 'agent-push',
    });

    // Seed the profile + claims directly through the service (mimics identity_push).
    const profile = await profilesService.createProfile(ds, {
      identityUuid: created.identity.uuid,
      label: 'default',
      purpose: 'main',
      visibility: 'public' as const,
    });
    await profilesService.addClaim(ds, { profileUuid: profile.uuid, claimKey: 'rank', claimValue: 'officer', valueType: 'string', disclosure: 'always' as const });
    await profilesService.addClaim(ds, { profileUuid: profile.uuid, claimKey: 'weapon', claimValue: 'sniper', valueType: 'string', disclosure: 'discretionary' as const });

    // Register the name (so name_resolve can find it) and link the profile.
    await ds.run(
      `INSERT INTO name_registry
       (namespace, name, did, identity_uuid, profile_uuid,
        proof_type, proof_reference, claimed_at, uuid)
       VALUES ('vta', 'shanster', ?, ?, ?, 'alsoKnownAs', NULL, unixepoch(), 'nreg-disc')`,
      realDid, identityUuid, profile.uuid,
    );

    // Phase C: the R-Card reader is the `registry` recordset served by
    // ExchangeQueryParticipant (exchange:registry), the catalog formalization
    // of the removed legacy name_resolve op.
    const lookup = new ExchangeQueryParticipant('server:test', ds, txDb);

    // Without requestedKeys → discretionary hidden.
    const noKeysRes = await lookup.query('exchange:registry', {
      requester: { realDid, uuid: identityUuid, role: 'vta' },
      filters: { namespace: 'vta', name: 'shanster' },
    }) as { ok: boolean; data?: Array<{ rCard?: { claims: Array<{ key: string }> } }> };
    assert.equal(noKeysRes.ok, true);
    const noKeysKeys = noKeysRes.data?.[0]?.rCard?.claims?.map(c => c.key) ?? [];
    assert.ok(noKeysKeys.includes('rank'), 'public claim present without requestedKeys');
    assert.ok(!noKeysKeys.includes('weapon'), 'discretionary claim hidden without requestedKeys');

    // With requestedKeys=['weapon'] → discretionary present.
    const withKeysRes = await lookup.query('exchange:registry', {
      requester: { realDid, uuid: identityUuid, role: 'vta' },
      filters: { namespace: 'vta', name: 'shanster', requestedKeys: ['weapon'] },
    }) as { ok: boolean; data?: Array<{ rCard?: { claims: Array<{ key: string; value: string | null }> } }> };
    assert.equal(withKeysRes.ok, true);
    const withKeysKeys = withKeysRes.data?.[0]?.rCard?.claims?.map(c => c.key) ?? [];
    assert.ok(withKeysKeys.includes('rank'));
    assert.ok(withKeysKeys.includes('weapon'), 'discretionary claim present when requested');
    const weapon = withKeysRes.data?.[0]?.rCard?.claims?.find(c => c.key === 'weapon');
    assert.strictEqual(weapon?.value, 'sniper');
  } finally {
    await ds.close();
    await txDb.close();
  }
});
