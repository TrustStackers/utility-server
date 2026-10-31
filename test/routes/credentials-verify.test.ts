// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * F-031 — "signature invalid" and "could not be verified" must not read the same.
 *
 * The route already computed a tri-state per signature (`true` | `false` | `null`,
 * where `null` = no locally-known key for the signer) and already counted only
 * `true` toward the threshold. What it threw away was the DISTINCTION: the
 * top-level result was a bare `valid: boolean`, and the reason strings collapsed
 * both failures into "No valid signatures could be verified against locally-known
 * keys". An operator could not tell a forged credential from one whose issuer key
 * simply is not on this node — opposite conclusions, one sentence.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ../test-loader.mjs --test test/routes/credentials-verify.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify, { type FastifyInstance } from 'fastify';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as keysRepo from '@p2p-trust-stack/core/db/repositories/keys-repo.js';
import * as credentialsRepo from '@p2p-trust-stack/core/db/repositories/credentials-repo.js';
import * as signaturesRepo from '@p2p-trust-stack/core/db/repositories/credential-signatures-repo.js';
import { generateEd25519KeyPair } from '@p2p-trust-stack/core/crypto/primitives.js';
import { registerCredentialRoutes } from '../../src/routes/layer3-tasks/credentials.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

interface Harness {
  ds: SqliteDataSource;
  app: FastifyInstance;
}

async function makeHarness(): Promise<Harness> {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);
  const app = Fastify();
  registerCredentialRoutes(app, ds);
  await app.ready();
  return { ds, app };
}

/** An identity with a DID document; `withKey` decides whether a key can be found. */
async function seedIdentity(ds: SqliteDataSource, did: string, withKey: boolean): Promise<string> {
  const uuid = generateUuid();
  await identitiesRepo.create(ds, {
    uuid, realDid: did, role: 'vta', subjectKind: 'human', custody: 'local',
    name: did.slice(-8), recordedByNode: 'test',
  });
  const docUuid = await didDocumentsRepo.create(ds, {
    identityUuid: uuid, did, method: 'did:scid:vh',
    documentJson: JSON.stringify({ id: did }), isPrimary: true, recordedByNode: 'test',
  });
  if (withKey) {
    // The public half is all the verifier reads; the encrypted fields are
    // placeholders because nothing on this path decrypts them.
    const kp = generateEd25519KeyPair();
    await keysRepo.createWithSecret(ds, {
      identityUuid: uuid, didDocumentUuid: docUuid, keyType: 'ed25519',
      publicKey: kp.publicKey,
      encryptedSecretKey: new Uint8Array(32).fill(1), salt: new Uint8Array(16).fill(2),
      nonce: new Uint8Array(12).fill(3), authTag: new Uint8Array(16).fill(4),
    });
  }
  return uuid;
}

/** A credential with one signature from `signerUuid`. */
async function seedCredential(
  ds: SqliteDataSource,
  issuerUuid: string,
  subjectUuid: string,
  signerUuid: string,
  signature: Uint8Array,
): Promise<string> {
  const uuid = await credentialsRepo.create(ds, {
    vcType: 'vmc', issuerIdentityUuid: issuerUuid, subjectIdentityUuid: subjectUuid,
    claim: JSON.stringify({ membershipRole: 'member' }), status: 'issued',
    thresholdRequired: 1, validFrom: Math.floor(Date.now() / 1000) - 60,
  });
  await signaturesRepo.create(ds, {
    credentialUuid: uuid, signerIdentityUuid: signerUuid, signature,
  });
  return uuid;
}

interface VerifyBody {
  valid: boolean;
  indeterminate?: boolean;
  reason: string;
  signatureCounts?: { valid: number; invalid: number; indeterminate: number };
}

test('F-031: a signature that could NOT be checked is INDETERMINATE, not invalid', async () => {
  const { ds, app } = await makeHarness();

  // The signer has a DID document but no ed25519 key on this node, so
  // `verifySignature` cannot reach a verdict at all.
  const issuer = await seedIdentity(ds, 'did:scid:vh:1:zIssuerNoKey', false);
  const subject = await seedIdentity(ds, 'did:scid:vh:1:zSubjectOne', true);
  const credentialUuid = await seedCredential(ds, issuer, subject, issuer, new Uint8Array(64).fill(9));

  const res = await app.inject({ method: 'POST', url: `/credentials/${credentialUuid}/verify` });
  assert.equal(res.statusCode, 200, res.body);
  const body = res.json() as VerifyBody;

  assert.equal(body.valid, false, 'the threshold is still not met');
  assert.equal(body.indeterminate, true, 'but nothing was proven invalid');
  assert.deepEqual(body.signatureCounts, { valid: 0, invalid: 0, indeterminate: 1 });
  assert.match(body.reason, /Could not verify/, 'the reason says it could not be checked');
  assert.match(body.reason, /Indeterminate, not invalid/);
  assert.doesNotMatch(body.reason, /signature\(s\) verified — 1 invalid/, 'it must not accuse the credential');

  await app.close();
  await ds.close();
});

test('F-031: a signature that WAS checked and failed is reported as INVALID', async () => {
  const { ds, app } = await makeHarness();

  // The signer HAS an ed25519 key, so the verifier reaches a verdict — and the
  // signature is garbage, so that verdict is "invalid".
  const issuer = await seedIdentity(ds, 'did:scid:vh:1:zIssuerWithKey', true);
  const subject = await seedIdentity(ds, 'did:scid:vh:1:zSubjectTwo', true);
  const credentialUuid = await seedCredential(ds, issuer, subject, issuer, new Uint8Array(64).fill(7));

  const res = await app.inject({ method: 'POST', url: `/credentials/${credentialUuid}/verify` });
  assert.equal(res.statusCode, 200, res.body);
  const body = res.json() as VerifyBody;

  assert.equal(body.valid, false);
  assert.equal(body.indeterminate, false, 'this one was judged, so it is not indeterminate');
  assert.deepEqual(body.signatureCounts, { valid: 0, invalid: 1, indeterminate: 0 });
  assert.match(body.reason, /invalid/, 'the reason names the failure');
  assert.doesNotMatch(body.reason, /Could not verify/, 'and not the could-not-check wording');

  await app.close();
  await ds.close();
});

