// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Session-cookie tests — HMAC validation and the F-020 constant-time compare.
 *
 * The audit's F-020 listed two sites. On inspection only ONE is a comparison:
 * `validateSession` compared the supplied MAC to the expected one with `!==`,
 * which exits at the first differing byte and leaks the expected MAC one byte at
 * a time to an unauthenticated caller. (The other cited site,
 * `vta-auth.ts:39-50`, is `verifyEd25519` — public-key verification of a nonce
 * signature, with no secret-dependent branch to make constant-time.)
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ../test-loader.mjs --test test/services/session.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  createSession,
  validateSession,
  generateSessionSecret,
} from '../../src/session.js';

/** Pull the cookie's `name=value` pair out of a Set-Cookie header. */
function cookiePair(setCookie: string): string {
  return setCookie.split(';')[0];
}

/**
 * Build a **legacy v1** token by hand: `uuid:expiresAt:sig`. The format is frozen on
 * purpose — a v1 token is whatever an existing deployment's browser already holds, so
 * the test must reproduce it independently of `session.ts` rather than round-trip
 * through the code under test.
 */
function legacyV1Token(identityUuid: string, expiresAt: number, secret: Buffer): string {
  const payload = `${identityUuid}:${expiresAt}`;
  const sig = createHmac('sha256', secret).update(payload).digest().toString('base64url');
  return Buffer.from(`${payload}:${sig}`).toString('base64url');
}

test('validateSession: a v2 token carries a session id and is individually revocable', () => {
  const secret = generateSessionSecret();
  const session = createSession('identity-uuid-v2', secret);
  const payload = validateSession(`p2pts_session=${session.token}`, secret);

  assert.ok(payload, 'a v2 token validates');
  assert.equal(payload!.identityUuid, 'identity-uuid-v2');
  assert.equal(payload!.sessionId, session.sessionId, 'the session id survives the round-trip');
  assert.equal(payload!.individuallyRevocable, true);
  assert.ok(payload!.issuedAt > 0, 'a v2 token records when it was issued');
  assert.equal(payload!.expiresAt, session.expiresAt);
});

test('validateSession: a legacy v1 token still validates, and is honestly marked unrevocable', () => {
  const secret = generateSessionSecret();
  const expiresAt = Math.floor(Date.now() / 1000) + 3600;
  const token = legacyV1Token('identity-uuid-v1', expiresAt, secret);

  const payload = validateSession(`p2pts_session=${token}`, secret);
  assert.ok(payload, 'existing cookies must keep working across the upgrade');
  assert.equal(payload!.identityUuid, 'identity-uuid-v1');
  assert.equal(payload!.sessionId, undefined, 'a v1 token has no session id');
  assert.equal(payload!.individuallyRevocable, false);
  // 0 is deliberate: the oldest possible value, so a revoke-all cutoff retires it too.
  assert.equal(payload!.issuedAt, 0);
});

test('validateSession: a 4-field token does NOT validate (v2 prefix, v1 MAC)', () => {
  const secret = generateSessionSecret();
  const expiresAt = Math.floor(Date.now() / 1000) + 3600;
  // A v1 token with an extra field spliced in: the MAC no longer covers the real
  // payload, so it must be rejected — the field count must never be inferred loosely.
  const v1 = legacyV1Token('identity-uuid-splice', expiresAt, secret);
  const decoded = Buffer.from(v1, 'base64url').toString('utf-8');
  const [uuid, exp, sig] = decoded.split(':');
  const spliced = Buffer.from(`${uuid}:extra:${exp}:${sig}`).toString('base64url');

  assert.equal(validateSession(`p2pts_session=${spliced}`, secret), null);
});


test('validateSession: accepts a session it issued', () => {
  const secret = generateSessionSecret();
  const { cookie } = createSession('identity-uuid-1', secret);

  const payload = validateSession(cookiePair(cookie), secret);
  assert.ok(payload, 'a freshly issued session must validate');
  assert.equal(payload!.identityUuid, 'identity-uuid-1');
  assert.ok(payload!.expiresAt > Date.now() / 1000, 'and must not be expired');
});

test('validateSession: rejects a tampered signature (the F-020 path)', () => {
  const secret = generateSessionSecret();
  const { cookie } = createSession('identity-uuid-1', secret);
  const pair = cookiePair(cookie);

  // Flip the LAST character of the MAC. With `sig !== expectedSig` the comparison
  // stops there and returns false after inspecting almost the whole MAC; with a
  // constant-time compare the time taken says nothing. Both must reject — this
  // pins that the change did not weaken the check.
  const [name, value] = pair.split('=');
  const decoded = Buffer.from(value, 'base64url').toString('utf-8');
  const lastChar = decoded.slice(-1);
  const flipped = lastChar === 'A' ? 'B' : 'A';
  const tampered = Buffer.from(decoded.slice(0, -1) + flipped).toString('base64url');

  assert.equal(validateSession(`${name}=${tampered}`, secret), null, 'a one-byte MAC change must be rejected');

  // …and the same for a MAC that is a different LENGTH (must not throw).
  const shortMac = Buffer.from(decoded.slice(0, -4)).toString('base64url');
  assert.equal(validateSession(`${name}=${shortMac}`, secret), null, 'a truncated MAC must be rejected, not throw');

  // The untampered cookie still validates — the check is not simply always-false.
  assert.ok(validateSession(pair, secret), 'the genuine cookie must still validate');
});

test('validateSession: rejects a payload tampered to a longer expiry, and a wrong secret', () => {
  const secret = generateSessionSecret();
  const other = generateSessionSecret();
  const { cookie } = createSession('identity-uuid-1', secret);
  const pair = cookiePair(cookie);
  const [name, value] = pair.split('=');
  const decoded = Buffer.from(value, 'base64url').toString('utf-8');
  const [uuid, exp, sig] = decoded.split(':');

  const forgedExpiry = Buffer.from(`${uuid}:${Number(exp) + 3600}:${sig}`).toString('base64url');
  assert.equal(validateSession(`${name}=${forgedExpiry}`, secret), null, 'extending the expiry invalidates the MAC');

  assert.equal(validateSession(pair, other), null, 'a session must not validate under the wrong secret');

  assert.equal(validateSession(undefined, secret), null, 'no cookie → no session');
  assert.equal(validateSession(`${name}=not-base64url!!`, secret), null, 'garbage → no session');
  assert.equal(validateSession(`${name}=${Buffer.from('two:parts').toString('base64url')}`, secret), null, 'wrong part count → no session');
});
