// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Session token utilities for VTA-authenticated web sessions.
 *
 * HMAC-SHA256 signed tokens in an httpOnly cookie.
 *
 * **v2 (current)** — `identityUuid : sessionId : issuedAt : expiresAt : sig`.
 * **v1 (legacy, still accepted)** — `identityUuid : expiresAt : sig`.
 *
 * v2 is audit F-019 / ruling R3-b (2026-09-24): *revocable-but-stateless* sessions.
 * A v1 token could not be terminated — `logout` only deleted the cookie, so a copied
 * token stayed valid for the rest of its 8-hour life. A per-session id makes
 * `revokeSession()` possible (see `session-store.ts`), and `issuedAt` supports a
 * per-identity cutoff that also retires **v1** tokens (treated as issued at 0 — the
 * fail-safe direction).
 *
 * Validation stays stateless (format + HMAC + expiry). Revocation lookups belong to
 * the caller (the auth plugin) so this module stays pure.
 *
 * Uses identityUuid (not integer identityId) so sessions are stable across
 * database resets — UUIDs are deterministic UUIDv5 from DIDs.
 */

import { createHmac, randomBytes } from 'node:crypto';
import { timingSafeEqualString } from '@p2p-trust-stack/core/crypto/primitives.js';

const SESSION_COOKIE = 'p2pts_session';
const SESSION_TTL_SECONDS = 8 * 60 * 60; // 8 hours

function base64url(buf: Buffer): string { return buf.toString('base64url'); }
function base64urlDecode(s: string): Buffer { return Buffer.from(s, 'base64url'); }

function sign(payload: string, secret: Buffer): string {
  return base64url(createHmac('sha256', secret).update(payload).digest());
}

export interface SessionPayload {
  identityUuid: string;
  expiresAt: number;
  /**
   * When the session was minted (unix seconds). `0` for a legacy v1 token, which
   * carries no issuance time — deliberately the *oldest* possible value, so a
   * revoke-all cutoff retires v1 tokens too (the fail-safe direction).
   */
  issuedAt: number;
  /** The per-session id; present on v2 tokens only. */
  sessionId?: string;
  /** False for legacy v1 tokens: only a revoke-all cutoff can retire those. */
  individuallyRevocable: boolean;
}

/** A fresh 128-bit session id. */
export function newSessionId(): string {
  return base64url(randomBytes(16));
}

/**
 * Mint a v2 session. Pass an explicit `sessionId` only when the caller needs to know
 * the id before the call (the routes don't).
 */
export function createSession(
  identityUuid: string,
  secret: Buffer,
  opts: { sessionId?: string; issuedAt?: number; ttlSeconds?: number } = {},
): { token: string; cookie: string; maxAge: number; sessionId: string; expiresAt: number; issuedAt: number } {
  const issuedAt = opts.issuedAt ?? Math.floor(Date.now() / 1000);
  const ttl = opts.ttlSeconds ?? SESSION_TTL_SECONDS;
  const expiresAt = issuedAt + ttl;
  const sessionId = opts.sessionId ?? newSessionId();

  const payload = `${identityUuid}:${sessionId}:${issuedAt}:${expiresAt}`;
  const token = base64url(Buffer.from(`${payload}:${sign(payload, secret)}`));
  const cookie = `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${ttl}`;
  return { token, cookie, maxAge: ttl, sessionId, expiresAt, issuedAt };
}

/**
 * Validate a session cookie.
 *
 * Accepts v2 (5 fields) and legacy v1 (3 fields) and returns null for everything
 * else — a malformed token, a bad MAC, or an expired one. A 4-field token (a v2
 * prefix with a *v1* MAC) must NOT validate, which is why the MAC is recomputed over
 * the whole pre-signature payload rather than a reassembled subset.
 *
 * **Revocation is NOT checked here** — that needs the database. The caller must
 * consult `session-store.ts` (`isRevoked` / `isCoveredByRevokeAll`).
 */
export function validateSession(cookieHeader: string | undefined, secret: Buffer): SessionPayload | null {
  if (!cookieHeader) return null;
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([^;]+)`));
  if (!match) return null;
  const token = match[1];
  let decoded: string;
  try { decoded = base64urlDecode(token).toString('utf-8'); } catch { return null; }

  const parts = decoded.split(':');
  // v2: uuid:sessionId:issuedAt:expiresAt:sig · v1: uuid:expiresAt:sig
  if (parts.length !== 5 && parts.length !== 3) return null;

  const identityUuid = parts[0];
  const sig = parts[parts.length - 1];
  if (!identityUuid) return null;

  let sessionId: string | undefined;
  let issuedAt: number;
  let expiresAt: number;

  if (parts.length === 5) {
    sessionId = parts[1];
    issuedAt = parseInt(parts[2], 10);
    expiresAt = parseInt(parts[3], 10);
    if (!sessionId || !Number.isFinite(issuedAt)) return null;
  } else {
    // v1: no issuance time. 0 is deliberately the oldest possible value, so a
    // revoke-all cutoff retires legacy tokens as well.
    issuedAt = 0;
    expiresAt = parseInt(parts[1], 10);
  }

  if (!Number.isFinite(expiresAt)) return null;
  if (Date.now() / 1000 > expiresAt) return null;

  const payload = parts.slice(0, parts.length - 1).join(':');
  const expectedSig = sign(payload, secret);
  // F-020: constant-time comparison. The previous `sig !== expectedSig` exits on
  // the first differing byte, which leaks how many leading bytes of the expected
  // MAC were correct — the classic MAC-forgery-by-timing setup on a value an
  // unauthenticated caller supplies in a cookie.
  if (!timingSafeEqualString(sig, expectedSig)) return null;

  return {
    identityUuid,
    expiresAt,
    issuedAt,
    sessionId,
    individuallyRevocable: sessionId !== undefined,
  };
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`;
}

export function generateSessionSecret(): Buffer {
  return randomBytes(32);
}
