/**
 * Session revocation store — the *minimal state* that makes F-019's ruling (R3-b:
 * revocable-but-stateless) real.
 *
 * Two tables, both in `0017_sessions.sql`:
 *
 *   revoked_sessions    — one row per terminated session, keyed by the per-session id
 *                         carried in a v2 token. Prunable: once the token's own
 *                         `expires_at` has passed the row proves nothing.
 *   session_revocations — one cutoff row per identity: "every session issued at or
 *                         before T is dead". This is what makes `logout-all` possible
 *                         WITHOUT recording issued sessions, and it retires legacy v1
 *                         tokens too (they have no issuance time, so `validateSession`
 *                         reports `issuedAt: 0`).
 *
 * ## What this deliberately does NOT do
 *
 * It cannot **enumerate** live sessions — that needs issuance records, i.e. option A,
 * which was considered and not chosen. Termination is now real; enumeration is not.
 * Better to say so than to imply the audit's "terminate AND enumerate" is fully met.
 *
 * The list is also **fail-open**: lose these rows (restore, truncate) and a revoked
 * session becomes valid again until its token expires. The alternative — a live row per
 * session validated by lookup — is fail-closed against that, but resurrects nothing on
 * a rollback either; neither is free, and R3-b chose the cheaper one knowingly.
 *
 * ## Dialect
 *
 * Every statement is portable across SQLite and Yugabyte/Postgres: no
 * `INSERT OR IGNORE`, no `INSERT … ON CONFLICT` (a duplicate insert's primary-key
 * violation is caught instead), no DB-side time functions — timestamps come from the
 * caller. That is H11's dialect audit applied, and
 * `test/services/session-revocation.test.ts` exercises it on SQLite.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';

/** True when this individual session id has been terminated. */
export async function isRevoked(db: DataSource, sessionId: string): Promise<boolean> {
  const row = await db.get<{ session_id: string }>(
    'SELECT session_id FROM revoked_sessions WHERE session_id = ?',
    sessionId,
  );
  return row !== null;
}

/**
 * True when a per-identity cutoff retires a session issued at `issuedAt`.
 *
 * `issuedAt <= revoked_before` is the kill condition, so a legacy v1 token
 * (`issuedAt: 0`) is retired by any cutoff — the fail-safe direction.
 */
export async function isCoveredByRevokeAll(
  db: DataSource,
  identityUuid: string,
  issuedAt: number,
): Promise<boolean> {
  const row = await db.get<{ revoked_before: number }>(
    'SELECT revoked_before FROM session_revocations WHERE identity_uuid = ?',
    identityUuid,
  );
  if (!row) return false;
  return issuedAt <= Number(row.revoked_before);
}

/**
 * Terminate one session.
 *
 * Idempotent: a second logout of the same session is a no-op (the primary key makes
 * the duplicate insert fail, and that is caught rather than surfaced — the operator
 * pressed logout twice, not something to error on).
 */
export async function revokeSession(
  db: DataSource,
  input: { sessionId: string; identityUuid: string; expiresAt: number; now?: number },
): Promise<void> {
  const now = input.now ?? Math.floor(Date.now() / 1000);

  const existing = await db.get<{ session_id: string }>(
    'SELECT session_id FROM revoked_sessions WHERE session_id = ?',
    input.sessionId,
  );
  if (!existing) {
    try {
      await db.run(
        'INSERT INTO revoked_sessions (session_id, identity_uuid, revoked_at, expires_at) VALUES (?, ?, ?, ?)',
        input.sessionId,
        input.identityUuid,
        now,
        input.expiresAt,
      );
    } catch (err) {
      // A concurrent logout of the same session won the race — same outcome.
      console.warn(`[session-store] revokeSession race for ${input.sessionId.slice(0, 8)}…: ${(err as Error)?.message}`);
    }
  }

  // Opportunistic prune: a row whose token can no longer validate proves nothing.
  await pruneExpired(db, now);
}

/**
 * Revoke EVERY session for an identity issued at or before `cutoff`.
 *
 * Returns the effective cutoff — a later existing cutoff is kept, so calling this
 * twice cannot *un-revoke* a window.
 */
export async function revokeAllBefore(
  db: DataSource,
  identityUuid: string,
  cutoff: number,
  now?: number,
): Promise<{ revokedBefore: number; changed: boolean }> {
  const at = now ?? Math.floor(Date.now() / 1000);
  const existing = await db.get<{ revoked_before: number }>(
    'SELECT revoked_before FROM session_revocations WHERE identity_uuid = ?',
    identityUuid,
  );
  const effective = existing ? Math.max(Number(existing.revoked_before), cutoff) : cutoff;

  // DELETE + INSERT rather than an upsert: portable across both engines, and this is a
  // rare, operator-initiated operation.
  await db.run('DELETE FROM session_revocations WHERE identity_uuid = ?', identityUuid);
  await db.run(
    'INSERT INTO session_revocations (identity_uuid, revoked_before, revoked_at) VALUES (?, ?, ?)',
    identityUuid,
    effective,
    at,
  );

  return { revokedBefore: effective, changed: !existing || effective !== Number(existing.revoked_before) };
}

/**
 * Drop revocation rows whose token has expired anyway. Bounded work: the table only
 * ever holds sessions terminated inside the last TTL window (8 h by default).
 */
export async function pruneExpired(db: DataSource, now?: number): Promise<number> {
  const at = now ?? Math.floor(Date.now() / 1000);
  const before = await db.get<{ n: number }>(
    'SELECT COUNT(*) AS n FROM revoked_sessions WHERE expires_at < ?',
    at,
  );
  await db.run('DELETE FROM revoked_sessions WHERE expires_at < ?', at);
  return Number(before?.n ?? 0);
}

/**
 * The full check the auth plugin needs: is this session still alive?
 * The reason string lets a 401 say *why* without the gate guessing.
 */
export async function sessionLiveness(
  db: DataSource,
  session: { identityUuid: string; issuedAt: number; sessionId?: string },
): Promise<{ alive: boolean; reason?: string }> {
  if (session.sessionId && await isRevoked(db, session.sessionId)) {
    return { alive: false, reason: 'session_terminated' };
  }
  if (await isCoveredByRevokeAll(db, session.identityUuid, session.issuedAt)) {
    return { alive: false, reason: 'revoked_by_logout_all' };
  }
  return { alive: true };
}
