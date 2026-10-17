// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Layer 3 — Trust Tasks: /auth routes (Scenario 2 — "Authenticate with a
 * VTA").
 *
 * Pure API component (no UI/dashboard surface — see
 * ../../../../docs/vta-dashboard-ui-plan.md, which explicitly scopes this
 * feature out of the dashboard). Documented on the public developer site
 * (site/developers/api-reference.html) under Layer 3 — Trust Tasks,
 * alongside credentials/status-lists/nonces, since VTA challenge-response
 * authentication is built directly on top of the nonces replay-protection
 * primitive (see ./nonces.ts) and is a cross-cutting building block for
 * any application built on the trust stack.
 *
 * - POST /auth/challenge — issue a nonce for a VTA to sign
 * - POST /auth/verify    — verify a signed nonce against the VTA's
 *                          published Ed25519 key
 */


import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import {
  issueChallenge,
  verifyChallenge,
  VtaAuthValidationError,
  VtaAuthNotFoundError,
} from '../../services/vta-auth.js';
import type { IssueChallengeInput, VerifyChallengeInput } from '../../services/vta-auth.js';
import { createSession, validateSession, clearSessionCookie } from '../../session.js';
import { revokeSession, revokeAllBefore } from '../../session-store.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';

export function registerAuthRoutes(app: FastifyInstance, db: DataSource): void {
  app.post(
    '/auth/challenge',
    async (req: FastifyRequest<{ Body: IssueChallengeInput }>, reply: FastifyReply) => {
      try {
        const result = await issueChallenge(db, req.body);
        return reply.code(201).send(result);
      } catch (err) {
        if (err instanceof VtaAuthValidationError) {
          return reply.code(400).send({ error: { message: err.message } });
        }
        if (err instanceof VtaAuthNotFoundError) {
          return reply.code(404).send({ error: { message: err.message } });
        }
        throw err;
      }
    },
  );

  app.post(
    '/auth/verify',
    async (req: FastifyRequest<{ Body: VerifyChallengeInput }>, reply: FastifyReply) => {
      try {
        const result = await verifyChallenge(db, req.body);

        // On successful verification, issue a session cookie with identity UUID
        if (result.valid && req.body.identityUuid) {
          const hmacSecret = (app as any).hmacSecret as Buffer;
          const identity = await identitiesRepo.findByUuid(db, req.body.identityUuid);
          if (identity) {
            const session = createSession(identity.uuid, hmacSecret);
            reply.header('Set-Cookie', session.cookie);
          }
        }

        return reply.code(200).send(result);
      } catch (err) {
        if (err instanceof VtaAuthValidationError) {
          return reply.code(400).send({ error: { message: err.message } });
        }
        if (err instanceof VtaAuthNotFoundError) {
          return reply.code(404).send({ error: { message: err.message } });
        }
        throw err;
      }
    },
  );

  // Login-page support: which VTAs may sign in on this node.
  //
  // The sign-in page is the one surface that cannot have a session yet (obtaining one IS
  // its job), so it cannot read `/identities`: F-011 made that session-protected because
  // it discloses how many identities exist. But without a picker the operator has nothing
  // to select — an identity UUID is never shown to them anywhere. So this is a
  // deliberately NARROW public read (public by virtue of the `/auth/` prefix) that
  // returns the same source of truth the pre-F-011 picker used —
  // `findByRoleAndSubjectKind`, which also excludes TSP-bridge fakes with no active
  // endpoint — and only the three fields a picker needs.
  //
  // Not included, on purpose: custody, peer ids, endpoints, timestamps, counts, key
  // material, and every other role/subject-kind. The general listing stays protected;
  // pinned by test/routes/auth-candidates.test.ts, which asserts 200 here and 401 there
  // against the real auth plugin.
  app.get('/auth/candidates', async (_req: FastifyRequest, reply: FastifyReply) => {
    const candidates = await identitiesRepo.findByRoleAndSubjectKind(db, 'vta', 'human');
    return reply.code(200).send(candidates.map((c) => ({ uuid: c.uuid, name: c.name, did: c.did })));
  });

  // Logout — clear the cookie AND terminate the session (F-019 / ruling R3-b).
  //
  // Before this, logout only cleared the browser's cookie: the token itself stayed
  // valid for the rest of its 8-hour life, so any copy of it (malware, a shared
  // machine, an archived request log) kept full write access. Now the per-session id
  // goes on the revocation list, so the gate refuses it even if it is replayed.
  app.post('/auth/logout', async (req: FastifyRequest, reply: FastifyReply) => {
    const hmacSecret = (app as any).hmacSecret as Buffer;
    const session = validateSession(req.headers.cookie, hmacSecret);

    let revoked = false;
    let note: string | undefined;
    if (session?.sessionId) {
      await revokeSession(db, {
        sessionId: session.sessionId,
        identityUuid: session.identityUuid,
        expiresAt: session.expiresAt,
      });
      revoked = true;
    } else if (session) {
      // A legacy v1 token carries no session id, so it cannot be terminated
      // individually. Say so instead of implying a logout that did not happen — the
      // honest options for it are `logout-all` (a cutoff) or waiting out the expiry.
      note =
        'legacy session token: it has no session id, so it cannot be terminated individually — ' +
        'it expires at its own expiry time, or use POST /auth/logout-all to retire it now';
    }

    reply.header('Set-Cookie', clearSessionCookie());
    return reply.code(200).send({ loggedOut: true, revoked, ...(note ? { note } : {}) });
  });

  // Logout everywhere — retire every session issued up to now, for this identity.
  //
  // This is the half of the audit's requirement that a per-session revocation list
  // alone cannot deliver: a cutoff retires sessions we never recorded AND legacy v1
  // tokens (they report `issuedAt: 0`, so any cutoff kills them).
  app.post('/auth/logout-all', async (req: FastifyRequest, reply: FastifyReply) => {
    const hmacSecret = (app as any).hmacSecret as Buffer;
    const session = validateSession(req.headers.cookie, hmacSecret);
    if (!session) {
      return reply.code(401).send({ error: { message: 'Authentication required.' } });
    }

    const now = Math.floor(Date.now() / 1000);
    const { revokedBefore, changed } = await revokeAllBefore(db, session.identityUuid, now);

    reply.header('Set-Cookie', clearSessionCookie());
    return reply.code(200).send({
      revokedAll: true,
      identityUuid: session.identityUuid,
      revokedBefore,
      changed,
      note:
        'every session for this identity issued at or before this moment is now invalid, ' +
        'including this one; live sessions cannot be enumerated (R3-b does not record issuance)',
    });
  });

  // Session status — returns current identity if authenticated, null otherwise.
  // Used by UI pages to gate write operations behind login.
  app.get('/auth/status', async (req: FastifyRequest, reply: FastifyReply) => {
    const hmacSecret = (app as any).hmacSecret as Buffer;
    const session = validateSession(req.headers.cookie, hmacSecret);
    if (!session) {
      return reply.code(200).send({ authenticated: false });
    }
    const identity = await identitiesRepo.findByUuid(db, session.identityUuid);
    if (!identity || identity.role !== 'vta') {
      return reply.code(200).send({ authenticated: false });
    }
    return reply.code(200).send({
      authenticated: true,
      identityUuid: identity.uuid,
      name: identity.name,
      did: identity.did,
    });
  });
}
