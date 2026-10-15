/**
 * Auth plugin — session-based VTA authentication.
 *
 * Reads the `p2pts_session` cookie, validates its HMAC signature against the server's
 * session secret, **checks that the session has not been revoked** (F-019 / ruling
 * R3-b), resolves the identity, and attaches `req.currentIdentity` for downstream route
 * handlers.
 *
 * ## F-011 / ruling Y4 (2026-09-24): reads are no longer blanket-open
 *
 * The hook used to be `if (req.method === 'GET' || isPublicPath(req.url)) return;` — so
 * **every** read was unauthenticated: how many identities exist, which DIDs are known,
 * which credentials are held, and (via 404-vs-200) whether a given identifier exists at
 * all. The write surface was authenticated while the read surface disclosed everything
 * it was asked about.
 *
 * Now: only **static UI assets and the login/setup paths** are public, and every other
 * request — read or write — needs a live session.
 *
 * The login page must remain reachable (it is how a session is obtained) and `/setup/`
 * must remain reachable during first-run provisioning, when no session can exist yet.
 * `TSP_READ_AUTH_POLICY` exists as a rollout valve: `enforce` (default) requires a
 * session for reads, `warn` reports reads that would have been refused and lets them
 * through, `off` restores the pre-F-011 behaviour for an operator mid-migration.
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { Identity } from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import { validateSession } from '../session.js';
import { sessionLiveness } from '../session-store.js';
import { isConfigured } from '../setup/setup-state.js';

export const READ_AUTH_POLICY_ENV = 'TSP_READ_AUTH_POLICY';

export type ReadAuthPolicy = 'off' | 'warn' | 'enforce';

/** Resolve the read policy: environment → `enforce`. Unknown values fall back to `enforce`. */
export function resolveReadAuthPolicy(raw: string | undefined = process.env[READ_AUTH_POLICY_ENV]): ReadAuthPolicy {
  const v = (raw ?? '').trim().toLowerCase();
  if (v === 'off' || v === 'warn' || v === 'enforce') return v;
  if (v.length > 0) {
    console.warn(`[auth] unrecognised ${READ_AUTH_POLICY_ENV}="${raw}" — falling back to "enforce"`);
  }
  return 'enforce';
}

// Extend Fastify request to carry the current identity
declare module 'fastify' {
  interface FastifyRequest {
    currentIdentity?: Identity;
  }
}

/**
 * Paths reachable **without** a session.
 *
 * The UI's static assets are public because they are the login page and its code; the
 * `/auth/*` routes are how a session is obtained.
 *
 * `/setup/*` is handled **separately** in `isPublicPath` and is NOT listed here: it must
 * work before any session can exist (first-run provisioning), but only while the instance
 * is unconfigured — see below.
 *
 * `/dashboard/summary` was previously here and is **no longer public**: it reports counts
 * about this node's data, which is exactly the class of disclosure F-011 is about.
 */
const PUBLIC_PREFIXES = [
  '/ui/',
  '/lib/',
  '/auth/',
  '/favicon.ico',
];

/**
 * Exact paths reachable without a session (no prefix matching — see below).
 *
 * `/namespace/status` is the node's **published network name** (`vta:<ns>:`), not private
 * data about this node: agents must be able to discover which namespace a server serves in
 * order to register names against it, the dashboard shows the line before sign-in, and the
 * route documents itself as a public read in three places (`config-routes.ts` — *"public
 * read of the configured namespace"* — `server.ts`, and its own doc comment). F-011's
 * blanket "reads need a session" rule caught it by accident. Contrast `/dashboard/summary`,
 * deliberately NOT here: that one reports counts about this node's data, which is the
 * disclosure class F-011 names.
 *
 * Deliberately an exact path and not a prefix, so the exception cannot widen by accident.
 *
 * `/health` is a **liveness probe** — `{status, service, time}` and nothing about this
 * node's data. It belongs here for the same reason `/namespace/status` does but with a
 * sharper edge: F-011 moved the hook from "every GET is public" to an allow-list, and
 * `/health` was not named, so a probe that used to answer started returning 401. A
 * liveness endpoint that requires a session cannot be used by an orchestrator, a load
 * balancer, or `curl`, which is the whole point of it. Its sibling
 * `/health/connectivity` — which *does* report this node's state — stays gated, and is
 * the correct thing to gate.
 */
const PUBLIC_EXACT_PATHS = ['/namespace/status', '/health'];

function isPublicPath(url: string): boolean {
  const path = url.split('?')[0];
  // The root is a pure redirect (→ dashboard, or → the wizard while unconfigured).
  // It discloses nothing, and requiring a session here only strands a browser at a
  // 401 instead of sending it on to the dashboard/login.
  if (path === '/') return true;
  // F-06 / SYN-014: `/setup/*` is public ONLY while the instance is unconfigured.
  // Once `/setup/confirm` persists the configuration, the exemption is withdrawn so a
  // completed instance never serves setup routes without a session — in this process or
  // after a restart. (The handlers are additionally closed by the setup guard.)
  if (path === '/setup' || path.startsWith('/setup/')) return !isConfigured();
  if (PUBLIC_PREFIXES.some((p) => url === p || url.startsWith(p))) return true;
  return PUBLIC_EXACT_PATHS.includes(path);
}

export function registerAuth(app: FastifyInstance, db: DataSource, hmacSecret: Buffer): void {
  // Store the secret on the app instance so auth routes can access it
  app.decorate('hmacSecret', hmacSecret);

  app.addHook('preHandler', async (req: FastifyRequest, reply: FastifyReply) => {
    // Static UI assets, the login path, and first-run setup.
    if (isPublicPath(req.url)) return;

    const isRead = req.method === 'GET' || req.method === 'HEAD';
    const readPolicy = resolveReadAuthPolicy();

    if (isRead && readPolicy === 'off') return; // pre-F-011 behaviour, for a transition

    const session = validateSession(req.headers.cookie, hmacSecret);

    if (isRead && readPolicy === 'warn') {
      if (!session) {
        console.warn(
          `[auth] F-011 would refuse unauthenticated read ${req.method} ${req.url} ` +
          `(${READ_AUTH_POLICY_ENV}=warn, so it is being allowed)`,
        );
      }
      return;
    }

    if (!session) {
      return reply.code(401).send({ error: { message: 'Authentication required. Visit /ui/login.html to sign in.' } });
    }

    // F-019 / R3-b: a cryptographically valid token can still be a TERMINATED one.
    // Before this check, `logout` only deleted the browser's cookie, so a copied token
    // kept full write access for the rest of its 8-hour life.
    const liveness = await sessionLiveness(db, session);
    if (!liveness.alive) {
      return reply.code(401).send({
        error: { message: `Session no longer valid (${liveness.reason}). Sign in again.` },
        reason: liveness.reason,
      });
    }

    const identity = await identitiesRepo.findByUuid(db, session.identityUuid);
    if (!identity || identity.role !== 'vta') {
      return reply.code(401).send({ error: { message: 'Session identity not found or not a VTA.' } });
    }

    req.currentIdentity = identity;
  });
}
