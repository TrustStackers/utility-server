/**
 * Resolver app builder — the PUBLIC did:scid:vh resolution surface.
 *
 * This is a SECOND Fastify instance, separate from the admin app built by
 * `server.ts`, listening on its own port (see `config.resolverPort`). It exists
 * so the resolver can face the public internet (typically via a router port
 * map or a TLS reverse proxy) WITHOUT exposing the administrator web interface,
 * which must stay on localhost.
 *
 * ## What it deliberately does NOT do
 *
 *   - It does not call `registerAuth()` — there is no session gate here. The
 *     resolver serves public DID documents to anonymous callers by design.
 *   - It does not register the admin static UI (`@fastify/static`), the
 *     `p2pts_session` cookie plumbing, or any layer 1–5 admin route.
 *
 * Keeping the route tables disjoint is the isolation mechanism; it is asserted
 * by `test/resolution/isolation.test.ts` rather than left to convention.
 *
 * See `routes/resolution/index.ts` for the route list.
 */

import Fastify, { type FastifyInstance } from 'fastify';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import { registerErrorHandler } from './plugins/error-handler.js';
import { registerResolutionRoutes } from './routes/resolution/index.js';

export interface ResolverAppDeps {
  /** Shared YugabyteDB DataSource — read-only in practice. */
  db: DataSource;
  /** Fastify logger setting. Defaults to `true` (production); tests pass `false`. */
  logger?: boolean;
}

/**
 * Build the resolver Fastify instance. Importable from tests (build an app
 * around a DataSource and `inject()` against it without listening).
 */
export function buildResolverApp(deps: ResolverAppDeps): FastifyInstance {
  const app = Fastify({ logger: deps.logger ?? true });

  // Same JSON error envelope as the admin app, so a 404/500 looks familiar.
  registerErrorHandler(app);

  registerResolutionRoutes(app, { db: deps.db });

  return app;
}
