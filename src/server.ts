// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Fastify app builder.
 *
 * Registers all plugins and route groups. Called from index.ts, and
 * separately importable from tests (build a fresh app instance around a
 * DataSource without needing to actually listen()).
 */

import Fastify, { type FastifyInstance } from 'fastify';
import fastifyStatic from '@fastify/static';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import type { Libp2p } from 'libp2p';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { TransactionManager } from '@p2p-trust-stack/core/tx/manager.js';
import type { TransactionCoordinator } from '@p2p-trust-stack/core/tx/coordinator.js';
import type { ServerTspRequestAdapter } from './tx/tsp-request.js';

import { generateSessionSecret } from './session.js';
import { registerErrorHandler } from './plugins/error-handler.js';
import { registerAuth } from './plugins/auth.js';
import { registerHealthRoute } from './routes/health.js';
import { registerHelpRoute } from './routes/help.js';

import { registerIdentityRoutes } from './routes/layer1-infrastructure/identities.js';
import { registerDidDocumentRoutes } from './routes/layer1-infrastructure/did-documents.js';
import { registerRotationRoutes } from './routes/layer1-infrastructure/rotation.js';

import { registerLayer2Routes } from './routes/layer2-spanning/index.js';
import { registerLayer3Routes } from './routes/layer3-tasks/index.js';
import { registerLayer4Routes } from './routes/layer4-governance/index.js';
import { registerLayer5Routes } from './routes/layer5-applications/index.js';
import { registerConfigRoutes } from './routes/config-routes.js';
import { registerSetupRoutes } from './setup/setup-routes.js';
import { requireSetup } from './setup/setup-guard.js';

export interface AppDeps {
  /** YugabyteDB DataSource for all trust task data. */
  db: DataSource;
  /** Transaction-coordinator DataSource (ceremony/governance-change state); optional. */
  txDb?: DataSource;
  /** Live libp2p node. */
  node: Libp2p;
  /** Path to the shared SqliteKeyStore db file (Layer 2 routes read key material to sign RFI/RFA). */
  keyStorePath: string;
  /** Hex-encoded HMAC secret for session tokens (persisted across restarts). */
  hmacSecretHex?: string;
  /** Transaction coordinator manager (optional — for VTC push). */
  txManager?: TransactionManager;
  /** Transaction coordinator (optional — for participant registration). */
  txCoordinator?: TransactionCoordinator;
  /** TSP request adapter for server→agent communication (optional — for VTC push). */
  tspAdapter?: ServerTspRequestAdapter;
  /** Ceremony coordinator (optional — for Phase 3 governance ceremonies). */
  ceremonyCoordinator?: import('@p2p-trust-stack/core/tx/index.js').CeremonyCoordinator;
  /** When true, the instance is unconfigured — registers setup wizard + guard. */
  setupMode?: boolean;
  /**
   * Live connectivity snapshot for the operator surface (`GET /health/connectivity`).
   *
   * Injected as a function rather than the supervisor itself so `buildServer` needs
   * no dependency on the service layer, and so a process without a supervisor is an
   * explicit "not available" (503) instead of a silently empty payload.
   */
  getConnectivityStatus?: () => import('./services/connectivity-supervisor.js').SupervisorStatus;
}

export function buildServer(deps: AppDeps): FastifyInstance {
  const app = Fastify({ logger: true });

  // Load persisted HMAC secret for session tokens, or generate a new one.
  const hmacSecret = deps.hmacSecretHex
    ? Buffer.from(deps.hmacSecretHex, 'hex')
    : generateSessionSecret();

  // Make the DataSource available to every route handler via app.db.
  app.decorate('db', deps.db);
  // The tx-coordinator DB (proposals/ceremonies) — needed by the VTN governance surface.
  if (deps.txDb) app.decorate('txDb', deps.txDb);

  // Make transaction coordinator available to route handlers.
  if (deps.txManager) app.decorate('txManager', deps.txManager);
  if (deps.txCoordinator) app.decorate('txCoordinator', deps.txCoordinator);
  if (deps.tspAdapter) app.decorate('tspAdapter', deps.tspAdapter);
  if (deps.ceremonyCoordinator) app.decorate('ceremonyCoordinator', deps.ceremonyCoordinator);

  registerErrorHandler(app);
  registerAuth(app, deps.db, hmacSecret);

  registerHelpRoute(app);
  registerHealthRoute(app, { getConnectivityStatus: deps.getConnectivityStatus });

  // Layer 1 — Infrastructure
  registerIdentityRoutes(app, deps.db);
  registerDidDocumentRoutes(app, deps.db);
  registerRotationRoutes(app, deps.db);

  // Layer 2 — Trust Spanning
  registerLayer2Routes(app, deps.db, deps.node, deps.keyStorePath);

  // Layer 3 — Trust Tasks
  registerLayer3Routes(app, deps.db);

  // Layer 4 — Governance
  registerLayer4Routes(app, deps.db);

  // Layer 5 — Trust Applications
  registerLayer5Routes(app, deps.db, deps.node);

  // Founder-admin configuration surface (+ public /namespace/status).
  registerConfigRoutes(app, deps.db);

  // Static UI
  const uiDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'ui');
  app.register(fastifyStatic, {
    root: uiDir,
    prefix: '/ui/',
  });

  // Serve cytoscape.js from node_modules (npm dependency, not CDN). Resolve it instead of assuming
  // `<this repo>/node_modules/…`, so the path still works when dependencies are hoisted (npm
  // workspaces) or installed by a different package manager.
  const cyDistPath = createRequire(import.meta.url).resolve('cytoscape/dist/cytoscape.min.js');
  const cyContent = readFileSync(cyDistPath, 'utf-8');
  app.get('/lib/cytoscape.min.js', async (_req, reply) => {
    return reply.type('application/javascript').send(cyContent);
  });

  app.get('/', async (_req, reply) => {
    return reply.redirect(deps.setupMode ? '/ui/setup.html' : '/ui/index.html');
  });

  // A configured instance has no wizard: `setup.html` is a STATIC asset, so unlike
  // the `/setup/*` API routes it survives a configured restart and would otherwise
  // still be served. It is a dead form by then (its API is unregistered), so send
  // the operator to the dashboard instead. `@fastify/static` serves `/ui/*`, but a
  // literal route takes precedence over its wildcard. In setup mode it stays live.
  if (!deps.setupMode) {
    app.get('/ui/setup.html', async (_req, reply) => reply.redirect('/ui/index.html'));
  }

  // ── Setup wizard (unconfigured instance) ──────────────────────────────
  if (deps.setupMode) {
    registerSetupRoutes(app, {
      getDb: () => deps.db,
    });
    app.addHook('onRequest', requireSetup);
  }

  return app;
}

declare module 'fastify' {
  interface FastifyInstance {
    db: DataSource;
    hmacSecret: Buffer;
    txDb?: DataSource;
    txManager?: TransactionManager;
    txCoordinator?: TransactionCoordinator;
  }
}
