// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * setup-routes — API endpoints for the first-launch configuration wizard.
 * Mirrors the crowdfund app's setup-routes, but the VTN it creates is a REAL
 * namespace VTN and the founder is the operator's own VTA.
 */

import type { FastifyInstance } from 'fastify';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import { loadBootstrapClientEnv } from '@p2p-trust-stack/core/config/bootstrap-env.js';
import { createSetupState, type SetupState, buildSetupConfig, saveSetupConfig, isConfigured } from './setup-state.js';
import {
  listLocalFounderVtas,
  registerLocalVtaAsFounder,
  createFounderVta,
  createNamespaceVtn,
  selectExternalVtn,
} from './setup-service.js';
import { getBootstrapQuery } from '../services/bootstrap-info.js';
import { CreateVtcConflictError, CreateVtcNotFoundError, CreateVtcValidationError } from '../services/vtc.js';
import { requestShutdown } from '../services/shutdown.js';
import { getNamespaceConfig } from '../services/namespace-service.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';

let state: SetupState = createSetupState();

const __dirname = dirname(fileURLToPath(import.meta.url));

/** `utility-server/.env` — the same file index.ts reads at boot. */
function componentEnvPath(): string {
  return join(__dirname, '..', '..', '.env');
}

/**
 * A bootstrap host is a DNS name or an IP literal — anything with whitespace or
 * a scheme is a paste mistake, and `/` would corrupt the multiaddr built from it.
 */
function isValidBootstrapHost(host: string): boolean {
  if (!host) return true; // empty = "use the .env value"
  if (host.length > 253) return false;
  if (/[\s/\\?#@]/.test(host)) return false;
  return /^[A-Za-z0-9._:-]+$/.test(host);
}

/**
 * A libp2p peer ID is base58btc (`12D3KooW…`) — no `0`, `O`, `I`, or `l`. Checked
 * loosely on length + alphabet: a wrong peer ID means every dial goes to the
 * wrong identity, and the failure mode (a timeout) is otherwise undiagnosable.
 */
function isValidPeerId(peerId: string): boolean {
  if (!peerId) return true; // empty = "use the .env value"
  if (peerId.length < 40 || peerId.length > 128) return false;
  return /^[1-9A-HJ-NP-Za-km-z]+$/.test(peerId);
}

// ── Setup-complete guard (F-06 / SYN-014) ─────────────────────────────
//
// The wizard's handlers are registered once, at boot, when the instance is
// unconfigured — and nothing removes them when `/setup/confirm` persists the
// configuration. Without a guard every setup mutation stays reachable (and, via
// the `/setup/` auth exemption, unauthenticated) in the SAME process for the
// window between confirm and restart, so the config could be rewritten or the
// wizard replayed. `setupClosed()` closes that window: it reads the persisted
// `configured` flag, and every mutation re-checks it *inside* a serialized lock
// so a check-then-act cannot interleave with a concurrent or replayed request.
let lock: Promise<unknown> = Promise.resolve();

/** Serialize setup mutations so simultaneous requests cannot interleave. */
function withSetupLock<T>(fn: () => Promise<T>): Promise<T> {
  const run = lock.then(fn, fn); // run regardless of the prior task's outcome
  lock = run.catch(() => {}); // never let the chain reject
  return run;
}

/** Whether first-launch configuration has already been persisted. */
function setupClosed(): boolean {
  return isConfigured();
}

/** Shared 409 body for a setup action attempted after configuration. */
const SETUP_CLOSED = { error: { message: 'Setup already complete.' } } as const;

export interface SetupRoutesDeps {
  getDb: () => DataSource;
}

export function registerSetupRoutes(app: FastifyInstance, deps: SetupRoutesDeps): void {
  // Encapsulate the wizard in its own Fastify scope so the setup-complete guard
  // applies ONLY to `/setup/*` routes — never to the operational surface.
  app.register(async (scope) => {
    scope.addHook('preHandler', async (_req, reply) => {
      if (setupClosed()) return reply.code(409).send(SETUP_CLOSED);
    });
    registerSetupRouteHandlers(scope, deps);
  });
}

function registerSetupRouteHandlers(app: FastifyInstance, deps: SetupRoutesDeps): void {
  app.get('/setup/state', async (_req, reply) => reply.send(state));

  // Existing VTAs in the agent-app's per-agent databases
  // (P2PTS_HOME/vta/<agent>/p2pts-database.db) — one directory per agent.
  // The wizard forces creation when localDbExists is false or vtas is empty.
  app.get('/setup/candidates', async (_req, reply) => {
    const scan = await listLocalFounderVtas();
    return reply.send(scan);
  });

  // Locate an agent VTA on the network via the bootstrap server (primary path).
  app.get('/setup/discover', async (_req, reply) => {
    const bq = getBootstrapQuery();
    if (!bq) {
      return reply.send({ available: false, peers: [], message: 'Bootstrap server not connected.' });
    }
    try {
      const result = await bq.client.query(bq.node);
      const peers = result.response.peers
        .filter((p) => p.peerType === 'agent')
        .map((p) => ({
          peerId: p.peerId,
          did: p.did,
          vid: p.vid,
          multiaddrs: p.multiaddrs,
          relayAddr: p.relayAddr,
        }));
      return reply.send({ available: true, peers });
    } catch (err) {
      return reply.send({ available: false, peers: [], message: (err as Error).message });
    }
  });

  // Bootstrap defaults for the network step.
  //
  // Pre-filled from this component's `.env` (the block `npm run init:bootstrap`
  // writes), so the operator can ACCEPT the default or replace it in the wizard
  // without editing a file. A missing/invalid `.env` is NOT an error here: the
  // server would simply run in LAN-only mode, and the wizard must stay reachable
  // so setup can still be completed.
  app.get('/setup/bootstrap', async (_req, reply) => {
    try {
      const env = loadBootstrapClientEnv({ path: componentEnvPath() });
      return reply.send({
        available: true,
        host: env.host,
        peerId: env.peerId,
        tcpPort: env.tcpPort,
        wsPort: env.wsPort,
      });
    } catch (err) {
      return reply.send({
        available: false,
        host: '',
        peerId: '',
        tcpPort: 4001,
        wsPort: 4002,
        message: (err as Error).message,
      });
    }
  });

  // Step 1 — mode selection.
  app.post<{ Body: { mode?: string } }>('/setup/mode', async (req, reply) =>
    withSetupLock(async () => {
      if (setupClosed()) return reply.code(409).send(SETUP_CLOSED);
      const mode = req.body?.mode;
      const valid = ['vtn_host', 'vtn_affiliate', 'standalone_vtc'];
      if (!mode || !valid.includes(mode)) {
        return reply.code(400).send({ error: `Invalid mode. Must be one of: ${valid.join(', ')}` });
      }
      state.mode = mode as SetupState['mode'];
      state.currentStep = 1;
      return reply.send({ ok: true, step: state.currentStep });
    }),
  );

  // Step 2 — network / advertised IP + which bootstrap server to register with.
  app.post<{
    Body: {
      advertisedHost?: string;
      httpPort?: number;
      libp2pPort?: number;
      bootstrapHost?: string;
      bootstrapPeerId?: string;
    };
  }>(
    '/setup/network',
    async (req, reply) =>
      withSetupLock(async () => {
        if (setupClosed()) return reply.code(409).send(SETUP_CLOSED);

        // The two bootstrap fields are pre-filled from `.env` and may be accepted
        // as-is or replaced. Empty is legitimate (it means "use the .env value"),
        // but a malformed value is not — a bad peer ID fails as an opaque dial
        // timeout much later, so it is rejected here where it can be explained.
        const bootstrapHost = req.body?.bootstrapHost?.trim() ?? '';
        const bootstrapPeerId = req.body?.bootstrapPeerId?.trim() ?? '';
        if (!isValidBootstrapHost(bootstrapHost)) {
          return reply.code(400).send({
            error: `Invalid bootstrap host "${bootstrapHost}" — use a DNS name or an IP address.`,
          });
        }
        if (!isValidPeerId(bootstrapPeerId)) {
          return reply.code(400).send({
            error: 'Invalid bootstrap peer ID — expected a base58btc libp2p peer ID (12D3Koo…).',
          });
        }

        state.network = {
          advertisedHost: req.body?.advertisedHost ?? '127.0.0.1',
          httpPort: req.body?.httpPort ?? 8787,
          libp2pPort: req.body?.libp2pPort ?? 4003,
          bootstrapHost,
          bootstrapPeerId,
        };
        state.currentStep = 2;
        return reply.send({ ok: true, step: state.currentStep, network: state.network });
      }),
  );

  // Step 3 — founder VTA: log in with an existing local VTA, locate one on the
  // network (bootstrap), or create a new one.
  app.post<{ Body: { action?: string; did?: string; name?: string; passphrase?: string } }>(
    '/setup/identity',
    async (req, reply) =>
      withSetupLock(async () => {
        if (setupClosed()) return reply.code(409).send(SETUP_CLOSED);
        try {
          const db = deps.getDb();
          const action = req.body?.action ?? 'login';

          let founder: { identityUuid: string; did: string; name: string; mnemonic?: string };
          let note: string | undefined;
          if (action === 'create') {
            if (!req.body?.name || !req.body?.passphrase) {
              return reply.code(400).send({ error: 'name and passphrase are required when creating a VTA' });
            }
            founder = await createFounderVta(db, { name: req.body.name, passphrase: req.body.passphrase });
            note = 'Founder VTA created and registered on this server (public identity only — private keys are not stored here).';
          } else {
            if (!req.body?.did || !req.body?.passphrase) {
              return reply.code(400).send({ error: 'did and passphrase are required to log in with an existing local VTA' });
            }
            founder = await registerLocalVtaAsFounder(db, { did: req.body.did, passphrase: req.body.passphrase });
            note = 'Registered your existing VTA as the founding admin.';
          }

          state.adminVtaUuid = founder.identityUuid;
          state.adminVtaDid = founder.did;
          state.currentStep = 3;
          return reply.send({ ok: true, step: state.currentStep, founder, note });
        } catch (err) {
          return reply.code(statusFor(err)).send({ error: (err as Error).message });
        }
      }),
  );

  // Step 4 — create a new VTN (default) or join an existing one (stub).
  app.post<{ Body: { action?: string; name?: string; namespace?: string; vtnDid?: string } }>(
    '/setup/vtn',
    async (req, reply) =>
      withSetupLock(async () => {
        if (setupClosed()) return reply.code(409).send(SETUP_CLOSED);
        try {
          const db = deps.getDb();
          if (!state.adminVtaUuid) {
            return reply.code(400).send({ error: 'Founder VTA must be selected first (step 3)' });
          }

          const action = req.body?.action ?? 'create';
          if (action === 'join') {
            const result = await selectExternalVtn(db, req.body?.vtnDid ?? '');
            return reply.code(501).send({ ok: false, stub: result.stub, message: result.message });
          }

          // Resume an already-provisioned server. The namespace binding lives in the
          // database (which survives losing the local config.json — e.g. a wiped data
          // dir), and `createNamespaceVtn` deliberately refuses a second one. Rather
          // than dead-ending the wizard on the one-namespace-per-server rule, adopt the
          // existing VTN so setup can complete and reconcile config.json with the DB.
          const existingNs = await getNamespaceConfig(db);
          if (existingNs) {
            const vtn = await identitiesRepo.findByUuid(db, existingNs.vtnIdentityUuid);
            const memberships = await membershipsRepo.findForCommunity(db, existingNs.vtnIdentityUuid);
            const foundingAdmin =
              memberships.find((m) => m.role === 'founding_admin' && m.status === 'active') ??
              memberships.find((m) => m.role === 'founding_admin');
            if (foundingAdmin) {
              const adminIdentity = await identitiesRepo.findByUuid(db, foundingAdmin.memberIdentityUuid);
              state.adminVtaUuid = foundingAdmin.memberIdentityUuid;
              state.adminVtaDid = adminIdentity?.did ?? state.adminVtaDid;
            }
            state.vtnUuid = existingNs.vtnIdentityUuid;
            state.vtnDid = vtn?.did ?? undefined;
            state.namespace = existingNs.namespace;
            state.vtnName = vtn?.name ?? existingNs.namespace;
            state.currentStep = 4;
            return reply.send({
              ok: true,
              step: state.currentStep,
              vtn: {
                vtnUuid: existingNs.vtnIdentityUuid,
                vtnDid: vtn?.did ?? '',
                name: vtn?.name ?? existingNs.namespace,
                namespace: existingNs.namespace,
              },
              note:
                `This server already serves the namespace "${existingNs.namespace}" — ` +
                'resumed the existing VTN.',
            });
          }

          const result = await createNamespaceVtn(db, {
            name: req.body?.name ?? 'Default Network',
            namespace: req.body?.namespace ?? 'default',
            founderUuid: state.adminVtaUuid,
          });

          state.vtnUuid = result.vtnUuid;
          state.vtnDid = result.vtnDid;
          state.namespace = result.namespace;
          state.vtnName = result.name;
          state.currentStep = 4;
          return reply.send({ ok: true, step: state.currentStep, vtn: result });
        } catch (err) {
          return reply.code(statusFor(err)).send({ error: (err as Error).message });
        }
      }),
  );

  // Step 5 — confirm & finalize (persists config; the setup process then exits).
  app.post('/setup/confirm', async (_req, reply) =>
    withSetupLock(async () => {
      if (setupClosed()) return reply.code(409).send(SETUP_CLOSED);
      try {
        const cfg = buildSetupConfig(state);
        saveSetupConfig(cfg);
        state.completed = true;
        // Terminate the setup process once this response has been flushed: the HTTP
        // and libp2p ports + advertised IP were bound at boot, so operational mode
        // needs a fresh start. The `finish` hook guarantees the client gets its 200
        // before the process tears down. See services/shutdown.ts + index.ts.
        reply.raw.once('finish', () => requestShutdown('setup-complete'));
        return reply.send({
          ok: true,
          message:
            'Setup complete! Configuration saved. The setup process is now shutting down — ' +
            'restart the utility server to enter operational mode.',
          config: cfg,
        });
      } catch (err) {
        return reply.code(400).send({ error: (err as Error).message });
      }
    }),
  );

  // Reset the in-memory wizard.
  app.post('/setup/reset', async (_req, reply) =>
    withSetupLock(async () => {
      if (setupClosed()) return reply.code(409).send(SETUP_CLOSED);
      state = createSetupState();
      return reply.send({ ok: true });
    }),
  );
}

/** Map known setup errors to HTTP status codes. */
function statusFor(err: unknown): number {
  if (err instanceof CreateVtcConflictError) return 409;
  if (err instanceof CreateVtcNotFoundError) return 404;
  if (err instanceof CreateVtcValidationError) return 400;
  return 400;
}
