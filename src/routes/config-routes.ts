// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * config-routes — founder-admin configuration surface (post-setup).
 *
 * - GET  /namespace/status — public read of the configured namespace.
 * - GET  /config           — view current configuration (founder admin only).
 * - PATCH /config          — edit network (IP/ports) + namespace (founder admin only).
 */

import type { FastifyInstance } from 'fastify';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import { loadSetupConfig, saveSetupConfig } from '../setup/setup-state.js';
import { getNamespaceConfig, setNamespaceConfig } from '../services/namespace-service.js';
import { requireNamespaceAdmin } from '../plugins/require-namespace-admin.js';

export function registerConfigRoutes(app: FastifyInstance, db: DataSource): void {
  // Public read — used by dashboards and (future) agent namespace discovery.
  app.get('/namespace/status', async (_req, _reply) => {
    const cfg = await getNamespaceConfig(db);
    return {
      configured: cfg != null,
      namespace: cfg?.namespace ?? null,
      vtnUuid: cfg?.vtnIdentityUuid ?? null,
    };
  });

  app.get('/config', { preHandler: requireNamespaceAdmin }, async (_req, _reply) => {
    const setup = loadSetupConfig();
    const ns = await getNamespaceConfig(db);
    return {
      mode: setup.mode,
      adminVtaUuid: setup.adminVtaUuid,
      adminVtaDid: setup.adminVtaDid,
      namespace: ns?.namespace ?? setup.namespace,
      vtnUuid: ns?.vtnIdentityUuid ?? setup.vtnUuid,
      vtnDid: setup.vtnDid,
      network: setup.network,
      createdAt: setup.createdAt,
      updatedAt: setup.updatedAt,
    };
  });

  app.patch(
    '/config',
    { preHandler: requireNamespaceAdmin },
    async (req, reply) => {
      const body = (req.body ?? {}) as {
        advertisedHost?: string; httpPort?: number; libp2pPort?: number; namespace?: string;
      };
      const setup = loadSetupConfig();
      let requiresRestart = false;

      if (body.advertisedHost !== undefined && body.advertisedHost.trim()) {
        setup.network.advertisedHost = body.advertisedHost.trim();
        requiresRestart = true;
      }
      if (body.httpPort !== undefined) {
        const port = Number(body.httpPort);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
          return reply.code(400).send({ error: { message: 'httpPort must be an integer 1-65535' } });
        }
        setup.network.httpPort = port;
        requiresRestart = true;
      }
      if (body.libp2pPort !== undefined) {
        const port = Number(body.libp2pPort);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
          return reply.code(400).send({ error: { message: 'libp2pPort must be an integer 1-65535' } });
        }
        setup.network.libp2pPort = port;
        requiresRestart = true;
      }

      if (body.namespace !== undefined && body.namespace.trim()) {
        const ns = await getNamespaceConfig(db);
        if (!ns) {
          return reply.code(409).send({ error: { message: 'Namespace not configured' } });
        }
        await setNamespaceConfig(db, { vtnIdentityUuid: ns.vtnIdentityUuid, namespace: body.namespace.trim() });
        setup.namespace = body.namespace.trim();
      }

      saveSetupConfig(setup);
      return {
        ok: true,
        config: setup,
        note: requiresRestart
          ? 'Network changes (IP/ports) take effect after a restart.'
          : 'Configuration saved.',
      };
    },
  );
}
