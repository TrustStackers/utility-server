// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * require-namespace-admin — Fastify preHandler that gates the founder-admin
 * configuration surface: the session identity must be a VTA holding an ACTIVE
 * founding_admin/admin membership in the namespace VTN.
 */

import type { FastifyRequest, FastifyReply } from 'fastify';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import { validateSession } from '../session.js';
import { getNamespaceConfig, isNamespaceAdmin } from '../services/namespace-service.js';

export async function requireNamespaceAdmin(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const db = (request.server as any).db as DataSource;
  const hmacSecret = (request.server as any).hmacSecret as Buffer;

  const session = validateSession(request.headers.cookie, hmacSecret);
  if (!session) {
    return reply.code(401).send({ error: { message: 'Authentication required. Sign in with your founder VTA.' } });
  }

  const identity = await identitiesRepo.findByUuid(db, session.identityUuid);
  if (!identity || identity.role !== 'vta') {
    return reply.code(401).send({ error: { message: 'Session identity not found or not a VTA.' } });
  }

  const ns = await getNamespaceConfig(db);
  if (!ns) {
    return reply.code(409).send({ error: { message: 'Namespace not configured.' } });
  }

  const allowed = await isNamespaceAdmin(db, identity.uuid, ns.vtnIdentityUuid);
  if (!allowed) {
    return reply.code(403).send({ error: { message: 'Founding admin membership required.' } });
  }

  request.currentIdentity = identity;
}
