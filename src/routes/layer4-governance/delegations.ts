/**
 * Layer 4 — Governance: /delegations routes.
 *
 * - POST /delegations              — create a delegation (operates/owns/represents/employs)
 * - GET  /delegations              — list, filterable by ?principalUuid=&dependentUuid=
 * - POST /delegations/:uuid/revoke — revoke a delegation
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import * as delegationsRepo from '@p2p-trust-stack/core/db/repositories/delegations-repo.js';
import type { DelegationRelationshipType } from '@p2p-trust-stack/core/db/repositories/delegations-repo.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as credentialsRepo from '@p2p-trust-stack/core/db/repositories/credentials-repo.js';

interface CreateDelegationBody {
  principalIdentityUuid: string;
  dependentIdentityUuid: string;
  relationshipType: DelegationRelationshipType;
  scope?: unknown;
  credentialUuid?: string;
  expiresAt?: number;
}

interface ListQuery {
  principalUuid?: string;
  dependentUuid?: string;
}

const VALID_RELATIONSHIP_TYPES: DelegationRelationshipType[] = ['operates', 'owns', 'represents', 'employs'];

export function registerDelegationRoutes(app: FastifyInstance, db: DataSource): void {
  // -------------------------------------------------------------------------
  // GET /delegations/:uuid — fetch a single delegation by uuid
  // -------------------------------------------------------------------------
  app.get(
    '/delegations/:uuid',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const delegationUuid = req.params.uuid;
      if (!delegationUuid) {
        return reply.code(400).send({ error: { message: 'delegation uuid (param) is required' } });
      }
      const delegation = await delegationsRepo.findByUuid(db, delegationUuid);
      if (!delegation) {
        return reply.code(404).send({ error: { message: `delegation ${delegationUuid} not found` } });
      }
      return delegation;
    },
  );

  // -------------------------------------------------------------------------
  // POST /delegations — create a delegation
  // -------------------------------------------------------------------------
  app.post(
    '/delegations',
    async (req: FastifyRequest<{ Body: CreateDelegationBody }>, reply: FastifyReply) => {
      const body = req.body;
      if (!body?.principalIdentityUuid || !body?.dependentIdentityUuid || !body?.relationshipType) {
        return reply.code(400).send({
          error: { message: 'principalIdentityUuid, dependentIdentityUuid, and relationshipType are required' },
        });
      }
      if (!VALID_RELATIONSHIP_TYPES.includes(body.relationshipType)) {
        return reply
          .code(400)
          .send({ error: { message: `relationshipType must be one of: ${VALID_RELATIONSHIP_TYPES.join(', ')}` } });
      }
      const principal = await identitiesRepo.findByUuid(db, body.principalIdentityUuid);
      if (!principal) {
        return reply
          .code(404)
          .send({ error: { message: `principal identity ${body.principalIdentityUuid} not found` } });
      }
      const dependent = await identitiesRepo.findByUuid(db, body.dependentIdentityUuid);
      if (!dependent) {
        return reply
          .code(404)
          .send({ error: { message: `dependent identity ${body.dependentIdentityUuid} not found` } });
      }
      let credentialUuid: string | null | undefined;
      if (body.credentialUuid !== undefined) {
        const cred = await credentialsRepo.findByUuid(db, body.credentialUuid);
        if (!cred) {
          return reply.code(404).send({ error: { message: `credential ${body.credentialUuid} not found` } });
        }
        credentialUuid = cred.uuid;
      }

      const delegationUuid = await delegationsRepo.create(db, {
        principalIdentityUuid: principal.uuid,
        dependentIdentityUuid: dependent.uuid,
        relationshipType: body.relationshipType,
        scope: body.scope !== undefined ? JSON.stringify(body.scope) : undefined,
        credentialUuid: credentialUuid ?? undefined,
        expiresAt: body.expiresAt,
      });

      return reply.code(201).send(await delegationsRepo.findByUuid(db, delegationUuid));
    },
  );

  // -------------------------------------------------------------------------
  // GET /delegations — list, filterable by ?principalUuid=&dependentUuid=
  // -------------------------------------------------------------------------
  app.get('/delegations', async (req: FastifyRequest<{ Querystring: ListQuery }>, _reply: FastifyReply) => {
    const { principalUuid, dependentUuid } = req.query;

    return delegationsRepo.list(db, { principalIdentityUuid: principalUuid, dependentIdentityUuid: dependentUuid });
  });

  // -------------------------------------------------------------------------
  // POST /delegations/:uuid/revoke — revoke a delegation
  // -------------------------------------------------------------------------
  app.post(
    '/delegations/:uuid/revoke',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const delegationUuid = req.params.uuid;
      if (!delegationUuid) {
        return reply.code(400).send({ error: { message: 'delegation uuid (param) is required' } });
      }
      const delegation = await delegationsRepo.findByUuid(db, delegationUuid);
      if (!delegation) {
        return reply.code(404).send({ error: { message: `delegation ${delegationUuid} not found` } });
      }
      if (delegation.revokedAt !== null) {
        return reply.code(409).send({ error: { message: `delegation ${delegationUuid} is already revoked` } });
      }

      await delegationsRepo.revoke(db, delegationUuid);
      return delegationsRepo.findByUuid(db, delegationUuid);
    },
  );
}
