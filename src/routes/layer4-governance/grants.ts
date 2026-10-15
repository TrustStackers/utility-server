/**
 * Layer 4 — Governance: /grants routes.
 *
 * - POST /grants        — create a grant (usually system-generated on credential/delegation
 *                          issuance, exposed here for manual/testing use)
 * - GET  /grants/check  — the fast-path authorization check: does grantee hold permission in scope?
 *
 * Grant rows are uuid-keyed (migration 0018); the HTTP surface addresses a
 * grant by its own `uuid`. Identity/credential/delegation references in the
 * create body remain integers where those target tables are still
 * integer-id-keyed (identities, credentials) or are resolved via uuid
 * (delegations), and are converted to *_uuid columns for the repo call.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import * as grantsRepo from '@p2p-trust-stack/core/db/repositories/grants-repo.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as credentialsRepo from '@p2p-trust-stack/core/db/repositories/credentials-repo.js';
import * as delegationsRepo from '@p2p-trust-stack/core/db/repositories/delegations-repo.js';

interface CreateGrantBody {
  granteeIdentityUuid: string;
  scopeIdentityUuid?: string;
  permission: string;
  sourceCredentialUuid?: string;
  sourceDelegationUuid?: string;
}

interface CheckQuery {
  granteeUuid?: string;
  permission?: string;
  scopeUuid?: string;
}

interface ListQuery {
  granteeUuid?: string;
  scopeUuid?: string;
  permission?: string;
}

export function registerGrantRoutes(app: FastifyInstance, db: DataSource): void {
  // -------------------------------------------------------------------------
  // GET /grants/:uuid — fetch a single grant by uuid
  // -------------------------------------------------------------------------
  app.get(
    '/grants/:uuid',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const grantUuid = req.params.uuid;
      if (!grantUuid) {
        return reply.code(400).send({ error: { message: 'grant uuid (param) is required' } });
      }
      const grant = await grantsRepo.findByUuid(db, grantUuid);
      if (!grant) {
        return reply.code(404).send({ error: { message: `grant ${grantUuid} not found` } });
      }
      return grant;
    },
  );

  // -------------------------------------------------------------------------
  // GET /grants — list, filterable by ?granteeUuid=&scopeUuid=&permission=
  // -------------------------------------------------------------------------
  app.get('/grants', async (req: FastifyRequest<{ Querystring: ListQuery }>, _reply: FastifyReply) => {
    const { granteeUuid, scopeUuid, permission } = req.query;

    return grantsRepo.list(db, { granteeIdentityUuid: granteeUuid, scopeIdentityUuid: scopeUuid, permission });
  });

  // -------------------------------------------------------------------------
  // POST /grants — create a grant
  // -------------------------------------------------------------------------
  app.post(
    '/grants',
    async (req: FastifyRequest<{ Body: CreateGrantBody }>, reply: FastifyReply) => {
      const body = req.body;
      if (!body?.granteeIdentityUuid || !body?.permission) {
        return reply.code(400).send({ error: { message: 'granteeIdentityUuid and permission are required' } });
      }
      const grantee = await identitiesRepo.findByUuid(db, body.granteeIdentityUuid);
      if (!grantee) {
        return reply.code(404).send({ error: { message: `grantee identity ${body.granteeIdentityUuid} not found` } });
      }
      let scopeUuid: string | null | undefined;
      if (body.scopeIdentityUuid !== undefined) {
        const scope = await identitiesRepo.findByUuid(db, body.scopeIdentityUuid);
        if (!scope) {
          return reply.code(404).send({ error: { message: `scope identity ${body.scopeIdentityUuid} not found` } });
        }
        scopeUuid = scope.uuid;
      }
      let sourceCredentialUuid: string | null | undefined;
      if (body.sourceCredentialUuid !== undefined) {
        const cred = await credentialsRepo.findByUuid(db, body.sourceCredentialUuid);
        if (!cred) {
          return reply
            .code(404)
            .send({ error: { message: `source credential ${body.sourceCredentialUuid} not found` } });
        }
        sourceCredentialUuid = cred.uuid;
      }
      if (body.sourceDelegationUuid !== undefined && !await delegationsRepo.findByUuid(db, body.sourceDelegationUuid)) {
        return reply
          .code(404)
          .send({ error: { message: `source delegation ${body.sourceDelegationUuid} not found` } });
      }

      const grantUuid = await grantsRepo.create(db, {
        granteeIdentityUuid: grantee.uuid,
        scopeIdentityUuid: scopeUuid ?? undefined,
        permission: body.permission,
        sourceCredentialUuid: sourceCredentialUuid ?? undefined,
        sourceDelegationUuid: body.sourceDelegationUuid,
      });

      return reply.code(201).send(await grantsRepo.findByUuid(db, grantUuid));
    },
  );

  // -------------------------------------------------------------------------
  // POST /grants/:uuid/revoke — revoke a grant
  // -------------------------------------------------------------------------
  app.post(
    '/grants/:uuid/revoke',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const grantUuid = req.params.uuid;
      if (!grantUuid) {
        return reply.code(400).send({ error: { message: 'grant uuid (param) is required' } });
      }
      const grant = await grantsRepo.findByUuid(db, grantUuid);
      if (!grant) {
        return reply.code(404).send({ error: { message: `grant ${grantUuid} not found` } });
      }
      if (grant.revokedAt !== null) {
        return reply.code(409).send({ error: { message: `grant ${grantUuid} is already revoked` } });
      }

      await grantsRepo.revoke(db, grantUuid);
      return grantsRepo.findByUuid(db, grantUuid);
    },
  );

  // -------------------------------------------------------------------------
  // GET /grants/check?granteeUuid=&permission=&scopeUuid=
  // -------------------------------------------------------------------------
  app.get('/grants/check', async (req: FastifyRequest<{ Querystring: CheckQuery }>, reply: FastifyReply) => {
    const { granteeUuid, permission, scopeUuid } = req.query;
    if (!granteeUuid || !permission) {
      return reply.code(400).send({ error: { message: 'granteeUuid and permission query parameters are required' } });
    }

    const grant = await grantsRepo.check(db, granteeUuid, permission, scopeUuid);
    return {
      granted: grant !== null,
      grant,
    };
  });
}
