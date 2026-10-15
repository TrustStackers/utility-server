/**
 * Layer 5 — Trust Applications: GET /identities/:id/profile
 *
 * Assembled, cross-cutting view of a single identity: the identity row
 * itself, its primary DID document, every membership it holds (as a
 * member), every delegation it participates in (as principal or
 * dependent), and every grant where it is the grantee — a read-only
 * composition over Layer 1-4 tables, per
 * ../../../../docs/utility-server-api-plan.md section 4 "Layer 5".
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import * as delegationsRepo from '@p2p-trust-stack/core/db/repositories/delegations-repo.js';
import * as grantsRepo from '@p2p-trust-stack/core/db/repositories/grants-repo.js';

export function registerProfileRoute(app: FastifyInstance, db: DataSource): void {
  app.get(
    '/identities/:uuid/profile',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const identityUuid = req.params.uuid;

      const identity = await identitiesRepo.findByUuid(db, identityUuid);
      if (!identity) {
        return reply.code(404).send({ error: { message: `identity ${identityUuid} not found` } });
      }

      const primaryDidDocument = await didDocumentsRepo.findPrimaryForIdentity(db, identityUuid);
      const memberships = await membershipsRepo.findForMember(db, identity.uuid);

      // Delegations where this identity is either side of the relationship.
      const delegationsAsPrincipal = await delegationsRepo.list(db, { principalIdentityUuid: identity.uuid });
      const delegationsAsDependent = await delegationsRepo.list(db, { dependentIdentityUuid: identity.uuid });

      const grants = await grantsRepo.list(db, { granteeIdentityUuid: identity.uuid });

      return reply.code(200).send({
        identity,
        primaryDidDocument,
        memberships,
        delegations: {
          asPrincipal: delegationsAsPrincipal,
          asDependent: delegationsAsDependent,
        },
        grants,
      });
    },
  );
}
