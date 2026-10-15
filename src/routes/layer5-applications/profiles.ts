/**
 * Layer 5 — Trust Applications: Profile routes (Scenario 3 — "Manage
 * Multiple Profiles"), including the R-Card assembly endpoint that also
 * backs Scenario 8's "attach a profile card to a VRC" flow.
 *
 * - POST   /identities/:id/profiles          — create a profile
 * - GET    /identities/:id/profiles          — list an identity's profiles
 * - PATCH  /profiles/:id                     — update label/purpose/visibility/default
 * - DELETE /profiles/:id                     — remove a profile (guarded)
 * - POST   /profiles/:id/claims              — add a claim
 * - GET    /profiles/:id/claims              — list a profile's claims
 * - PATCH  /profile-claims/:id               — update a claim
 * - DELETE /profile-claims/:id               — remove a claim
 * - GET    /profiles/:id/card                — assemble the shareable R-Card view
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import * as profilesService from '../../services/profiles.js';
import { ProfileValidationError, ProfileNotFoundError } from '../../services/profiles.js';
import type { ProfileVisibility } from '@p2p-trust-stack/core/db/repositories/profiles-repo.js';
import type { ProfileClaimValueType, ProfileClaimDisclosure } from '@p2p-trust-stack/core/db/repositories/profile-claims-repo.js';

interface CreateProfileBody {
  label: string;
  purpose?: string;
  visibility?: ProfileVisibility;
}

interface UpdateProfileBody {
  label?: string;
  purpose?: string | null;
  visibility?: ProfileVisibility;
  setDefault?: boolean;
}

interface CreateClaimBody {
  claimKey: string;
  claimValue?: string | null;
  valueType?: ProfileClaimValueType;
  disclosure?: ProfileClaimDisclosure;
  displayOrder?: number;
}

interface UpdateClaimBody {
  claimValue?: string | null;
  valueType?: ProfileClaimValueType;
  disclosure?: ProfileClaimDisclosure;
  displayOrder?: number;
}

interface CardQuery {
  requested?: string; // comma-separated claim keys
}

function handleError(err: unknown, reply: FastifyReply) {
  if (err instanceof ProfileValidationError) {
    return reply.code(400).send({ error: { message: err.message } });
  }
  if (err instanceof ProfileNotFoundError) {
    return reply.code(404).send({ error: { message: err.message } });
  }
  throw err;
}

export function registerProfileRoutes(app: FastifyInstance, db: DataSource): void {
  // ---------------------------------------------------------------------
  // Profiles
  // ---------------------------------------------------------------------

  app.post(
    '/identities/:uuid/profiles',
    async (req: FastifyRequest<{ Params: { uuid: string }; Body: CreateProfileBody }>, reply: FastifyReply) => {
      const identityUuid = req.params.uuid;
      try {
        const profile = await profilesService.createProfile(db, {
          identityUuid,
          label: req.body?.label,
          purpose: req.body?.purpose,
          visibility: req.body?.visibility,
        });
        return reply.code(201).send(profile);
      } catch (err) {
        return handleError(err, reply);
      }
    },
  );

  app.get(
    '/identities/:uuid/profiles',
    async (req: FastifyRequest<{ Params: { uuid: string } }>) => {
      return profilesService.listProfiles(db, req.params.uuid);
    },
  );

  app.get(
    '/profiles/:uuid',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      try {
        return profilesService.getProfile(db, req.params.uuid);
      } catch (err) {
        return handleError(err, reply);
      }
    },
  );

  app.patch(
    '/profiles/:uuid',
    async (req: FastifyRequest<{ Params: { uuid: string }; Body: UpdateProfileBody }>, reply: FastifyReply) => {
      try {
        const profile = await profilesService.updateProfile(db, req.params.uuid, req.body ?? {});
        return reply.code(200).send(profile);
      } catch (err) {
        return handleError(err, reply);
      }
    },
  );

  app.delete(
    '/profiles/:uuid',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      try {
        await profilesService.removeProfile(db, req.params.uuid);
        return reply.code(204).send();
      } catch (err) {
        return handleError(err, reply);
      }
    },
  );

  // ---------------------------------------------------------------------
  // Profile Claims
  // ---------------------------------------------------------------------

  app.post(
    '/profiles/:uuid/claims',
    async (req: FastifyRequest<{ Params: { uuid: string }; Body: CreateClaimBody }>, reply: FastifyReply) => {
      const profileUuid = req.params.uuid;
      try {
        const claim = await profilesService.addClaim(db, {
          profileUuid,
          claimKey: req.body?.claimKey,
          claimValue: req.body?.claimValue,
          valueType: req.body?.valueType,
          disclosure: req.body?.disclosure,
          displayOrder: req.body?.displayOrder,
        });
        return reply.code(201).send(claim);
      } catch (err) {
        return handleError(err, reply);
      }
    },
  );

  app.get(
    '/profiles/:uuid/claims',
    async (req: FastifyRequest<{ Params: { uuid: string } }>) => {
      return profilesService.listClaims(db, req.params.uuid);
    },
  );

  app.patch(
    '/profile-claims/:uuid',
    async (req: FastifyRequest<{ Params: { uuid: string }; Body: UpdateClaimBody }>, reply: FastifyReply) => {
      const claimUuid = req.params.uuid;
      if (!claimUuid) {
        return reply.code(400).send({ error: { message: 'claim uuid (param) is required' } });
      }
      try {
        const claim = await profilesService.updateClaim(db, claimUuid, req.body ?? {});
        return reply.code(200).send(claim);
      } catch (err) {
        return handleError(err, reply);
      }
    },
  );

  app.delete(
    '/profile-claims/:uuid',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const claimUuid = req.params.uuid;
      if (!claimUuid) {
        return reply.code(400).send({ error: { message: 'claim uuid (param) is required' } });
      }
      try {
        await profilesService.removeClaim(db, claimUuid);
        return reply.code(204).send();
      } catch (err) {
        return handleError(err, reply);
      }
    },
  );

  // ---------------------------------------------------------------------
  // R-Card assembly
  // ---------------------------------------------------------------------

  app.get(
    '/profiles/:uuid/card',
    async (req: FastifyRequest<{ Params: { uuid: string }; Querystring: CardQuery }>, reply: FastifyReply) => {
      const requested = req.query.requested
        ? req.query.requested.split(',').map((k) => k.trim()).filter(Boolean)
        : [];
      try {
        return profilesService.getProfileCard(db, req.params.uuid, requested);
      } catch (err) {
        return handleError(err, reply);
      }
    },
  );
}
