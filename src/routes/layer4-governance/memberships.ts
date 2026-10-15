/**
 * Layer 4 — Governance: /memberships routes.
 *
 * - POST /communities/:communityId/memberships    — join request ('pending')
 * - POST /memberships/:uuid/approve               — admin approval -> 'active' + issues backing VMC credential
 * - POST /memberships/:uuid/reject                — admin rejection of a pending request
 * - POST /memberships/:uuid/revoke                — admin removal of an active member
 * - POST /memberships/:uuid/personhood-events     — record challenge/assert/revoke
 *
 * Membership rows are uuid-keyed (migration 0018) — `:uuid` params address the
 * membership itself by its PRIMARY KEY. Identity references in join bodies
 * remain integers where `identities` is still integer-keyed, resolved to the
 * identity uuid for the membership repo calls.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import type { MembershipRole } from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import * as personhoodEventsRepo from '@p2p-trust-stack/core/db/repositories/personhood-events-repo.js';
import type { PersonhoodEvent } from '@p2p-trust-stack/core/db/repositories/personhood-events-repo.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as credentialsRepo from '@p2p-trust-stack/core/db/repositories/credentials-repo.js';
import * as statusListsRepo from '@p2p-trust-stack/core/db/repositories/status-lists-repo.js';
import { gateMembershipAdmission } from '@p2p-trust-stack/core/services/membership-presentation.js';
import type { MembershipPresentation } from '@p2p-trust-stack/core/services/membership-presentation.js';
import { tryEnqueueFanout } from '../../services/exchange-runtime.js';
import { randomUUID } from 'node:crypto';
import { driveCeremony } from '@p2p-trust-stack/core/services/trust-tasks/driver.js';
import { guardAuthorizer } from '@p2p-trust-stack/core/services/trust-tasks/authorizer.js';
import { CEREMONY_MEMBER_ONBOARDING, ONBOARDING_VMC_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/type-uris.js';
import { GovernanceGuard } from '@p2p-trust-stack/core/services/governance-guard.js';
import { createPolicyEngine } from '@p2p-trust-stack/core/services/policy-engine-config.js';

/** VMC (Verified Membership Credential) default validity window per OpenVTC spec. */
const VMC_DEFAULT_VALIDITY_SECONDS = 30 * 24 * 60 * 60; // 30 days

interface JoinBody {
  memberIdentityUuid: string;
  role?: MembershipRole;
  /**
   * Optional proof of possession of the member's key (audit F-026 / decision
   * F-001b). Absent is still accepted under the default `warn` policy; under
   * `TSP_MEMBERSHIP_PRESENTATION_POLICY=enforce` it is required.
   */
  presentation?: MembershipPresentation;
}

interface ListQuery {
  memberIdentityUuid?: string;
  communityIdentityUuid?: string;
  status?: string;
}

interface ApproveBody {
  claim?: unknown;
  validUntil?: number;
}

interface PersonhoodEventBody {
  event: PersonhoodEvent;
  reason?: string;
  actorIdentityUuid?: string;
}

export function registerMembershipRoutes(app: FastifyInstance, db: DataSource): void {
  // -------------------------------------------------------------------------
  // GET /memberships/:uuid — fetch a single membership
  // -------------------------------------------------------------------------
  app.get(
    '/memberships/:uuid',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const membershipUuid = req.params.uuid;
      if (!membershipUuid) {
        return reply.code(400).send({ error: { message: 'membership uuid (param) is required' } });
      }
      const membership = await membershipsRepo.findByUuid(db, membershipUuid);
      if (!membership) {
        return reply.code(404).send({ error: { message: `membership ${membershipUuid} not found` } });
      }
      return membership;
    },
  );

  // -------------------------------------------------------------------------
  // GET /memberships — list, filterable by ?memberIdentityUuid=&communityIdentityUuid=&status=
  // -------------------------------------------------------------------------
  app.get('/memberships', async (req: FastifyRequest<{ Querystring: ListQuery }>, reply: FastifyReply) => {
    const { memberIdentityUuid, communityIdentityUuid, status } = req.query;

    if (status !== undefined && !['pending', 'active', 'revoked'].includes(status)) {
      return reply.code(400).send({ error: { message: 'status must be one of: pending, active, revoked' } });
    }

    return membershipsRepo.list(db, {
      memberIdentityUuid,
      communityIdentityUuid,
      status: status as 'pending' | 'active' | 'revoked' | undefined,
    });
  });

  // -------------------------------------------------------------------------
  // POST /communities/:communityId/memberships — join request ('pending')
  // -------------------------------------------------------------------------
  app.post(
    '/communities/:communityUuid/memberships',
    async (
      req: FastifyRequest<{ Params: { communityUuid: string }; Body: JoinBody }>,
      reply: FastifyReply,
    ) => {
      const communityUuid = req.params.communityUuid;
      const body = req.body;
      if (!communityUuid || !body?.memberIdentityUuid) {
        return reply
          .code(400)
          .send({ error: { message: 'communityUuid (param) and memberIdentityUuid (body) are required' } });
      }

      const community = await identitiesRepo.findByUuid(db, communityUuid);
      if (!community) {
        return reply.code(404).send({ error: { message: `community identity ${communityUuid} not found` } });
      }
      if (community.role !== 'vtc' && community.role !== 'vtn') {
        return reply
          .code(409)
          .send({ error: { message: `identity ${communityUuid} is not a community (role=${community.role})` } });
      }
      const member = await identitiesRepo.findByUuid(db, body.memberIdentityUuid);
      if (!member) {
        return reply.code(404).send({ error: { message: `member identity ${body.memberIdentityUuid} not found` } });
      }

      const existing = await membershipsRepo.findByPair(db, member.uuid, community.uuid);
      if (existing) {
        return reply.code(409).send({
          error: { message: `identity ${body.memberIdentityUuid} already has a membership (status=${existing.status}) in community ${communityUuid}` },
        });
      }

      // --- Admission presentation (audit F-026 / decision F-001b) ---
      // Before this, admission required no presentation of any kind, so nothing
      // proved the party being admitted is the party who asked.
      const gate = await gateMembershipAdmission(db, {
        communityUuid: community.uuid,
        memberIdentityUuid: member.uuid,
        role: body.role,
        presentation: body.presentation,
      });
      if (gate.refuse) {
        return reply.code(403).send({
          error: {
            message: `admission refused: ${gate.outcome!.reason}`,
          },
          admission: { policy: gate.policy, verdict: gate.outcome!.verdict, reason: gate.outcome!.reason },
        });
      }

      const membershipUuid = await membershipsRepo.create(db, {
        memberIdentityUuid: member.uuid,
        communityIdentityUuid: community.uuid,
        role: body.role,
        status: 'pending',
      });

      const created = await membershipsRepo.findByUuid(db, membershipUuid);
      return reply.code(201).send({
        ...created,
        // Reported on every admission so an operator can see WHICH admissions were
        // actually proven, rather than inferring it from the policy value.
        admission: gate.outcome
          ? { policy: gate.policy, verdict: gate.outcome.verdict, reason: gate.outcome.reason }
          : { policy: gate.policy },
      });
    },
  );

  // -------------------------------------------------------------------------
  // POST /memberships/:uuid/approve — admin approval -> 'active' + issues VMC
  // -------------------------------------------------------------------------
  app.post(
    '/memberships/:uuid/approve',
    async (req: FastifyRequest<{ Params: { uuid: string }; Body: ApproveBody }>, reply: FastifyReply) => {
      const membershipUuid = req.params.uuid;
      if (!membershipUuid) {
        return reply.code(400).send({ error: { message: 'membership uuid (param) is required' } });
      }

      const membership = await membershipsRepo.findByUuid(db, membershipUuid);
      if (!membership) {
        return reply.code(404).send({ error: { message: `membership ${membershipUuid} not found` } });
      }
      if (membership.status !== 'pending') {
        return reply
          .code(409)
          .send({ error: { message: `membership ${membershipUuid} is not pending (status=${membership.status})` } });
      }

      const body = req.body ?? ({} as ApproveBody);
      const now = Math.floor(Date.now() / 1000);
      const validUntil = body.validUntil ?? now + VMC_DEFAULT_VALIDITY_SECONDS;

      // Issue the backing VMC (Verified Membership Credential) by DRIVING the
      // `member-onboarding` trust-task ceremony: a `policy` gate on the community's
      // `issue_credential` rule, then an `effect` step that mints the credential
      // (single-issuer — the community identity issues directly to the member,
      // mirroring the single-signer path in layer3-tasks/credentials.ts). The gate,
      // the mint, and every trust-task record commit atomically; a denied gate rolls
      // the mint back and the request is refused.
      const issuer = await identitiesRepo.findByUuid(db, membership.communityIdentityUuid);
      const subject = await identitiesRepo.findByUuid(db, membership.memberIdentityUuid);
      if (!issuer || !subject) {
        return reply.code(404).send({ error: { message: 'issuer or subject identity not found' } });
      }
      const issuerDid = issuer.did ?? issuer.uuid;
      const subjectDid = subject.did ?? subject.uuid;

      const threadId = randomUUID();
      let credentialUuid: string | undefined;
      try {
        const driven = await db.transaction((tx) =>
          driveCeremony(tx, CEREMONY_MEMBER_ONBOARDING, threadId, {
            authorizer: guardAuthorizer(new GovernanceGuard(tx, createPolicyEngine())),
            context: {
              db: tx,
              issuerIdentityUuid: issuer.uuid,
              subjectIdentityUuid: subject.uuid,
              communityDid: issuerDid,
              actorDid: issuerDid,
              params: { kind: 'MembershipCredential', subjectDid },
              claim: body.claim !== undefined
                ? (typeof body.claim === 'string' ? JSON.parse(body.claim) : body.claim)
                : { membershipRole: membership.role },
              validUntil,
              membershipRole: membership.role,
            },
          }),
        );
        if (!driven.completed) {
          return reply.code(403).send({
            error: { message: `membership onboarding denied at ${driven.haltedAt}`, threadId },
          });
        }
        credentialUuid = (driven.outputs[ONBOARDING_VMC_TYPE] as { credentialUuid?: string } | undefined)
          ?.credentialUuid;
      } catch (err) {
        return reply.code(500).send({
          error: { message: `membership onboarding failed: ${(err as Error)?.message ?? err}`, threadId },
        });
      }
      if (!credentialUuid) {
        return reply.code(500).send({
          error: { message: 'membership onboarding produced no credential', threadId },
        });
      }

      // Exchange engine emission: fan out the minted VMC to the SUBJECT agent via
      // the CRE `credential` recordset (op exchange:credential), so the credential
      // reaches the holder even if they're offline at approval time.
      try {
        await tryEnqueueFanout('credential', { credentialUuid });
      } catch (err) {
        console.warn(
          `[memberships] failed to enqueue credential delivery for ${credentialUuid}: ${(err as Error)?.message ?? err}`,
        );
      }

      await membershipsRepo.approve(db, membershipUuid, credentialUuid ?? null);
      try { const { DidManager } = await import("@p2p-trust-stack/core/services/did-manager.js"); await new DidManager(db).createMemberDid(subject.uuid, issuer.uuid); } catch (err) { console.warn("[memberships] M-DID skipped:", (err as Error).message); }

      // ── Fan-out delivery for the now-active member via the CRE engine ─────
      // The durable AgentDeliveryQueue is the engine's queue-row transport; the
      // newly approved member receives the full community package when reachable.
      await tryEnqueueFanout('vtc-membership', { communityUuid: issuer.uuid });

      return reply.code(200).send({
        membership: await membershipsRepo.findByUuid(db, membershipUuid),
        credential: await credentialsRepo.findByUuid(db, credentialUuid),
      });
    },
  );

  // -------------------------------------------------------------------------
  // POST /memberships/:uuid/reject — admin rejection of a pending request
  // (Scenario 5). Distinct from /revoke (which removes an already-active
  // member): reject applies to a still-pending join request, and — unlike
  // approve — mints no VMC credential. Both land the membership row in the
  // same 'revoked' terminal status since there is no separate "rejected"
  // status in the schema (see mockup/data-schema-notes.md's memberships
  // table: status is pending|active|revoked); the distinction between
  // "never admitted" and "admitted then removed" lives in whether
  // membership_credential_id ever got set, not in a status value.
  // -------------------------------------------------------------------------
  app.post(
    '/memberships/:uuid/reject',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const membershipUuid = req.params.uuid;
      if (!membershipUuid) {
        return reply.code(400).send({ error: { message: 'membership uuid (param) is required' } });
      }

      const membership = await membershipsRepo.findByUuid(db, membershipUuid);
      if (!membership) {
        return reply.code(404).send({ error: { message: `membership ${membershipUuid} not found` } });
      }
      if (membership.status !== 'pending') {
        return reply
          .code(409)
          .send({ error: { message: `membership ${membershipUuid} is not pending (status=${membership.status})` } });
      }

      await membershipsRepo.revoke(db, membershipUuid);
      return reply.code(200).send(await membershipsRepo.findByUuid(db, membershipUuid));
    },
  );

  // -------------------------------------------------------------------------
  // POST /memberships/:uuid/revoke — admin removal of an active member
  // (Scenario 6 — "Manage a VTC"). Flips status to 'revoked' and, if a
  // backing VMC credential was issued at approval time, revokes it too
  // (flips its status_list bit) so external verifiers checking the
  // credential's revocation status see the membership end reflected there
  // as well — the membership row and its backing credential are two
  // separate rows (see memberships-repo.ts's docstring on entity-level vs
  // DID-level state) that must be kept in sync by the caller, which is what
  // this route does in one composed action.
  // -------------------------------------------------------------------------
  app.post(
    '/memberships/:uuid/revoke',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const membershipUuid = req.params.uuid;
      if (!membershipUuid) {
        return reply.code(400).send({ error: { message: 'membership uuid (param) is required' } });
      }

      const membership = await membershipsRepo.findByUuid(db, membershipUuid);
      if (!membership) {
        return reply.code(404).send({ error: { message: `membership ${membershipUuid} not found` } });
      }
      if (membership.status === 'revoked') {
        return reply.code(409).send({ error: { message: `membership ${membershipUuid} is already revoked` } });
      }

      await membershipsRepo.revoke(db, membershipUuid);

      // If a backing VMC was issued at approval time, revoke it too (flip
      // its status_list bit + set status='revoked'), mirroring the exact
      // sequence in layer3-tasks/credentials.ts's POST /credentials/:id/revoke
      // — duplicated rather than imported as a service since that route's
      // logic isn't (yet) factored out of the route handler itself.
      let credential = null;
      if (membership.membershipCredentialUuid !== null) {
        const cred = await credentialsRepo.findByUuid(db, membership.membershipCredentialUuid);
        if (cred && cred.status !== 'revoked') {
          let statusListUuid = cred.statusListUuid;
          let statusListIndex = cred.statusListIndex;

          if (statusListUuid === null) {
            let statusList = await statusListsRepo.findForCommunity(db, cred.issuerIdentityUuid, 'revocation');
            if (!statusList) {
              const issuer = await identitiesRepo.findByUuid(db, cred.issuerIdentityUuid);
              if (!issuer) {
                return reply.code(404).send({ error: { message: `issuer identity ${cred.issuerIdentityUuid} not found` } });
              }
              const newUuid = await statusListsRepo.create(db, {
                communityIdentityUuid: issuer.uuid,
                purpose: 'revocation',
              });
              statusList = await statusListsRepo.findByUuid(db, newUuid);
            }
            statusListUuid = statusList!.uuid;
            statusListIndex = await statusListsRepo.allocateNextIndex(db, statusListUuid);
            await credentialsRepo.setStatusListSlot(db, cred.uuid, statusListUuid, statusListIndex);
          }

          const statusListRow = await statusListsRepo.findByUuid(db, statusListUuid!);
          await statusListsRepo.flip(db, {
            statusListUuid: statusListRow!.uuid,
            slotIndex: statusListIndex!,
            value: 1,
            reason: 'membership revoked',
          });
          await credentialsRepo.updateStatus(db, cred.uuid, 'revoked');
        }
        credential = await credentialsRepo.findByUuid(db, membership.membershipCredentialUuid);
      }

      return reply.code(200).send({
        membership: await membershipsRepo.findByUuid(db, membershipUuid),
        credential,
      });
    },
  );

  // -------------------------------------------------------------------------
  // POST /memberships/:uuid/personhood-events — record challenge/assert/revoke
  // -------------------------------------------------------------------------

  app.post(
    '/memberships/:uuid/personhood-events',
    async (
      req: FastifyRequest<{ Params: { uuid: string }; Body: PersonhoodEventBody }>,
      reply: FastifyReply,
    ) => {
      const membershipUuid = req.params.uuid;
      const body = req.body;
      if (!membershipUuid || !body?.event) {
        return reply.code(400).send({ error: { message: 'membership uuid (param) and event (body) are required' } });
      }
      if (!['challenged', 'asserted', 'revoked'].includes(body.event)) {
        return reply
          .code(400)
          .send({ error: { message: `event must be one of: challenged, asserted, revoked` } });
      }

      const membership = await membershipsRepo.findByUuid(db, membershipUuid);
      if (!membership) {
        return reply.code(404).send({ error: { message: `membership ${membershipUuid} not found` } });
      }
      if (body.actorIdentityUuid !== undefined && !await identitiesRepo.findByUuid(db, body.actorIdentityUuid)) {
        return reply.code(404).send({ error: { message: `actor identity ${body.actorIdentityUuid} not found` } });
      }

      const eventUuid = await personhoodEventsRepo.create(db, {
        membershipUuid,
        event: body.event,
        reason: body.reason,
        actorIdentityUuid: body.actorIdentityUuid,
      });

      if (body.event === 'asserted') {
        await membershipsRepo.setPersonhoodAsserted(db, membershipUuid, true);
      } else if (body.event === 'revoked') {
        await membershipsRepo.setPersonhoodAsserted(db, membershipUuid, false);
      }

      return reply.code(201).send({
        event: await personhoodEventsRepo.findByUuid(db, eventUuid),
        membership: await membershipsRepo.findByUuid(db, membershipUuid),
      });
    },
  );

  // -------------------------------------------------------------------------
  // GET /memberships/:uuid/personhood-events — list personhood events for a membership
  // -------------------------------------------------------------------------
  app.get(
    '/memberships/:uuid/personhood-events',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const membershipUuid = req.params.uuid;
      if (!membershipUuid) {
        return reply.code(400).send({ error: { message: 'membership uuid (param) is required' } });
      }
      if (!await membershipsRepo.findByUuid(db, membershipUuid)) {
        return reply.code(404).send({ error: { message: `membership ${membershipUuid} not found` } });
      }
      return personhoodEventsRepo.findForMembership(db, membershipUuid);
    },
  );

  // -------------------------------------------------------------------------
  // GET /personhood-events/:uuid — fetch a single personhood event by uuid
  // -------------------------------------------------------------------------
  app.get(
    '/personhood-events/:uuid',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const eventUuid = req.params.uuid;
      if (!eventUuid) {
        return reply.code(400).send({ error: { message: 'personhood event uuid (param) is required' } });
      }
      const event = await personhoodEventsRepo.findByUuid(db, eventUuid);
      if (!event) {
        return reply.code(404).send({ error: { message: `personhood event ${eventUuid} not found` } });
      }
      return event;
    },
  );
}
