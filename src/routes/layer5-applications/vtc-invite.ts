// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Layer 5 — Trust Applications: POST /vtcs/:id/invite, POST /vtcs/:id/join
 *
 * Scenario 5 — "Invite & Join a VTC" (see mockup/vtc-invite-join.html).
 *
 * Discovery is deliberately OOBI-only (no public directory, no DHT
 * search): an admin generates a shareable invitation string for their
 * community, a prospective member decodes it and submits a join request.
 *
 * ## Cross-node consideration
 *
 * The invite payload is built from the *community's DID* (not its local
 * integer `identities.id`, which is meaningless outside this node's own
 * SQLite database) plus this server's own libp2p peerId/multiaddrs — the
 * same OOBI shape already used by ../layer2-spanning/relationships.ts for
 * peer-to-peer relationship establishment. That makes an invite minted by
 * the utility-server at least *decodable* by another node type (e.g. the
 * agent/TUI node in ../../../../src/agent), since decoding only needs the
 * shared `encodeOobi`/`decodeOobi` codec.
 *
 * What is NOT yet solved: once a remote node decodes an invite and wants
 * to submit a join request, there is no cross-node RFA-style message that
 * carries that request into *this* node's `memberships` table — join
 * requests today only land here via this same node's own
 * `POST /vtcs/:id/join` (i.e. the requester's identity must already exist
 * as a local `identities` row on this node, resolved by DID). Similarly,
 * an approval decision made here (a new `credentials` row + a
 * `memberships` status flip) is not yet pushed back out over TSP to the
 * requester's own node, so two nodes' local views of the same membership
 * can silently diverge. This is a known gap — not an oversight; closing it
 * needs a real TSP message type (something like
 * RFI/RFA's roles, but for membership join/approve) shared across every
 * node type, which is future work beyond this pass.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { Libp2p } from 'libp2p';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import { buildVtcInvite, parseVtcInvite } from '@p2p-trust-stack/core/relationship/vtc-invite.js';
import { getServerNodeInfo } from '../../services/server-node-info.js';
import { cesrEncode, CESR_CODES } from '@p2p-trust-stack/core/crypto/cesr.js';

import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import { DidManager } from '@p2p-trust-stack/core/services/did-manager.js';
import { driveCeremony } from '@p2p-trust-stack/core/services/trust-tasks/driver.js';
import { guardAuthorizer } from '@p2p-trust-stack/core/services/trust-tasks/authorizer.js';
import {
  CEREMONY_MEMBER_INVITATION,
  INVITATION_VIC_TYPE,
} from '@p2p-trust-stack/core/services/trust-tasks/type-uris.js';
import { GovernanceGuard } from '@p2p-trust-stack/core/services/governance-guard.js';
import { createPolicyEngine } from '@p2p-trust-stack/core/services/policy-engine-config.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import { gateMembershipAdmission } from '@p2p-trust-stack/core/services/membership-presentation.js';
import type { MembershipPresentation } from '@p2p-trust-stack/core/services/membership-presentation.js';


interface JoinBody {
  invite: string;
  memberIdentityUuid: string;
  role?: string;
  /**
   * Optional proof of possession of the member's key (audit F-026 / decision
   * F-001b) — the same gate the direct communities/:uuid/memberships join applies.
   */
  presentation?: MembershipPresentation;
}

interface InviteBody {
  /** Prospective member (subject of the VIC). Optional — omit for a bare OOBI. */
  subjectIdentityUuid?: string;
  subjectDid?: string;
  taskContext?: string;
}

/**
 * The community's DID is carried in the invite's `peerId` slot (packed alongside
 * the real transport peerId as `"<communityDid>|<peerId>"`), and the connection
 * target is the utility server. BOTH artifacts now come from the one shared
 * builder in `src/relationship/vtc-invite.ts`, so this route and the TSP
 * `vtc_invite` op can never drift apart again — that duplication is what left the
 * invite non-dialable (`<did>|<peerId>` is not a valid libp2p peerId), and
 * addressed to a DID that cannot answer a dial.
 */

export function registerVtcInviteRoutes(
  app: FastifyInstance,
  db: DataSource,
  node: Libp2p,
): void {
  // -------------------------------------------------------------------------
  // POST /vtcs/:id/invite — generate a shareable OOBI-style invitation
  // -------------------------------------------------------------------------
  app.post(
    '/vtcs/:uuid/invite',
    async (req: FastifyRequest<{ Params: { uuid: string }; Body?: InviteBody }>, reply: FastifyReply) => {
      const communityUuid = req.params.uuid;
      const body = req.body ?? ({} as InviteBody);

      const community = await identitiesRepo.findByUuid(db, communityUuid);
      if (!community) {
        return reply.code(404).send({ error: { message: `community identity ${communityUuid} not found` } });
      }
      if (community.role !== 'vtc' && community.role !== 'vtn') {
        return reply
          .code(409)
          .send({ error: { message: `identity ${communityUuid} is not a community (role=${community.role})` } });
      }

      // Resolve the community's Ed25519 signing key + real DID (Model A custody).
      const didManager = new DidManager(db);
      const signingKey = await didManager.resolveCommunitySigningKey(community.uuid);
      const communityDid = community.did ?? signingKey?.did ?? community.uuid;

      // The OOBI's `vid` is the community's real signing VID. Fall back to the
      // zero VID only for legacy rows without a persisted key — but then no
      // signed VIC can be minted.
      const vid = signingKey?.vid ?? cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, new Uint8Array(32));

      const multiaddrs = node.getMultiaddrs().map((a) => a.toString());
      const peerId = node.peerId.toString();
      // ONE shared builder (src/relationship/vtc-invite.ts): returns the legacy
      // packed `invite` token (byte-for-byte compatible with the join route below
      // and any already-issued invite) plus `connectionOobi`, a valid dialable OOBI
      // addressed to THIS server rather than to the community.
      const inviteArtifact = buildVtcInvite({
        communityDid,
        serverDid: getServerNodeInfo()?.did ?? null,
        vid,
        peerId,
        multiaddrs,
      });
      const invite = inviteArtifact.invite;

      // Mint a signed VIC (InvitationCredential) when a prospective member is
      // specified — this is the DTG-conformant invitation, signed by the
      // community's C-DID key and stored as a `vic` credential row.
      let vic: string | null = null;
      let credentialUuid: string | null = null;
      const subjectRef = body.subjectIdentityUuid ?? body.subjectDid;
      if (subjectRef && signingKey) {
        const subject = body.subjectIdentityUuid
          ? await identitiesRepo.findByUuid(db, body.subjectIdentityUuid)
          : await identitiesRepo.findByRealDid(db, body.subjectDid!);
        if (!subject) {
          return reply.code(404).send({ error: { message: `subject identity ${subjectRef} not found` } });
        }
        const taskContext = body.taskContext ?? `vtc-invite:${communityUuid}:${Date.now()}`;
        // Issue the VIC by DRIVING the cataloged `member-invitation` ceremony —
        // exactly as the TSP `vtc_invite` op does: a `policy` gate on the community's
        // `issue_credential` rule (the baseline `vic-issue` rule requires
        // `actor_is_admin`), then the effect step that mints the credential. The gate,
        // the mint and every trust-task record commit together, so an invitation is a
        // LOGGED ceremony rather than an untracked side effect.
        const threadId = generateUuid();
        const driven = await db.transaction((tx) =>
          driveCeremony(tx, CEREMONY_MEMBER_INVITATION, threadId, {
            authorizer: guardAuthorizer(new GovernanceGuard(tx, createPolicyEngine())),
            context: {
              db: tx,
              communityUuid: community.uuid,
              communityDid,
              subjectIdentityUuid: subject.uuid,
              actorDid: communityDid,
              params: { kind: 'InvitationCredential', subjectDid: subject.did ?? subject.uuid },
              oobi: { vid, peerId, multiaddrs, did: communityDid },
              taskContext,
              verificationMethod: signingKey.verificationMethod,
              signerSecretKey: signingKey.signerSecretKey,
            },
          }),
        );
        if (!driven.completed) {
          return reply.code(403).send({
            error: { message: `invitation refused by policy at '${driven.haltedAt}'`, threadId },
          });
        }
        const issued = driven.outputs[INVITATION_VIC_TYPE] as
          { credentialUuid?: string; vicJson?: string } | undefined;
        if (!issued?.credentialUuid || !issued.vicJson) {
          return reply.code(500).send({ error: { message: 'invitation produced no credential', threadId } });
        }
        vic = issued.vicJson;
        credentialUuid = issued.credentialUuid;
      }

      return reply.code(200).send({
        invite,
        connectionOobi: inviteArtifact.connectionOobi,
        vic,
        credentialUuid,
        communityUuid,
        communityDid,
        communityName: community.name,
        signed: !!vic,
      });
    },
  );

  // -------------------------------------------------------------------------
  // POST /vtcs/:id/join — decode an invite (or just target this VTC
  // directly, since this is a single-node scaffolding pass) and create a
  // pending membership for a local identity
  // -------------------------------------------------------------------------
  app.post(
    '/vtcs/:uuid/join',
    async (req: FastifyRequest<{ Params: { uuid: string }; Body: JoinBody }>, reply: FastifyReply) => {
      const communityUuid = req.params.uuid;
      const body = req.body ?? ({} as JoinBody);
      if (!communityUuid || !body.memberIdentityUuid) {
        return reply
          .code(400)
          .send({ error: { message: 'uuid (param) and memberIdentityUuid (body) are required' } });
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
      if (!await identitiesRepo.findByUuid(db, body.memberIdentityUuid)) {
        return reply.code(404).send({ error: { message: `member identity ${body.memberIdentityUuid} not found` } });
      }

      // If an invite string was supplied, decode + sanity-check it names
      // this same community's DID — catches the "pasted the wrong VTC's
      // invite" mistake early with a clear error instead of silently
      // joining the wrong community.
      if (body.invite) {
        let parsed;
        try {
          parsed = parseVtcInvite(body.invite);
        } catch (err) {
          return reply.code(400).send({ error: { message: `failed to decode invite: ${(err as Error).message}` } });
        }
        // Only the legacy token carries the community DID (in its peer field).
        // The modern connection OOBI is addressed to the server and carries no
        // community reference — the community is fixed by the `:uuid` path, and
        // the signed VIC claim names it — so there is nothing to cross-check.
        if (parsed.communityDid && parsed.communityDid !== community.did) {
          return reply.code(409).send({
            error: {
              message: `invite is for community DID ${parsed.communityDid}, but url targets community ${communityUuid} (${community.did})`,
            },
          });
        }
      }

      const member = await identitiesRepo.findByUuid(db, body.memberIdentityUuid);
      if (!member) {
        return reply.code(404).send({ error: { message: `member identity ${body.memberIdentityUuid} not found` } });
      }

      const existing = await membershipsRepo.findByPair(db, member.uuid, community.uuid);
      if (existing) {
        return reply.code(409).send({
          error: {
            message: `identity ${body.memberIdentityUuid} already has a membership (status=${existing.status}) in community ${communityUuid}`,
          },
        });
      }

      // --- Admission presentation (audit F-026 / decision F-001b) ---
      // The SAME gate as POST /communities/:uuid/memberships, so the invite path
      // cannot admit what the direct path refuses.
      const gate = await gateMembershipAdmission(db, {
        communityUuid: community.uuid,
        memberIdentityUuid: member.uuid,
        role: body.role,
        presentation: body.presentation,
      });
      if (gate.refuse) {
        return reply.code(403).send({
          error: { message: `admission refused: ${gate.outcome!.reason}` },
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
        admission: gate.outcome
          ? { policy: gate.policy, verdict: gate.outcome.verdict, reason: gate.outcome.reason }
          : { policy: gate.policy },
      });
    },
  );

  // ── Decode an invite (agent-side proxy) ────────────────────────────────
  app.post('/vtcs/decode-invite', async (
    req: FastifyRequest<{ Body: { invite: string } }>, reply: FastifyReply,
  ) => {
    if (!req.body?.invite) return reply.code(400).send({ error: { message: 'invite is required' } });
    try {
      const parsed = parseVtcInvite(req.body.invite);
      return reply.code(200).send({
        // null when the caller pasted a modern connection-only OOBI (no community
        // reference on the wire — the signed VIC claim names the community).
        communityDid: parsed.communityDid,
        serverPeerId: parsed.peerId,
        // The DID the invite is addressed to. For a modern invite this is the
        // SERVER (the node the peerId reaches); for the legacy token it is the
        // community DID.
        serverDid: parsed.did,
        communityName: null, // caller resolves name from DID
      });
    } catch (err) {
      return reply.code(400).send({ error: { message: (err as Error).message } });
    }
  });

  // ── Join by invite (agent-side proxy) ──────────────────────────────────
  app.post('/vtcs/join-by-invite', async (
    req: FastifyRequest<{ Body: { invite: string; role?: string; memberDid: string } }>,
    reply: FastifyReply,
  ) => {
    const body = req.body ?? ({} as any);
    if (!body.invite || !body.memberDid) {
      return reply.code(400).send({ error: { message: 'invite and memberDid are required' } });
    }
    try {
      // Decode the invite to get the community DID. Only the legacy token carries
      // it (in its peer field); a modern connection OOBI cannot name a community,
      // so this route requires the legacy form (or use POST /vtcs/:uuid/join with
      // the community uuid).
      const parsed = parseVtcInvite(body.invite);
      if (!parsed.communityDid) {
        return reply.code(400).send({
          error: {
            message:
              'invite does not name a community (this is a connection-only OOBI) — ' +
              'use POST /vtcs/:uuid/join with the community uuid instead',
          },
        });
      }

      // Find community by DID
      const community = await identitiesRepo.findByRealDid(db, parsed.communityDid);
      if (!community) {
        return reply.code(404).send({ error: { message: `community ${parsed.communityDid} not found` } });
      }
      if (community.role !== 'vtc' && community.role !== 'vtn') {
        return reply.code(409).send({ error: { message: `identity is not a community` } });
      }

      // Find member by DID (identity must already exist on this server)
      const member = await identitiesRepo.findByRealDid(db, body.memberDid);
      if (!member) {
        return reply.code(404).send({ error: { message: `identity ${body.memberDid} not found — register the VTA on this server first` } });
      }

      // Check not already a member
      const existing = await membershipsRepo.findByPair(db, member.uuid, community.uuid);
      if (existing) {
        return reply.code(409).send({
          error: { message: `already a member (status=${existing.status}). Re-invitation of revoked members requires governance rule changes.` },
        });
      }

      // Create pending membership
      const membershipUuid = await membershipsRepo.create(db, {
        memberIdentityUuid: member.uuid,
        communityIdentityUuid: community.uuid,
        role: body.role || 'member',
        status: 'pending',
      });

      return reply.code(201).send(await membershipsRepo.findByUuid(db, membershipUuid));
    } catch (err) {
      if ((err as any)?.message?.startsWith('invite:')) {
        return reply.code(400).send({ error: { message: (err as Error).message } });
      }
      return reply.code(400).send({ error: { message: (err as Error).message } });
    }
  });
}

