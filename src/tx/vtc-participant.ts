/**
 * VTC Joining & Discovery Participant.
 *
 * Handles read-only + join operations against an EXISTING community on the
 * utility server, via the transaction coordinator:
 *   - name_check      — pre-flight name availability
 *   - vtc_join        — join an existing community by DID
 *   - vtc_invite      — mint a signed invitation (VIC) for onboarding
 *   - vtc_accept      — accept a VIC, mint + deliver the membership VMC
 *   - namespace_info  — the server's configured namespace/VTN (for the picker)
 *
 * VTC/VTN *creation* is NOT here. It is the `ceremony_begin`/`ceremony_approve`
 * ceremony, handled by CeremonyCoordinatorParticipant, which drives the cataloged
 * `vtc-establish` ceremony. The old `vtc_create` operation — which called
 * `createVtc` directly with no trust-task record — was removed (nothing sent it).
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type {
  Operation,
  Outcome,
  Participant,
  Vote,
} from '@p2p-trust-stack/core/tx/types.js';
import { checkCommunityNameAvailable, joinCommunityByDid } from '../services/vtc.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import { DidManager } from '@p2p-trust-stack/core/services/did-manager.js';
import { buildVtcInvite } from '@p2p-trust-stack/core/relationship/vtc-invite.js';
import { cesrEncode, CESR_CODES } from '@p2p-trust-stack/core/crypto/cesr.js';
import { getServerNodeInfo } from '../services/server-node-info.js';
import { tryEnqueueFanout } from '../services/exchange-runtime.js';
import { getNamespaceConfig } from '../services/namespace-service.js';
import { driveCeremony } from '@p2p-trust-stack/core/services/trust-tasks/driver.js';
import { guardAuthorizer } from '@p2p-trust-stack/core/services/trust-tasks/authorizer.js';
import {
  CEREMONY_MEMBER_ONBOARDING,
  CEREMONY_MEMBER_INVITATION,
  ONBOARDING_VMC_TYPE,
  INVITATION_VIC_TYPE,
} from '@p2p-trust-stack/core/services/trust-tasks/type-uris.js';
import { GovernanceGuard } from '@p2p-trust-stack/core/services/governance-guard.js';
import { createPolicyEngine } from '@p2p-trust-stack/core/services/policy-engine-config.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';

/**
 * A Participant that handles VTC join/invite/preflight operations (see the
 * file docstring). VTC/VTN creation lives in `ceremony-participant.ts`.
 *
 * pid: 'server:{serverId}' — identifies this as a utility server participant.
 * The serverId should be configured per deployment (default: 'us-1').
 */
export class VtcCreationParticipant implements Participant {
  readonly pid: string;
  private readonly appDb: DataSource;
  private readonly txDb: DataSource;

  constructor(pid: string, appDb: DataSource, txDb: DataSource) {
    this.pid = pid;
    this.appDb = appDb;
    this.txDb = txDb;
  }

  handlesOperation(op: Operation): boolean {
    // `namespace_info` is claimed here because the coordinator's tx_query dispatch
    // reuses this same predicate to find the participant that answers a query
    // (src/tx/coordinator.ts, case 'tx_query' → findParticipantForOperations) — it is
    // not a coordinator operation and is deliberately absent from bootstrap's knownOps.
    return op.op === 'name_check' || op.op === 'namespace_info' ||
      op.op === 'vtc_join' || op.op === 'vtc_invite' || op.op === 'vtc_accept';
  }

  /**
   * Read-only query support — used for pre-flight checks without creating a VTC.
   * Currently supports: 'name_check' — check if a community name is available.
   */
  async query(op: string, params?: Record<string, unknown>): Promise<unknown> {
    if (op === 'name_check') {
      const name = params?.name as string | undefined;
      if (!name) return { available: false, message: 'name is required' };
      return await checkCommunityNameAvailable(this.appDb, name);
    }

    if (op === 'vtc_join') {
      const communityDid = params?.communityDid as string | undefined;
      const memberDid = params?.memberDid as string | undefined;
      const role = params?.role as string | undefined;
      if (!communityDid || !memberDid) {
        throw new Error('vtc_join requires communityDid and memberDid');
      }
      const result = await joinCommunityByDid(this.appDb, { communityDid, memberDid, role });
      return {
        membership: result.membership,
        communityUuid: result.community.uuid,
        communityDid,
      };
    }

    if (op === 'vtc_accept') {
      // Accepting a signed VIC closes the loop: the VIC IS the community's
      // authorization, so acceptance grants membership directly (mint the VMC
      // and activate the membership) rather than leaving it pending.
      const communityDid = params?.communityDid as string | undefined;
      const memberDid = params?.memberDid as string | undefined;
      if (!communityDid || !memberDid) throw new Error('vtc_accept requires communityDid and memberDid');

      const community = await identitiesRepo.findByRealDid(this.appDb, communityDid);
      if (!community || (community.role !== 'vtc' && community.role !== 'vtn')) {
        throw new Error('community not found');
      }
      const member = await identitiesRepo.findByRealDid(this.appDb, memberDid);
      if (!member) throw new Error(`member ${memberDid} not found on this server`);

      const existing = await membershipsRepo.findByPair(this.appDb, member.uuid, community.uuid);
      if (existing && existing.status === 'active') {
        return { membership: existing, alreadyActive: true };
      }

      const membershipUuid = existing?.uuid
        ?? await membershipsRepo.create(this.appDb, {
          memberIdentityUuid: member.uuid,
          communityIdentityUuid: community.uuid,
          role: 'member',
          status: 'pending',
        });

      // Issue the backing VMC by DRIVING the cataloged `member-onboarding`
      // trust-task ceremony — a `policy` gate on the community's `issue_credential`
      // rule, then the `effect` step that mints the credential — exactly as the REST
      // `POST /memberships/:uuid/approve` route does. The gate, the mint and every
      // trust-task record commit together, so onboarding is a LOGGED ceremony rather
      // than an untracked side effect, and a denied gate rolls the mint back with it.
      //
      // Order matters: the membership is still `pending` while it is minted, because
      // the baseline `vmc-issue` rule is `actor_is_admin AND NOT
      // subject_is_active_member`. The community acts on its own behalf, so `actorDid`
      // is the community's own DID (the guard always authorizes that).
      const issuerDid = community.did ?? communityDid;
      const subjectDid = member.did ?? member.uuid;
      const threadId = generateUuid();
      const driven = await this.appDb.transaction((tx) =>
        driveCeremony(tx, CEREMONY_MEMBER_ONBOARDING, threadId, {
          authorizer: guardAuthorizer(new GovernanceGuard(tx, createPolicyEngine())),
          context: {
            db: tx,
            issuerIdentityUuid: community.uuid,
            subjectIdentityUuid: member.uuid,
            communityDid: issuerDid,
            actorDid: issuerDid,
            params: { kind: 'MembershipCredential', subjectDid },
            claim: {
              memberOf: communityDid,
              membershipRole: 'member',
              membershipUuid,
              membershipSince: new Date().toISOString(),
              communityName: community.name,
            },
            membershipRole: 'member',
          },
        }),
      );
      // Fail CLOSED: a membership must never be activated without its credential, so
      // a denied gate or a failed mint refuses the acceptance rather than
      // half-admitting the member.
      if (!driven.completed) {
        throw new Error(`'member-onboarding' ceremony halted at ${driven.haltedAt} (thread ${threadId})`);
      }
      const credentialUuid = (driven.outputs[ONBOARDING_VMC_TYPE] as { credentialUuid?: string } | undefined)
        ?.credentialUuid;
      if (!credentialUuid) {
        throw new Error(`member onboarding produced no credential (thread ${threadId})`);
      }
      await membershipsRepo.approve(this.appDb, membershipUuid, credentialUuid);

      try { await tryEnqueueFanout('credential', { credentialUuid }); }
      catch (err) { console.warn(`[vtc-participant] VMC delivery enqueue failed for ${credentialUuid}: ${(err as Error)?.message ?? err}`); }

      // Deliver the updated community package (incl. the new membership) to the
      // new member so their local graph/communities reflect the membership.
      try { await tryEnqueueFanout('vtc-membership', { communityUuid: community.uuid }); }
      catch (err) { console.warn(`[vtc-participant] vtc-membership delivery enqueue failed for ${community.uuid}: ${(err as Error)?.message ?? err}`); }

      return {
        membership: await membershipsRepo.findByUuid(this.appDb, membershipUuid),
        credentialUuid,
        active: true,
        // The `member-onboarding` ceremony thread, so a caller can point its operator
        // at the task log for exactly this onboarding.
        threadId,
      };
    }

    if (op === 'vtc_invite') {
      const communityUuid = params?.communityUuid as string | undefined;
      const communityDidParam = params?.communityDid as string | undefined;
      const subjectDid = params?.subjectDid as string | undefined;
      const subjectName = params?.subjectName as string | undefined;
      const subjectIdentityUuid = params?.subjectIdentityUuid as string | undefined;
      const taskContext = (params?.taskContext as string | undefined) ?? `vtc-invite:${Date.now()}`;

      const community = communityUuid
        ? await identitiesRepo.findByUuid(this.appDb, communityUuid)
        : communityDidParam
          ? await identitiesRepo.findByRealDid(this.appDb, communityDidParam)
          : null;
      if (!community) throw new Error('community not found');
      if (community.role !== 'vtc' && community.role !== 'vtn') {
        throw new Error(`identity is not a community (role=${community.role})`);
      }

      // Who is inviting, if known. This is used ONLY as the ceremony's ACTOR: whether
      // they may invite is decided by the `member-invitation` ceremony's policy gate
      // (the baseline `vic-issue` rule requires `actor_is_admin`), not by a role check
      // here — so "only an admin may invite" is a community rule it can change, and
      // there is exactly one place that decides it.
      const inviterDid = params?.inviterDid as string | undefined;
      const inviterUuid = params?.inviterUuid as string | undefined;
      const inviter = inviterUuid
        ? await identitiesRepo.findByUuid(this.appDb, inviterUuid)
        : inviterDid
          ? await identitiesRepo.findByRealDid(this.appDb, inviterDid)
          : null;

      // Resolve an agent name (vta:<namespace>:<name>) to a DID via name_registry.
      let resolvedSubjectDid = subjectDid;
      if (!resolvedSubjectDid && !subjectIdentityUuid && subjectName) {
        const { parseNameUri } = await import('@p2p-trust-stack/core/did/name-uri.js');
        let parsed;
        try {
          parsed = parseNameUri(subjectName);
        } catch {
          throw new Error(`Invalid agent name "${subjectName}" — expected vta:<namespace>:<name>.`);
        }
        const nameRow = await this.appDb.get<{ did: string }>(
          'SELECT did FROM name_registry WHERE namespace = ? AND name = ? AND revoked_at IS NULL ORDER BY claimed_at DESC LIMIT 1',
          parsed.namespace, parsed.name,
        );
        if (!nameRow) {
          throw new Error(`Agent name "${subjectName}" is not registered. The person must register their VTA name first.`);
        }
        resolvedSubjectDid = nameRow.did;
      }

      const didManager = new DidManager(this.appDb);
      const signingKey = await didManager.resolveCommunitySigningKey(community.uuid);
      const communityDid = community.did ?? signingKey?.did ?? community.uuid;
      const vid = signingKey?.vid ?? cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, new Uint8Array(32));

      const nodeInfo = getServerNodeInfo();
      const peerId = nodeInfo?.peerId ?? '';
      const multiaddrs = nodeInfo?.multiaddrs ?? [];
      // ONE builder for both invite producers (src/relationship/vtc-invite.ts):
      // the legacy packed `invite` token, plus a dialable `connectionOobi`
      // addressed to THIS server — the node the peerId actually reaches, which the
      // community DID cannot answer (an invite RFI addressed to the community is
      // now refused by the rev-3 addressee check).
      const inviteArtifact = buildVtcInvite({
        communityDid,
        serverDid: nodeInfo?.did ?? null,
        vid,
        peerId,
        multiaddrs,
      });
      const invite = inviteArtifact.invite;

      let vic: string | null = null;
      let credentialUuid: string | null = null;
      /** The `member-invitation` ceremony thread, when one ran (for the reply). */
      let invitationThreadId: string | null = null;
      if (resolvedSubjectDid || subjectIdentityUuid) {
        if (!signingKey) {
          throw new Error('This community has no signing key, so a signed invitation cannot be issued.');
        }
        const subject = subjectIdentityUuid
          ? await identitiesRepo.findByUuid(this.appDb, subjectIdentityUuid)
          : await identitiesRepo.findByRealDid(this.appDb, resolvedSubjectDid!);
        if (!subject) {
          throw new Error(
            `VTA "${subjectIdentityUuid ?? resolvedSubjectDid}" is not registered on this server. ` +
            `They must connect (push their identity) or register their name first.`,
          );
        }
        // Issue the VIC by DRIVING the cataloged `member-invitation` ceremony: a
        // `policy` gate on the community's `issue_credential` rule (the baseline
        // `vic-issue` rule requires `actor_is_admin`, which is what turns "only an
        // admin may invite" into a rule a community can change), then the effect step
        // that MINTS the signed credential. The gate, the mint and every trust-task
        // record commit together, so an invitation is a LOGGED ceremony — visible in
        // the ceremony task log beside every other ceremony — not a side effect.
        //
        // FAIL CLOSED: if the gate refuses, the invitation is refused. Quietly
        // degrading to an OOBI-only invite would mean issuing an authorization nobody
        // was entitled to grant.
        const threadId = generateUuid();
        const inviterActorDid = inviter?.did ?? inviterDid ?? communityDid;
        const driven = await this.appDb.transaction((tx) =>
          driveCeremony(tx, CEREMONY_MEMBER_INVITATION, threadId, {
            authorizer: guardAuthorizer(new GovernanceGuard(tx, createPolicyEngine())),
            context: {
              db: tx,
              communityUuid: community.uuid,
              communityDid,
              subjectIdentityUuid: subject.uuid,
              actorDid: inviterActorDid,
              params: { kind: 'InvitationCredential', subjectDid: subject.did ?? subject.uuid },
              oobi: { vid, peerId, multiaddrs, did: communityDid },
              taskContext,
              verificationMethod: signingKey.verificationMethod,
              signerSecretKey: signingKey.signerSecretKey,
            },
          }),
        );
        if (!driven.completed) {
          throw new Error(
            `Invitation refused by policy at '${driven.haltedAt}' (thread ${threadId}) — ` +
            `only an admin may invite a member.`,
          );
        }
        const issued = driven.outputs[INVITATION_VIC_TYPE] as
          { credentialUuid?: string; vicJson?: string } | undefined;
        if (!issued?.credentialUuid || !issued.vicJson) {
          throw new Error(`Invitation produced no credential (thread ${threadId}).`);
        }
        vic = issued.vicJson;
        credentialUuid = issued.credentialUuid;
        invitationThreadId = threadId;
        // Deliver the signed VIC to the invited member's agent via the durable
        // `credential` queue (pending_agent_deliveries) — an offline member
        // receives it on reconnect. Idempotent per credential (cred_<uuid>).
        try {
          await tryEnqueueFanout('credential', { credentialUuid });
        } catch (err) {
          console.warn(
            `[vtc-participant] VIC delivery enqueue failed for ${credentialUuid}: ${(err as Error)?.message ?? err}`,
          );
        }
      }

      return {
        invite,
        connectionOobi: inviteArtifact.connectionOobi,
        vic,
        credentialUuid,
        communityUuid: community.uuid,
        communityDid,
        communityName: community.name,
        signed: !!vic,
        // The `member-invitation` ceremony thread, when a signed VIC was issued, so a
        // caller can point its operator at the task log for this invitation.
        threadId: invitationThreadId,
      };
    }

    // Parent-VTN discovery, for agent UIs that create a VTC under this node's namespace.
    //
    // The namespace VTN is a SERVER-side identity, and an agent only receives records
    // for communities it is a MEMBER of — so an agent that joined a VTC but not the
    // namespace VTN has no local VTN record, and its create-community picker offers only
    // "None — standalone VTC". This returns exactly what that picker needs: the
    // namespace string the operator configured, the parent's identity uuid (the value
    // the founding ceremony's parentCommunityUuid expects), and the VTN's own name/DID.
    if (op === 'namespace_info') {
      const cfg = await getNamespaceConfig(this.appDb);
      if (!cfg) {
        return { configured: false, namespace: null, vtnUuid: null, vtnName: null, vtnDid: null };
      }
      const vtn = await identitiesRepo.findByUuid(this.appDb, cfg.vtnIdentityUuid);
      return {
        configured: true,
        namespace: cfg.namespace,
        vtnUuid: cfg.vtnIdentityUuid,
        vtnName: vtn?.name ?? null,
        vtnDid: vtn?.did ?? null,
      };
    }

    throw new Error(`VtcCreationParticipant does not support query operation: ${op}`);
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    for (const op of operations) {
      if (op.op === 'name_check') {
        // Read-only name check: vote 'yes' if available, 'no' if taken.
        const params = op.params as { name?: string; kind?: string } | undefined;
        if (!params?.name) return 'no';
        const result = await checkCommunityNameAvailable(this.appDb, params.name.trim());
        if (!result.available) {
          console.log(`[vtc-participant] name_check: "${params.name}" is taken`);
          return 'no';
        }
        console.log(`[vtc-participant] name_check: "${params.name}" is available`);
        continue; // proceed to record prepared state
      }

      if (op.op === 'namespace_info') {
        // Query-only (see `query()`): it is claimed in handlesOperation so the
        // coordinator routes the QUERY here. Sent as an OPERATION it must be refused
        // rather than silently accepted as an empty transaction.
        return 'no';
      }

      // VTC/VTN creation is NOT handled here — it is the `ceremony_begin` /
      // `ceremony_approve` ceremony (CeremonyCoordinatorParticipant). Any other
      // operation is either query-only or unsupported; skip it.
      continue;
    }

    await this.txDb.run(
      `INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome)
       VALUES (?, ?, 'prepared')`, txId, this.pid,
    );
    return 'yes';
  }

  async commit(txId: string): Promise<void> {
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'committed'
       WHERE tx_id = ? AND pid = ?`, txId, this.pid,
    );
  }

  async abort(txId: string): Promise<void> {
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'aborted'
       WHERE tx_id = ? AND pid = ?`, txId, this.pid,
    );
  }

  async compensate(txId: string): Promise<void> {
    await this.abort(txId);
  }

  async inquiry(txId: string): Promise<Outcome> {
    const row = await this.txDb.get<{ outcome: string }>(
      'SELECT outcome FROM tx_participant_state WHERE tx_id = ? AND pid = ?',
      txId, this.pid,
    );
    return (row?.outcome as Outcome) ?? 'unknown';
  }
}