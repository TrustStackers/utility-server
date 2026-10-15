/**
 * CeremonyCoordinatorParticipant — utility-server participant that exposes
 * VTC/VTN founding ceremony lifecycle over the TSP transaction coordinator.
 *
 * Handles operations:
 *   - 'ceremony_begin'   — create a ceremony_proposals row (status=pending)
 *   - 'ceremony_approve' — record self-approval; if threshold met, crystallize
 *   - 'ceremony_query'   — read-only: return ceremony status + error reason
 *   - 'ceremony_reset'   — mark a failed/expired ceremony as 'aborted' for retry
 *   - 'ceremony_reconcile' — compare ceremony status vs actual DB, fix mismatches
 *
 * Uses UUIDs throughout (proposerUuid, adminUuids) — the utility server's
 * identities table maps these to integer IDs via the deterministic uuid column.
 *
 * pid: 'server:{serverId}' — identifies this as a utility server participant.
 */

import { randomUUID } from 'node:crypto';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type {
  Operation,
  Outcome,
  Participant,
  Vote,
} from '@p2p-trust-stack/core/tx/types.js';
import { CeremonyStore } from '@p2p-trust-stack/core/tx/ceremony-store.js';
import { createVtc, checkCommunityNameAvailable } from '../services/vtc.js';
import type { VtcKind, CreateVtcResult } from '../services/vtc.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import { tryEnqueueFanout } from '../services/exchange-runtime.js';
import { enqueueFoundingAdminVmcFanout } from '../services/vtc-push-data.js';
import type { MembershipRow } from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import {
  VTC_ESTABLISH_TYPE, MEMBERSHIP_VMC_TYPE, ONBOARDING_VMC_TYPE, INVITATION_VIC_TYPE,
  CEREMONY_PROPOSE_TYPE, CEREMONY_CO_SIGN_TYPE,
} from '@p2p-trust-stack/core/services/trust-tasks/type-uris.js';
import { driveCeremony } from '@p2p-trust-stack/core/services/trust-tasks/driver.js';
import { registerExecutor } from '@p2p-trust-stack/core/services/trust-tasks/catalog.js';
import * as trustTasksRepo from '@p2p-trust-stack/core/db/repositories/trust-tasks-repo.js';
import {
  listCeremonyThreads,
  getCeremonyThread,
} from '@p2p-trust-stack/core/services/trust-tasks/ceremony-log.js';
// Task documents get time-ordered (UUIDv7) ids: a ceremony thread is read back with
// `ORDER BY created_at, uuid` and `created_at` is SECOND-resolution, so the id is what
// keeps several steps recorded in the same second in record order.
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import { CredentialFactoryImpl } from '@p2p-trust-stack/core/services/credential-factory/credential-factory-impl.js';
import { GovernanceGuard } from '@p2p-trust-stack/core/services/governance-guard.js';
import { createPolicyEngine } from '@p2p-trust-stack/core/services/policy-engine-config.js';
import { DidManager } from '@p2p-trust-stack/core/services/did-manager.js';

// ── Registry: the founding-ceremony effect executors ─────────────────────────
// Ceremony DEFINITIONS live in the DB (0019); an effect step's EXECUTOR lives in
// code (src/services/trust-tasks/catalog.ts). The utility server registers ITS
// executors at import time — idempotent (Map.set), so re-import is a no-op.
//
// The establishment gate is createVtc's own validation (unique name, human-VTA +
// active-endpoint + mutual-VRC + threshold checks) — it throws and rolls back the
// surrounding transaction; no separate `policy` step is needed for the founding flow.
registerExecutor(VTC_ESTABLISH_TYPE, async (context) => {
  const db = context.db as DataSource;
  const result = await createVtc(db, {
    name: context.name as string,
    kind: context.kind as VtcKind,
    adminIdentityUuids: context.adminIdentityUuids as string[],
    threshold: context.threshold as number | undefined,
    parentCommunityUuid: context.parentCommunityUuid as string | undefined,
  });
  // The response's recipient is the community this step just established.
  return { ...result, recipientDid: result.identity.did ?? undefined };
});

registerExecutor(MEMBERSHIP_VMC_TYPE, async (context) => {
  const admin = context.item as MembershipRow;
  const db = context.db as DataSource;
  // The founding VMC is minted *inside* createVtc (memberships.membership_credential_uuid);
  // this step documents one already-minted credential per founding admin, fed by the
  // establish step's output (`repeat: "$…vtc:establish:0.1#foundingAdmins"`). Its
  // recipient is the member who holds the credential.
  const member = await identitiesRepo.findByUuid(db, admin.memberIdentityUuid);
  return {
    membershipUuid: admin.uuid,
    memberIdentityUuid: admin.memberIdentityUuid,
    membershipCredentialUuid: admin.membershipCredentialUuid,
    role: admin.role,
    recipientDid: member?.did ?? undefined,
  };
});

// ── Registry: the member-onboarding ceremony's effect executor ───────────────
// `member-onboarding` (migration 0020) is the policy-GATED ceremony: its first step
// is a `policy` gate on the community's `issue_credential` rule, then this effect
// MINTS the single member's backing VMC. The gate, the mint, and every trust-task
// record commit together (the caller drives inside `db.transaction`), so a denied
// gate rolls the mint back with it.
registerExecutor(ONBOARDING_VMC_TYPE, async (context) => {
  const db = context.db as DataSource;
  const issuer = await identitiesRepo.findByUuid(db, context.issuerIdentityUuid as string);
  const subject = await identitiesRepo.findByUuid(db, context.subjectIdentityUuid as string);
  if (!issuer || !subject) {
    throw new Error('onboarding-vmc: issuer or subject identity not found');
  }

  // Model A custody: sign with the community's Ed25519 key when it was persisted
  // encrypted at creation; otherwise fall back to a record-only credential.
  const signingKey = await new DidManager(db).resolveCommunitySigningKey(issuer.uuid);
  const factory = new CredentialFactoryImpl(db, new GovernanceGuard(db, createPolicyEngine()));
  const issuerDid = issuer.did ?? issuer.uuid;
  const mintResult = await factory.mint({
    kind: 'MembershipCredential',
    scenario: 'community-join',
    issuerDid,
    subjectDid: subject.did ?? subject.uuid,
    governanceDid: issuerDid,
    claim: context.claim !== undefined
      ? (typeof context.claim === 'string' ? JSON.parse(context.claim) : context.claim)
      : { membershipRole: context.membershipRole },
    verificationMethod: signingKey?.verificationMethod ?? `${issuerDid}#key-1`,
    signerSecretKey: signingKey?.signerSecretKey,
    validUntil: context.validUntil !== undefined
      ? new Date((context.validUntil as number) * 1000)
      : undefined,
    extension: {
      issuerIdentityUuid: issuer.uuid,
      subjectIdentityUuid: subject.uuid,
    },
  });

  // The response's recipient is the member who will hold the credential.
  return { credentialUuid: mintResult.credentialUuid, recipientDid: subject.did ?? undefined };
});

// ── Registry: the member-INVITATION ceremony's effect executor ────────────────
// `member-invitation` (migration 0023) is the INVITATION half of onboarding: a `policy`
// gate on the community's `issue_credential` rule for an InvitationCredential (the
// baseline `vic-issue` rule requires `actor_is_admin` — so "only an admin may invite"
// became a community RULE rather than a hard-coded role check), then this effect MINTS
// the signed VIC that carries the community's authorization plus the OOBI transport
// artifact. The gate, the mint and every trust-task record commit together.
registerExecutor(INVITATION_VIC_TYPE, async (context) => {
  const db = context.db as DataSource;
  const community = await identitiesRepo.findByUuid(db, context.communityUuid as string);
  const subject = await identitiesRepo.findByUuid(db, context.subjectIdentityUuid as string);
  if (!community || !subject) {
    throw new Error('invitation-vic: community or subject identity not found');
  }

  const communityDid = context.communityDid as string;
  const factory = new CredentialFactoryImpl(db, new GovernanceGuard(db, createPolicyEngine()));
  const minted = await factory.mint({
    kind: 'InvitationCredential',
    scenario: 'invite-new-member',
    issuerDid: communityDid,
    subjectDid: subject.did ?? subject.uuid,
    governanceDid: communityDid,
    claim: { oobi: context.oobi, communityName: community.name },
    taskContext: context.taskContext as string,
    verificationMethod: context.verificationMethod as string,
    signerSecretKey: context.signerSecretKey as Uint8Array,
    extension: { issuerIdentityUuid: community.uuid, subjectIdentityUuid: subject.uuid },
  });

  // The response's recipient is the invited member — they hold the credential.
  return {
    credentialUuid: minted.credentialUuid,
    vicJson: minted.serialized,
    recipientDid: subject.did ?? undefined,
  };
});

interface CeremonyBeginParams {
  ceremonyId?: string;   // optional client-supplied ID (agent generates it)
  proposerUuid: string;
  name: string;
  kind?: 'vtc' | 'vtn';
  threshold?: number;
  adminUuids: string[];
  parentCommunityUuid?: string;  // optional parent VTN (UUID) to nest the new VTC under
}

interface CeremonyApproveParams {
  ceremonyId: string;
  approverUuid: string;
  signature: string;
}

interface CeremonyQueryParams {
  ceremonyId: string;
}

interface CeremonyResetParams {
  ceremonyId: string;
}

interface CeremonyReconcileParams {
  ceremonyId: string;
}

export class CeremonyCoordinatorParticipant implements Participant {
  readonly pid: string;
  private readonly appDb: DataSource;
  private readonly txDb: DataSource;
  private readonly store: CeremonyStore;
  private readonly guard: GovernanceGuard;

  constructor(pid: string, appDb: DataSource, txDb: DataSource) {
    this.pid = pid;
    this.appDb = appDb;
    this.txDb = txDb;
    this.store = new CeremonyStore(txDb);
    // GovernanceGuard is the single home for crystallization authorization
    // (crypto + policy). The participant DRIVES the founding ceremony, so it —
    // not only the REST coordinator — must consult it before crystallizing.
    this.guard = new GovernanceGuard(appDb, createPolicyEngine());
  }

  handlesOperation(op: Operation): boolean {
    // `ceremony_pending_for` is a QUERY claimed here because the coordinator's
    // tx_query dispatch reuses this predicate to find the participant that answers
    // a query (see the `namespace_info` precedent in vtc-participant.ts).
    return op.op === 'ceremony_begin'
      || op.op === 'ceremony_approve'
      || op.op === 'ceremony_query'
      || op.op === 'ceremony_pending_for'
      || op.op === 'ceremony_log_threads'
      || op.op === 'ceremony_log_thread'
      || op.op === 'ceremony_reset'
      || op.op === 'ceremony_reconcile';
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    for (const op of operations) {
      try {
        if (op.op === 'ceremony_pending_for'
          || op.op === 'ceremony_log_threads'
          || op.op === 'ceremony_log_thread') {
          // Query-only (see `query()`): refused as an operation rather than
          // silently accepted as an empty transaction (mirrors namespace_info).
          return 'no';
        }
        if (op.op === 'ceremony_begin') {
          const p = op.params as unknown as CeremonyBeginParams;
          if (!p?.name || !p?.proposerUuid || !p?.adminUuids) return 'no';
          await this.handleBegin(p);
        } else if (op.op === 'ceremony_approve') {
          const p = op.params as unknown as CeremonyApproveParams;
          if (!p?.ceremonyId || !p?.approverUuid) return 'no';
          await this.handleApprove(p);
        } else if (op.op === 'ceremony_query') {
          // Read-only — always vote yes
        } else if (op.op === 'ceremony_reset') {
          const p = op.params as unknown as CeremonyResetParams;
          if (!p?.ceremonyId) return 'no';
          await this.store.updateStatus(p.ceremonyId, 'aborted');
        } else if (op.op === 'ceremony_reconcile') {
          const p = op.params as unknown as CeremonyReconcileParams;
          if (!p?.ceremonyId) return 'no';
          await this.handleReconcile(p);
        }
      } catch (err) {
        console.error(`[ceremony-participant] prepare failed for tx ${txId}, op ${op.op}:`, (err as Error)?.message);
        return 'no';
      }
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

  async query(op: string, params?: Record<string, unknown>): Promise<unknown> {
    if (op === 'ceremony_query') {
      const p = params as unknown as CeremonyQueryParams;
      if (!p?.ceremonyId) return { error: 'ceremonyId required' };
      const proposal = await this.store.getProposal(p.ceremonyId);
      if (!proposal) return { error: 'ceremony not found' };
      const approvals = await this.store.getApprovals(p.ceremonyId);
      return {
        status: proposal.status,
        name: proposal.name,
        kind: proposal.kind,
        adminUuids: proposal.adminUuids,
        threshold: proposal.threshold,
        proposalHash: proposal.proposalHash,
        expiresAt: proposal.expiresAt,
        errorReason: proposal.errorReason || null,
        approvals: approvals.map(a => ({
          approverUuid: a.approverDid,
          receivedAt: a.receivedAt,
        })),
        approvalCount: approvals.length,
      };
    }
    if (op === 'ceremony_pending_for') {
      const p = params as unknown as { adminUuid?: string };
      if (!p?.adminUuid) return { error: 'adminUuid required' };
      const pending = await this.store.listPending();
      const out: Array<Record<string, unknown>> = [];
      for (const prop of pending) {
        const isAdmin = (prop.adminUuids ?? []).includes(p.adminUuid)
          || prop.proposerUuid === p.adminUuid;
        if (!isAdmin) continue;
        const approvals = await this.store.getApprovals(prop.proposalId);
        // Already co-signed by this admin? Then it no longer needs THEIR signature
        // (the ceremony may still be waiting on other admins).
        if (approvals.some((a) => a.approverDid === p.adminUuid)) continue;
        out.push({
          ceremonyId: prop.proposalId,
          name: prop.name,
          kind: prop.kind,
          threshold: prop.threshold,
          adminCount: prop.adminUuids.length,
          proposalHash: prop.proposalHash,
          expiresAt: prop.expiresAt,
          approvalCount: approvals.length,
          approvedBy: approvals.map((a) => a.approverDid),
        });
      }
      return out;
    }
    // ── The ceremony task log (read) ────────────────────────────────────────
    // The agent app is where communities are created and managed, so its UI reads
    // the log from HERE rather than the utility server having a second UI of its own.
    if (op === 'ceremony_log_threads') {
      return { threads: await listCeremonyThreads(this.appDb) };
    }
    if (op === 'ceremony_log_thread') {
      const p = params as unknown as { threadId?: string };
      if (!p?.threadId) return { error: 'threadId required' };
      return { threadId: p.threadId, steps: await getCeremonyThread(this.appDb, p.threadId) };
    }
    throw new Error(`CeremonyCoordinatorParticipant does not support query: ${op}`);
  }

  // ── Internal handlers ────────────────────────────────────────────────

  private async handleBegin(p: CeremonyBeginParams): Promise<void> {
    const ceremonyId = p.ceremonyId ?? randomUUID();
    const now = Date.now();
    const expiresAt = now + 7 * 24 * 60 * 60 * 1000;

    // Reject if a ceremony with this ID already exists (idempotency guard)
    const existing = await this.store.getProposal(ceremonyId);
    if (existing) throw new Error(`ceremony ${ceremonyId.slice(0, 8)} already exists`);

    const canonical = JSON.stringify({
      ceremonyId,
      name: p.name,
      kind: p.kind ?? 'vtc',
      adminUuids: [...p.adminUuids].sort(),
      threshold: p.threshold ?? 1,
      proposerUuid: p.proposerUuid,
      parentCommunityUuid: p.parentCommunityUuid ?? null,
      expiresAt,
    });
    const { sha256 } = await import('@p2p-trust-stack/core/crypto/primitives.js');
    const proposalHash = Buffer.from(sha256(new TextEncoder().encode(canonical))).toString('base64');

    await this.store.createProposal({
      proposalId: ceremonyId,
      proposerDid: p.proposerUuid,
      vtcDid: `did:p2pts:ceremony:${ceremonyId.slice(0, 12)}`,
      name: p.name,
      kind: p.kind ?? 'vtc',
      adminDids: p.adminUuids,
      threshold: p.threshold ?? 1,
      expiresAt,
      proposalHash,
      parentCommunityDid: p.parentCommunityUuid ?? null,
      proposerUuid: p.proposerUuid,
      adminUuids: p.adminUuids,
    });

    console.log(`[ceremony-participant] began ${ceremonyId.slice(0, 8)}: '${p.name}' (${p.kind ?? 'vtc'}, admins=${p.adminUuids.length})`);

    // Log the proposal as a Trust Task. The founding ceremony is ONE thread
    // (`threadId` = ceremonyId): its first documents are the proposal and the
    // co-signatures that answer it, followed by the `vtc-establish` steps the
    // driver records at crystallization. A response here states what the server
    // now AWAITS — one co-signature from every named admin — which is what makes
    // "naming someone an admin" a request rather than a grant.
    await trustTasksRepo.record(this.appDb, {
      uuid: generateUuid(),
      threadId: ceremonyId,
      type: CEREMONY_PROPOSE_TYPE,
      direction: 'request',
      issuerDid: p.proposerUuid,
      payload: {
        ceremonyId,
        name: p.name,
        kind: p.kind ?? 'vtc',
        adminUuids: p.adminUuids,
        threshold: p.threshold ?? 1,
        parentCommunityUuid: p.parentCommunityUuid ?? null,
        proposalHash,
      },
    });
    await trustTasksRepo.record(this.appDb, {
      uuid: generateUuid(),
      threadId: ceremonyId,
      type: CEREMONY_PROPOSE_TYPE,
      direction: 'response',
      recipientDid: p.proposerUuid,
      status: 'pending',
      payload: {
        result: 'proposal recorded',
        coSignaturesRequired: p.adminUuids.length,
        coSignaturesReceived: 0,
      },
    });
  }

  private async handleApprove(p: CeremonyApproveParams): Promise<void> {
    const proposal = await this.store.getProposal(p.ceremonyId);
    if (!proposal) throw new Error(`ceremony ${p.ceremonyId} not found`);
    if (proposal.status !== 'pending') throw new Error(`ceremony is ${proposal.status}`);

    // GovernanceGuard gap-closure (admin-set membership). An arbitrary
    // `approverUuid` used to be recorded and counted, so a caller could inflate the
    // approval count with identities that are not founding admins. The authoritative
    // admin set is the one the proposer declared at `ceremony_begin`; the proposer
    // is included defensively. This mirrors the admin-set check inside
    // `GovernanceGuard.validateCrystallization`, which the core coordinator applies
    // but this participant previously did not.
    //
    // The SAME set is the co-signature quorum: every declared admin must accept, so
    // "who may sign" and "how many must sign" are one list by definition.
    const declaredAdmins = new Set<string>([
      ...(proposal.adminUuids ?? []),
      ...(proposal.adminDids ?? []),
    ]);
    if (proposal.proposerUuid) declaredAdmins.add(proposal.proposerUuid);
    const required = Math.max(declaredAdmins.size, 1);

    // Record the ATTEMPT first — a refused co-signature is exactly the kind of event
    // the trust-task log exists to capture.
    await trustTasksRepo.record(this.appDb, {
      uuid: generateUuid(),
      threadId: p.ceremonyId,
      type: CEREMONY_CO_SIGN_TYPE,
      direction: 'request',
      issuerDid: p.approverUuid,
      payload: {
        ceremonyId: p.ceremonyId,
        proposalHash: proposal.proposalHash,
        signature: p.signature,
      },
    });

    if (!declaredAdmins.has(p.approverUuid)) {
      // Best-effort denial record: the refusal REASON must be what surfaces, so a
      // failure to write the audit row must not mask it.
      try {
        await trustTasksRepo.record(this.appDb, {
          uuid: generateUuid(),
          threadId: p.ceremonyId,
          type: CEREMONY_CO_SIGN_TYPE,
          direction: 'response',
          recipientDid: p.approverUuid,
          status: 'denied',
          payload: { result: 'refused', reason: 'not a founding admin of this ceremony' },
        });
      } catch (err) {
        console.warn(`[ceremony-participant] denial audit row not written: ${(err as Error)?.message ?? err}`);
      }
      throw new Error(`approver ${p.approverUuid} is not a founding admin of this ceremony`);
    }

    await this.store.recordApproval(p.ceremonyId, p.approverUuid, p.signature);
    const count = await this.store.countApprovals(p.ceremonyId);

    // The response is the ACCEPTANCE side of the exchange. Crystallization requires
    // EVERY declared founding admin to co-sign: the creator approving on their own —
    // which used to found the community on everyone's behalf — is deliberately NOT a
    // trigger any more.
    //
    // The count decides only whether it is worth ASKING the policy yet; the quorum
    // itself is the `crystallize-quorum-*` rules (they compare `approval_count`
    // against `threshold_n`, the declared admin count). Asking early is harmless —
    // `crystallize` leaves the ceremony PENDING while the policy reports
    // `requireConsent`.
    await trustTasksRepo.record(this.appDb, {
      uuid: generateUuid(),
      threadId: p.ceremonyId,
      type: CEREMONY_CO_SIGN_TYPE,
      direction: 'response',
      recipientDid: p.approverUuid,
      status: 'allowed',
      payload: {
        result: 'co-signature recorded',
        coSignaturesRequired: required,
        coSignaturesReceived: count,
        quorumMet: count >= required,
      },
    });

    // Nudge the OTHER founding admins: a co-signature landed and their "N of M" is now stale.
    //
    // Nothing announced this before. The `vtc-membership` fan-out fires only on CRYSTALLIZATION (the community
    // does not exist until then), so while a founding was still collecting co-signatures an admin watching it
    // could only find out by asking — which is why `communities.html` polled `/api/ceremony-log` every 4 s.
    //
    // The nudge carries no log content: `{ threadId, step, adminUuids }`. The agent re-reads its own log
    // endpoint, so what matters is the signal, not the payload.
    //
    // Deliberately AFTER the record and NOT on the crystallizing path: crystallization already fans out
    // `vtc-membership`, and nudging there would be a second delivery for the same event.
    if (count < required) {
      try {
        await tryEnqueueFanout('ceremony-event', {
          threadId: p.ceremonyId,
          step: `co-sign:${count}`,
          adminUuids: [...declaredAdmins],
          at: Date.now(),
        });
        console.log(
          `[ceremony-participant] co-signature ${count}/${required} on ${p.ceremonyId.slice(0, 8)} — nudged the other admins`,
        );
      } catch (err) {
        console.warn('[ceremony-participant] %s', `failed to nudge admins for ${p.ceremonyId.slice(0, 8)}: ${(err as Error)?.message ?? err}`);
      }
    }

    if (count >= required) {
      await this.crystallize(p.ceremonyId);
    }
  }

  private async crystallize(ceremonyId: string): Promise<void> {
    const proposal = await this.store.getProposal(ceremonyId);
    if (!proposal) throw new Error(`ceremony ${ceremonyId} not found`);

    try {
      const avail = await checkCommunityNameAvailable(this.appDb, proposal.name);
      if (!avail.available) {
        await this.store.updateStatus(ceremonyId, 'failed');
        await this.txDb.run(
          `UPDATE ceremony_proposals SET error_reason = ? WHERE proposal_id = ?`,
          `Name "${proposal.name}" is already taken.`, ceremonyId,
        );
        throw new Error(`Name "${proposal.name}" is already taken.`);
      }

      // GovernanceGuard gap-closure (parent-VTN policy). The parent VTN's own
      // policy governs which child KINDS it accepts (`validateParentVtnPolicy` →
      // the `parent_accepts_child` rule). The core CeremonyCoordinator applies
      // this; this participant previously skipped it, so the agent-driven path
      // ignored a parent's `allowedChildKinds` restriction. It early-returns
      // `allow` when there is no parent or the parent is not a VTN, so orphan and
      // non-VTN-parented communities are unaffected.
      const parentCheck = await new GovernanceGuard(this.appDb, createPolicyEngine())
        .validateParentVtnPolicy(proposal.parentCommunityDid, proposal.kind);
      if (!parentCheck.allowed) {
        await this.store.updateStatus(ceremonyId, 'failed');
        await this.txDb.run(
          `UPDATE ceremony_proposals SET error_reason = ? WHERE proposal_id = ?`,
          `Parent VTN policy denied: ${parentCheck.reason}`, ceremonyId,
        );
        throw new Error(`Parent VTN policy denied: ${parentCheck.reason}`);
      }

      // GovernanceGuard gap-closure (crystallization authorization). This is the
      // authoritative gate the core CeremonyCoordinator applies and this participant
      // previously skipped: verify every approval's Ed25519 signature over the
      // proposal hash, require approvers to be founding admins, count DISTINCT
      // VERIFIED approvers, and evaluate the `crystallize_ceremony` policy
      // (quorum M-of-N, min admins, min threshold).
      //
      // `validateCrystallization` is DID-space — it tests the admin set against an
      // approver's DID and resolves each approver's signing key BY DID. The ceremony
      // stores UUIDs (proposerUuid / adminUuids / approverUuid), so every UUID is
      // resolved to its PRIMARY DID here first. Without this the guard looks up a key
      // for a UUID and refuses with "cannot resolve key for <uuid>".
      const adminUuids = proposal.adminUuids.length > 0 ? proposal.adminUuids : proposal.adminDids;
      const adminDids: string[] = [];
      const uuidToDid = new Map<string, string>();
      for (const uuid of adminUuids) {
        const identity = await identitiesRepo.findByUuid(this.appDb, uuid);
        if (identity?.did) {
          uuidToDid.set(uuid, identity.did);
          adminDids.push(identity.did);
        }
      }
      const proposerDid = proposal.proposerUuid
        ? (uuidToDid.get(proposal.proposerUuid)
            ?? (await identitiesRepo.findByUuid(this.appDb, proposal.proposerUuid))?.did
            ?? proposal.vtcDid)
        : proposal.vtcDid;

      const approvals = await this.store.getApprovals(ceremonyId);
      const approvalsForGuard = approvals.map((a) => ({
        ...a,
        approverDid: uuidToDid.get(a.approverDid) ?? a.approverDid,
      }));
      const decision = await this.guard.validateCrystallization(
        { ...proposal, adminDids, proposerDid },
        approvalsForGuard,
      );
      if (!decision.allowed) {
        // `requireConsent` means "not allowed YET" — one or more founding admins
        // have not co-signed. That is a normal stage of the ceremony, not a
        // failure: leave the proposal PENDING so the remaining admins' approvals
        // can satisfy it. Only a hard deny (invalid signature, unknown approver,
        // banned parent kind, taken name) fails the proposal.
        if (decision.requireConsent) {
          console.log(
            `[ceremony-participant] ${ceremonyId.slice(0, 8)} awaiting co-signature: ` +
            `${decision.reason ?? 'quorum not met'}`,
          );
          return;
        }
        await this.store.updateStatus(ceremonyId, 'failed');
        await this.txDb.run(
          `UPDATE ceremony_proposals SET error_reason = ? WHERE proposal_id = ?`,
          `Crystallization denied: ${decision.reason ?? 'policy'}`, ceremonyId,
        );
        throw new Error(`Crystallization denied: ${decision.reason ?? 'policy'}`);
      }

      const identityUuids: string[] = [];
      for (const uuid of adminUuids) {
        const identity = await identitiesRepo.findByUuid(this.appDb, uuid);
        if (!identity) throw new Error(`admin UUID ${uuid} not found`);
        // The UUID may resolve to an endpoint-less TSP-bridge/did:peer:4 stub (the
        // relationship handshake row) rather than the agent's authoritative
        // did:scid:vh identity. createVtc rejects any founding admin without an
        // active libp2p endpoint, so resolve the REAL VTA that shares this
        // stub's Ed25519 public key and use that instead. This tolerates any
        // caller (agent, API, recovered ceremony) that offers a stub UUID.
        const isRealVta = await identitiesRepo.hasAnyEndpoint(this.appDb, identity.uuid);
        if (!isRealVta) {
          const real = await this.resolveRealVtaForStub(this.appDb, identity.uuid);
          if (real) {
            identityUuids.push(real.uuid);
            continue;
          }
        }
        identityUuids.push(identity.uuid);
      }

      const result = await this.appDb.transaction(async (tx) => {
        // An ATOMIC driven ceremony: createVtc + every step's trust-task record commit
        // together, or not at all. The gate is createVtc's own validation (name/endpoint/
        // VRC/threshold), which throws and rolls back the transaction on failure.
        const drive = await driveCeremony(tx, 'vtc-establish', ceremonyId, {
          context: {
            db: tx,
            name: proposal.name,
            kind: proposal.kind as VtcKind,
            adminIdentityUuids: identityUuids,
            threshold: proposal.threshold,
            parentCommunityUuid: proposal.parentCommunityDid ?? undefined,
          },
        });
        if (!drive.completed) {
          throw new Error(`ceremony 'vtc-establish' halted at ${drive.haltedAt}`);
        }
        return drive.outputs[VTC_ESTABLISH_TYPE] as CreateVtcResult;
      });

      // Fan-out a pending-send-state delivery to each founding admin via the CRE
      // engine. Only the communityId REF is stored — the current VTC records are
      // materialized at send time by the engine's queue-row store (incl. on a
      // reconnect flush), so offline agents receive up-to-date data when they return.
      // (Delivery runs AFTER the atomic create+record has committed.)
      await tryEnqueueFanout('vtc-membership', { communityUuid: result.identity.uuid });

      // …then deliver each founding admin's VMC (minted inside createVtc and
      // referenced by memberships.membership_credential_uuid) to its holder.
      // Queued AFTER the community package so the queue — which drains in
      // created_at order — lands the membership link before the credential.
      await enqueueFoundingAdminVmcFanout(result.foundingAdmins);

      await this.store.updateStatus(ceremonyId, 'crystallized', Date.now());
      console.log(`[ceremony-participant] crystallized ${ceremonyId.slice(0, 8)} → VTC '${result.identity.name}'`);

    } catch (err) {
      const msg = (err as Error)?.message ?? 'Unknown error';
      await this.store.updateStatus(ceremonyId, 'failed');
      await this.txDb.run(
        `UPDATE ceremony_proposals SET error_reason = ? WHERE proposal_id = ?`,
        msg, ceremonyId,
      );
      throw err;
    }
  }

  private async handleReconcile(p: CeremonyReconcileParams): Promise<void> {
    const proposal = await this.store.getProposal(p.ceremonyId);
    if (!proposal) throw new Error(`ceremony ${p.ceremonyId} not found`);

    if (proposal.status === 'crystallized') return;

    if (proposal.status === 'pending' || proposal.status === 'failed') {
      try {
        const avail = await checkCommunityNameAvailable(this.appDb, proposal.name);
        if (!avail.available) {
          await this.store.updateStatus(p.ceremonyId, 'crystallized', Date.now());
          console.log(`[ceremony-participant] reconciled ${p.ceremonyId.slice(0, 8)}: VTC exists, marked crystallized`);
        }
      } catch { /* ignore */ }
    }
  }

  /**
   * Resolve the authoritative (did:scid:vh) identity that shares the same
   * Ed25519 public key as an endpoint-less did:peer:4 stub identity. The
   * utility server's TSP bridge creates such stubs (no active peer_endpoint)
   * when recording the relationship handshake, keyed by the peer's did:peer:4
   * VID — a DIFFERENT identity row from the agent's real did:scid:vh VTA.
   * createVtc requires an active libp2p endpoint on every founding admin, so
   * we map the stub to its real VTA.
   */
  private async resolveRealVtaForStub(db: DataSource, stubUuid: string): Promise<{ uuid: string } | null> {
    const hex = (b: Buffer | Uint8Array | null | undefined): string =>
      b && b.length > 0 ? Buffer.from(b).toString('hex') : '<none>';

    // Dump the stub's DIDs and keys.
    const stubDids = await db.all<{ did: string; method: string; is_primary: number }>(
      `SELECT d.did, d.method, d.is_primary FROM did_documents d WHERE d.identity_uuid = $1`, stubUuid,
    );
    const stubKeys = await db.all<{ key_type: string; public_key: Buffer }>(
      `SELECT key_type, public_key FROM keys WHERE identity_uuid = $1`, stubUuid,
    );
    console.log(
      `[ceremony-participant] resolveRealVtaForStub stub=${stubUuid}`,
    );
    for (const d of stubDids) {
      console.log(`[ceremony-participant]   stub.did (${d.method}, primary=${d.is_primary}) = ${d.did}`);
    }
    for (const k of stubKeys) {
      console.log(`[ceremony-participant]   stub.key ${k.key_type} = ${hex(k.public_key)}`);
    }

    // Dump every VTA identity (excluding the stub) with its DIDs, keys, endpoint.
    const others = await db.all<{ uuid: string; name: string | null; has_endpoint: number }>(
      `SELECT i.uuid, i.name,
              (SELECT 1 FROM peer_endpoints pe WHERE pe.identity_uuid = i.uuid LIMIT 1) AS has_endpoint
       FROM identities i
       WHERE i.role = 'vta' AND i.uuid <> $1
       ORDER BY i.created_at, i.uuid`, stubUuid,
    );
    for (const o of others) {
      const oDids = await db.all<{ did: string; method: string }>(
        `SELECT d.did, d.method FROM did_documents d WHERE d.identity_uuid = $1`, o.uuid,
      );
      const oKeys = await db.all<{ key_type: string; public_key: Buffer }>(
        `SELECT key_type, public_key FROM keys WHERE identity_uuid = $1`, o.uuid,
      );
      console.log(
        `[ceremony-participant]   candidate uuid=${o.uuid} name=${JSON.stringify(o.name ?? null)} ` +
        `endpoint=${o.has_endpoint ? 'yes' : 'no'}`,
      );
      for (const d of oDids) {
        console.log(`[ceremony-participant]     cand.did (${d.method}) = ${d.did}`);
      }
      for (const k of oKeys) {
        console.log(`[ceremony-participant]     cand.key ${k.key_type} = ${hex(k.public_key)}`);
      }
    }

    // Resolve by shared DID first (authoritative), then by shared key (ed25519 OR x25519).
    const realByDid = await db.get<{ uuid: string }>(
      `SELECT i.uuid FROM identities i
       JOIN did_documents d ON d.identity_uuid = i.uuid
       WHERE i.role = 'vta' AND i.uuid <> $1
         AND d.did IN (SELECT dd.did FROM did_documents dd WHERE dd.identity_uuid = $1)
         AND EXISTS (SELECT 1 FROM peer_endpoints pe WHERE pe.identity_uuid = i.uuid)
       ORDER BY i.created_at, i.uuid
       LIMIT 1`,
      stubUuid,
    );
    if (realByDid) {
      console.log(`[ceremony-participant] resolveRealVtaForStub → real (by DID) = ${realByDid.uuid}`);
      return realByDid;
    }

    const real = await db.get<{ uuid: string }>(
      `SELECT i.uuid FROM identities i
       JOIN keys k ON k.identity_uuid = i.uuid
       JOIN keys k2 ON k2.public_key = k.public_key AND k2.key_type = k.key_type
       JOIN identities i2 ON i2.uuid = k2.identity_uuid
       JOIN peer_endpoints pe ON pe.identity_uuid = i.uuid
       WHERE i2.uuid = $1 AND i.role = 'vta' AND i.uuid <> $1
       ORDER BY i.created_at, i.uuid
       LIMIT 1`,
      stubUuid,
    );
    if (real) {
      console.log(`[ceremony-participant] resolveRealVtaForStub → real (by key) = ${real.uuid}`);
    } else {
      console.log(`[ceremony-participant] resolveRealVtaForStub → NO real VTA (no DID or key match)`);
    }
    return real ?? null;
  }
}
