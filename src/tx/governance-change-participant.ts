/**
 * GovernanceChangeParticipant — utility-server participant for the community
 * governance-change consent ceremony (Phase B).
 *
 * Ops (TSP, over the coordinator):
 *   gov_change_begin        — resolve the approval scope, hash the proposal, create it
 *   gov_change_approve      — record a signed approval; crystallize when the distinct
 *                             VERIFIED approval count reaches the requirement
 *   gov_change_query        — read-only: status + hash + counts
 *   gov_change_pending_for  — read-only: pending proposals this approver may approve
 *
 * Crystallization drives the DB-defined `governance-change` ceremony (a `policy` gate
 * on `update_governance` + an `apply` effect), so the change is applied inside one
 * atomic transaction and every step is recorded as a trust task.
 *
 * Consent (who/how many) is data-driven — resolved from the setting's approval scope at
 * `begin` time — and enforced by verified Ed25519 signatures over the proposal hash,
 * the same discipline `GovernanceGuard.validateCrystallization` applies to founding.
 *
 * pid: 'server:us-1' — the agent path addresses the utility server as server:us-1.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { Operation, Outcome, Participant, Vote } from '@p2p-trust-stack/core/tx/types.js';
import { GovernanceChangeStore } from '@p2p-trust-stack/core/tx/governance-change-store.js';
import { resolveRequiredApprovers, computeChangeProposalHash } from '@p2p-trust-stack/core/services/governance-change.js';
import type { ApprovalScope, GovernanceChange, BindingOp } from '@p2p-trust-stack/core/services/governance-change.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import * as governanceRepo from '@p2p-trust-stack/core/db/repositories/governance-repo.js';
import { findEd25519KeysByIdentity } from '@p2p-trust-stack/core/db/repositories/keys-repo.js';
import { verifyEd25519 } from '@p2p-trust-stack/core/crypto/primitives.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import { GovernanceGuard } from '@p2p-trust-stack/core/services/governance-guard.js';
import { createPolicyEngine } from '@p2p-trust-stack/core/services/policy-engine-config.js';
import { guardAuthorizer } from '@p2p-trust-stack/core/services/trust-tasks/authorizer.js';
import { driveCeremony } from '@p2p-trust-stack/core/services/trust-tasks/driver.js';
import { registerExecutor } from '@p2p-trust-stack/core/services/trust-tasks/catalog.js';
import { GOVERNANCE_CHANGE_APPLY_TYPE, CEREMONY_GOVERNANCE_CHANGE } from '@p2p-trust-stack/core/services/trust-tasks/type-uris.js';
import { tryEnqueueFanout } from '../services/exchange-runtime.js';

interface GovernanceBeginParams {
  proposalId?: string;
  communityUuid: string;
  proposerUuid: string;
  change: GovernanceChange;
  scope?: ApprovalScope;
  minApprovals?: number;
  expiresInMs?: number;
}

interface GovernanceApproveParams {
  proposalId: string;
  approverUuid: string;
  /** Ed25519 (base64) over the proposal hash. */
  signature: string;
}

const DEFAULT_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;

/** Apply ONE binding op (add/update = upsert; remove = delete). */
async function applyBindingOp(
  db: DataSource,
  communityUuid: string,
  op: BindingOp,
  now: number,
): Promise<void> {
  if (op.op === 'remove') {
    await db.run(
      'DELETE FROM community_policy_bindings WHERE community_identity_uuid = ? AND rule_type = ?',
      communityUuid, op.ruleType,
    );
    return;
  }
  const enabled = op.enabled === false ? 0 : 1;
  const params = op.params === undefined ? null : JSON.stringify(op.params);
  await db.run(
    `INSERT INTO community_policy_bindings
       (uuid, community_identity_uuid, rule_type, enabled, params, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (community_identity_uuid, rule_type) DO UPDATE SET
       enabled = excluded.enabled, params = excluded.params, updated_at = excluded.updated_at`,
    generateUuid(), communityUuid, op.ruleType, enabled, params, now,
  );
}

// ── Registry: the governance-change ceremony's effect executor ────────────────
// Applies the approved change: threshold updates + binding ops. This runs only after
// the `policy` gate (update_governance) has allowed, inside the caller's transaction.
registerExecutor(GOVERNANCE_CHANGE_APPLY_TYPE, async (context) => {
  const db = context.db as DataSource;
  const communityUuid = context.communityUuid as string;
  const change = (context.change ?? {}) as GovernanceChange;
  const now = Math.floor(Date.now() / 1000);

  if (change.adminThresholdM !== undefined || change.adminThresholdN !== undefined) {
    await governanceRepo.findOrCreateForCommunity(db, communityUuid);
    await governanceRepo.update(db, communityUuid, {
      adminThresholdM: change.adminThresholdM,
      adminThresholdN: change.adminThresholdN,
    });
  }

  for (const op of change.bindings ?? []) {
    await applyBindingOp(db, communityUuid, op, now);
  }

  return { communityUuid, applied: true, bindingOps: (change.bindings ?? []).length };
});

// ── The participant ──────────────────────────────────────────────────────────

export class GovernanceChangeParticipant implements Participant {
  readonly pid: string;
  private readonly appDb: DataSource;
  private readonly txDb: DataSource;
  private readonly store: GovernanceChangeStore;
  private readonly guard: GovernanceGuard;

  constructor(pid: string, appDb: DataSource, txDb: DataSource) {
    this.pid = pid;
    this.appDb = appDb;
    this.txDb = txDb;
    this.store = new GovernanceChangeStore(txDb);
    this.guard = new GovernanceGuard(appDb, createPolicyEngine());
  }

  handlesOperation(op: Operation): boolean {
    return op.op === 'gov_change_begin'
      || op.op === 'gov_change_approve'
      || op.op === 'gov_change_query'
      || op.op === 'gov_change_pending_for';
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    for (const op of operations) {
      try {
        if (op.op === 'gov_change_pending_for') {
          return 'no'; // query-only (see query())
        }
        if (op.op === 'gov_change_begin') {
          const p = op.params as unknown as GovernanceBeginParams;
          if (!p?.communityUuid || !p?.proposerUuid || !p?.change) return 'no';
          await this.handleBegin(p);
        } else if (op.op === 'gov_change_approve') {
          const p = op.params as unknown as GovernanceApproveParams;
          if (!p?.proposalId || !p?.approverUuid) return 'no';
          await this.handleApprove(p);
        } else if (op.op === 'gov_change_query') {
          // read-only — always yes
        }
      } catch (err) {
        console.error(`[gov-change] prepare failed for tx ${txId}, op ${op.op}:`, (err as Error)?.message);
        return 'no';
      }
    }
    await this.txDb.run(
      `INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome) VALUES (?, ?, 'prepared')`,
      txId, this.pid);
    return 'yes';
  }

  async commit(txId: string): Promise<void> {
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'committed' WHERE tx_id = ? AND pid = ?`, txId, this.pid);
  }

  async abort(txId: string): Promise<void> {
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'aborted' WHERE tx_id = ? AND pid = ?`, txId, this.pid);
  }

  async compensate(txId: string): Promise<void> {
    await this.abort(txId);
  }

  async inquiry(txId: string): Promise<Outcome> {
    const row = await this.txDb.get<{ outcome: string }>(
      'SELECT outcome FROM tx_participant_state WHERE tx_id = ? AND pid = ?', txId, this.pid);
    return (row?.outcome as Outcome) ?? 'unknown';
  }

  async query(op: string, params?: Record<string, unknown>): Promise<unknown> {
    if (op === 'gov_change_query') {
      const p = params as unknown as { proposalId?: string };
      if (!p?.proposalId) return { error: 'proposalId required' };
      const proposal = await this.store.getProposal(p.proposalId);
      if (!proposal) return { error: 'proposal not found' };
      const approvals = await this.store.getApprovals(p.proposalId);
      // `approvalCount` is how many signatures were RECORDED. `verifiedApproverCount` is how
      // many actually VERIFY — the number that decides crystallization. They differ whenever a
      // recorded signature cannot be checked (most often: the approver's Ed25519 key is not
      // registered on this server), and that difference is invisible from `approvalCount`,
      // which is precisely how a proposal can sit at "awaiting others" forever.
      const verifiedApproverCount = await this.countVerifiedApprovers(proposal.proposalHash, approvals);
      return {
        found: true,
        proposalId: proposal.proposalId,
        status: proposal.status,
        communityUuid: proposal.communityUuid,
        communityDid: proposal.communityDid,
        scope: proposal.scope,
        requiredApproverCount: proposal.requiredApproverCount,
        approvalCount: approvals.length,
        verifiedApproverCount,
        proposalHash: proposal.proposalHash,
        change: proposal.change,
        expiresAt: proposal.expiresAt,
        errorReason: proposal.errorReason ?? null,
        approvedBy: approvals.map((a) => a.approverUuid),
      };
    }
    if (op === 'gov_change_pending_for') {
      const p = params as unknown as { approverUuid?: string };
      if (!p?.approverUuid) return { error: 'approverUuid required' };
      const rows = await this.store.listPendingForApprover(p.approverUuid);
      const proposals: Array<Record<string, unknown>> = [];
      for (const prop of rows) {
        const approvals = await this.store.getApprovals(prop.proposalId);
        proposals.push({
          proposalId: prop.proposalId,
          communityUuid: prop.communityUuid,
          communityDid: prop.communityDid,
          scope: prop.scope,
          requiredApproverCount: prop.requiredApproverCount,
          // Surfaced so a caller can show REAL progress ("1 of 2 verified") rather than
          // recording a signature and leaving the operator to guess why nothing applies.
          approvalCount: approvals.length,
          verifiedApproverCount: await this.countVerifiedApprovers(prop.proposalHash, approvals),
          approvedBy: approvals.map((a) => a.approverUuid),
          proposalHash: prop.proposalHash,
          change: prop.change,
          expiresAt: prop.expiresAt,
        });
      }
      return { proposals };
    }
    throw new Error(`GovernanceChangeParticipant does not support query: ${op}`);
  }

  /**
   * Server-LOCAL entry point for the utility server's own HTTP surface (no 2PC): begin
   * a proposal on behalf of a signed-in admin. `begin` needs no signature — the consent
   * is collected later, from each approver's AGENT (the server never holds their keys).
   */
  async beginChange(params: GovernanceBeginParams): Promise<void> {
    await this.handleBegin(params);
  }


  // ── Internal handlers ─────────────────────────────────────────────────────

  private async handleBegin(p: GovernanceBeginParams): Promise<void> {
    const community = await identitiesRepo.findByUuid(this.appDb, p.communityUuid);
    if (!community) throw new Error(`community ${p.communityUuid} not found`);
    const communityDid = community.did ?? community.uuid;
    const proposalId = p.proposalId ?? generateUuid();

    if (await this.store.getProposal(proposalId)) {
      throw new Error(`proposal ${proposalId.slice(0, 8)} already exists`);
    }

    // Roster for scope resolution (active members only).
    const memberships = await membershipsRepo.findForCommunity(this.appDb, p.communityUuid);
    const active = memberships.filter((m) => m.status === 'active');
    const memberUuids = active.map((m) => m.memberIdentityUuid);
    const adminUuids = active
      .filter((m) => m.role === 'admin' || m.role === 'founding_admin')
      .map((m) => m.memberIdentityUuid);

    const scope: ApprovalScope = p.scope ?? 'admins';
    const resolved = resolveRequiredApprovers(
      { scope, minApprovals: p.minApprovals },
      { adminUuids, memberUuids },
    );
    if (resolved.requiredCount === 0) {
      throw new Error(`no eligible approvers for scope '${scope}'`);
    }

    const expiresAt = Date.now() + (p.expiresInMs ?? DEFAULT_EXPIRY_MS);
    const proposalHash = computeChangeProposalHash({
      proposalId, communityUuid: p.communityUuid, proposerUuid: p.proposerUuid,
      change: p.change, scope: resolved.scope,
      requiredApproverUuids: resolved.eligibleUuids, expiresAt,
    });

    await this.store.createProposal({
      proposalId, communityUuid: p.communityUuid, communityDid, proposerUuid: p.proposerUuid,
      change: p.change, scope: resolved.scope, requiredApproverCount: resolved.requiredCount,
      requiredApproverUuids: resolved.eligibleUuids, proposalHash, expiresAt,
    });
    console.log(`[gov-change] began ${proposalId.slice(0, 8)}: scope=${resolved.scope} required=${resolved.requiredCount}`);

    // Durable fan-out: one pending_agent_deliveries row per required approver, so an
    // offline approver learns of the proposal when they reconnect. The REF carries the
    // (immutable) proposal; delivery re-materializes it via the catalog.
    try {
      await tryEnqueueFanout('governance-proposal', {
        proposalId,
        communityUuid: p.communityUuid,
        communityDid,
        proposalHash,
        scope: resolved.scope,
        requiredApproverCount: resolved.requiredCount,
        change: p.change,
        expiresAt,
        approverUuids: resolved.eligibleUuids,
      });
    } catch (err) {
      console.warn('[gov-change] %s', `failed to enqueue proposal fanout for ${proposalId.slice(0, 8)}: ${(err as Error)?.message ?? err}`);
    }
  }

  private async handleApprove(p: GovernanceApproveParams): Promise<void> {
    const proposal = await this.store.getProposal(p.proposalId);
    if (!proposal) throw new Error(`proposal ${p.proposalId} not found`);
    if (proposal.status !== 'pending') throw new Error(`proposal is ${proposal.status}`);
    if (Date.now() > proposal.expiresAt) {
      await this.store.updateStatus(p.proposalId, 'expired');
      throw new Error('proposal expired');
    }
    if (!proposal.requiredApproverUuids.includes(p.approverUuid)) {
      throw new Error(`approver ${p.approverUuid} is not eligible for this proposal`);
    }

    await this.store.recordApproval(p.proposalId, p.approverUuid, p.signature);

    const approvals = await this.store.getApprovals(p.proposalId);
    const verified = await this.countVerifiedApprovers(proposal.proposalHash, approvals);
    if (verified >= proposal.requiredApproverCount) {
      await this.crystallize(p.proposalId);
      return;
    }

    // Still short of the quorum, but its PROGRESS changed — and the other approvers cannot see that.
    //
    // The server fans a proposal out on BEGIN and (via the `governance` recordset) on CRYSTALLIZE. Neither
    // covers a partial approval, so "1 of 2 verified" was only observable by asking — which is why
    // `rules.html` polled every 4 s.
    //
    // Re-fanning `governance-proposal` is the right vehicle rather than a new recordset: the payload is
    // IMMUTABLE (committed to by `proposalHash`) and the agent's mirror is idempotent, so a re-delivery is a
    // safe "state changed, re-read" nudge down a durable path that already exists. The page re-reads the
    // SERVER for the counter, so what matters is the nudge, not the payload.
    //
    // `progressVersion` is what makes the nudge DELIVERABLE: the queue keys a row on
    // `govprop_<proposal>_<member>_<version>` and the table has UNIQUE(idempotency_key), so without a version
    // that moves with the approval count this enqueue would collide with the BEGIN row and be dropped.
    //
    // Deliberately NOT done on the crystallizing path: that already fans out `governance`, and re-delivering a
    // proposal that is no longer pending would be noise.
    try {
      await tryEnqueueFanout('governance-proposal', {
        proposalId: proposal.proposalId,
        communityUuid: proposal.communityUuid,
        communityDid: proposal.communityDid,
        proposalHash: proposal.proposalHash,
        scope: proposal.scope,
        requiredApproverCount: proposal.requiredApproverCount,
        change: proposal.change,
        expiresAt: proposal.expiresAt,
        approverUuids: proposal.requiredApproverUuids,
        // The state marker the queue versions on. `approvals.length` is the recorded count, which is exactly
        // what the other approvers' "N of M" display is derived from.
        progressVersion: approvals.length,
      });
      console.log(
        `[gov-change] progress ${proposal.proposalId.slice(0, 8)}: ${verified}/${proposal.requiredApproverCount} verified — nudged the other approvers`,
      );
    } catch (err) {
      console.warn('[gov-change] %s', `failed to nudge approvers for ${proposal.proposalId.slice(0, 8)}: ${(err as Error)?.message ?? err}`);
    }
  }

  /**
   * Distinct approvers whose Ed25519 signature ACTUALLY verifies over the hash.
   *
   * Every registered Ed25519 key of the approver is tried, not just the first: an identity
   * legitimately holds several (its authoritative `did:scid:vh` key AND the `did:peer:4`
   * relationship-handshake stub's, both at `rotation_version` 0), and `findByIdentityUuid`
   * orders only by `(key_type, rotation_version)` — so picking "the first" is arbitrary and
   * silently discards valid signatures. That is how a proposal with every required approval
   * recorded sat below its quorum and never crystallized.
   */
  private async countVerifiedApprovers(
    proposalHash: string,
    approvals: Array<{ approverUuid: string; signature: string }>,
  ): Promise<number> {
    const hashBytes = new TextEncoder().encode(proposalHash);
    const verified = new Set<string>();
    for (const a of approvals) {
      const publicKeys = await findEd25519KeysByIdentity(this.appDb, a.approverUuid);
      if (publicKeys.length === 0) continue;
      const sig = Buffer.from(a.signature, 'base64');
      if (publicKeys.some((k) => verifyEd25519(sig, hashBytes, k))) verified.add(a.approverUuid);
    }
    return verified.size;
  }

  private async crystallize(proposalId: string): Promise<void> {
    const proposal = await this.store.getProposal(proposalId);
    if (!proposal) throw new Error(`proposal ${proposalId} not found`);

    // Admin gate (POLICY): the proposer must be authorized to change governance.
    const proposerDid = (await identitiesRepo.findByUuid(this.appDb, proposal.proposerUuid))?.did
      ?? proposal.communityDid;
    const decision = await this.guard.authorize({
      action: 'update_governance',
      communityDid: proposal.communityDid,
      actorDid: proposerDid,
    });
    if (!decision.allowed) {
      await this.store.updateStatus(proposalId, 'failed', `update_governance denied: ${decision.reason ?? 'policy'}`);
      throw new Error(`Governance change denied: ${decision.reason ?? 'policy'}`);
    }

    const communityUuid = proposal.communityUuid;
    await this.appDb.transaction(async (tx) => {
      const drive = await driveCeremony(tx, CEREMONY_GOVERNANCE_CHANGE, proposalId, {
        authorizer: guardAuthorizer(new GovernanceGuard(tx, createPolicyEngine())),
        context: {
          db: tx,
          communityUuid,
          communityDid: proposal.communityDid,
          actorDid: proposerDid,
          change: proposal.change,
        },
      });
      if (!drive.completed) {
        throw new Error(`ceremony 'governance-change' halted at ${drive.haltedAt}`);
      }
    });

    await this.store.updateStatus(proposalId, 'crystallized');
    try {
      await tryEnqueueFanout('governance', { communityUuid });
    } catch (err) {
      console.warn('[gov-change] %s', `failed to enqueue governance fanout for ${communityUuid}: ${(err as Error)?.message ?? err}`);
    }
    console.log(`[gov-change] crystallized ${proposalId.slice(0, 8)}`);
  }
}

