/**
 * VTC push-data assembly — the server-side catalog materializers + payload
 * builders for the queue-row recordsets (vtc-membership, governance, credential).
 *
 * The queue (`pending_agent_deliveries`) is driven by the CRE ExchangeEngine /
 * AgentDeliveryQueue: fan-out rows store only a REF (communityUuid /
 * credentialUuid); these materializers re-assemble the full payload from the
 * authoritative utility-server DB AT SEND TIME (via AgentDeliveryQueue.deliverOne
 * → catalog). Nothing here enqueues rows anymore — that is the engine's job.
 *
 * Exposes:
 *   - buildVtcPushData / buildGovernancePushData / buildCredentialPushData
 *     — the raw send-time payload assemblers
 *   - enqueueFoundingAdminVmcFanout
 *     — the creation-ceremony VMC delivery fan-out (one `credential` queue row
 *       per founding admin's minted VMC)
 *   - materializeGovernance / registerVtcMaterializers / registerCredentialMaterializer
 *     — the catalog wiring
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import type { MembershipRow } from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import * as governanceRepo from '@p2p-trust-stack/core/db/repositories/governance-repo.js';
import { registerMaterializer } from '@p2p-trust-stack/core/exchange/catalog.js';
import { ExchangeError } from '@p2p-trust-stack/core/exchange/types.js';
import { tryEnqueueFanout } from './exchange-runtime.js';
import type { VtcPushData } from '@p2p-trust-stack/core/tx/vtc-receive-participant.js';
import { resolveCommunityClaimTypes } from '@p2p-trust-stack/core/services/policy-bindings.js';

/**
 * Build the full current VTC push payload for a community from the authoritative
 * utility-server DB at send time. This is what the queue transmits when a
 * pending send state becomes valid.
 */
export async function buildVtcPushData(ds: DataSource, communityUuid: string): Promise<VtcPushData> {
  const community = await identitiesRepo.findByUuid(ds, communityUuid);
  if (!community) throw new Error(`community ${communityUuid} not found`);

  const memberRows = await membershipsRepo.findForCommunity(ds, community.uuid);
  const governance = await governanceRepo.findForCommunity(ds, communityUuid);

  const docRow = await ds.get<{ did: string; document_json: string }>(
    `SELECT did, document_json FROM did_documents
     WHERE identity_uuid = ? AND method = 'peer4' AND is_primary = 1
     LIMIT 1`, communityUuid,
  );
  const realDid = docRow?.did ?? community.did ?? community.uuid;

  const keyRows = await ds.all<{ key_type: string; public_key: Buffer }>(
    `SELECT key_type, public_key FROM keys
     WHERE identity_uuid = ? AND rotation_version = 0`, community.uuid,
  );

  const memberships: VtcPushData['memberships'] = [];
  for (const member of memberRows) {
    if (member.status !== 'active') continue;
    const adminIdentity = await identitiesRepo.findByUuid(ds, member.memberIdentityUuid);
    let adminRealDid = adminIdentity?.did ?? null;
    if (adminIdentity) {
      const adminDoc = await ds.get<{ did: string }>(
        `SELECT did FROM did_documents
         WHERE identity_uuid = ? AND is_primary = 1 LIMIT 1`,
        adminIdentity.uuid,
      );
      if (adminDoc) adminRealDid = adminDoc.did;
    }
    memberships.push({
      uuid: member.uuid,
      role: member.role,
      status: member.status,
      personhoodAsserted: member.personhoodAsserted ?? false,
      memberUuid: member.memberIdentityUuid,
      memberDid: adminRealDid ?? undefined,
      memberName: adminIdentity?.name ?? null,
      // credentials.uuid of this member's VMC (minted by createVtc for founding
      // admins). Carried on the community package so the receiving agent can
      // link the membership to the credential it receives separately.
      membershipCredentialUuid: member.membershipCredentialUuid ?? null,
    });
  }

  return {
    community: {
      uuid: community.uuid,
      did: realDid,
      name: community.name,
      role: community.role,
    },
    governance: governance ? {
      adminThresholdM: governance.adminThresholdM,
      adminThresholdN: governance.adminThresholdN,
      parentCommunityUuid: governance.parentCommunityUuid ?? null,
      // Claim types ride as data (from the claim-type bindings); the digest is the
      // stored VTC governance-doc commitment. No policy blob crosses the wire.
      allowedClaimTypes: await resolveCommunityClaimTypes(ds, communityUuid),
      vtcGovernanceDigest: governance.vtcGovernanceDigest ?? null,
    } : null,
    memberships,
    didDocument: docRow ? {
      did: docRow.did,
      documentJson: docRow.document_json,
    } : undefined,
    keys: keyRows.map((k) => ({
      keyType: k.key_type as 'ed25519' | 'x25519',
      publicKey: Buffer.from(k.public_key).toString('base64'),
    })),
  };
}

/**
 * Governance recordset — the subset of `buildVtcPushData` that carries the
 * governable state for a community: thresholds, parent affiliation, the allowed
 * claim types (from claim-type bindings), and the stored governance-doc digest.
 * This is what the `governance` catalog entry mines at send time (queue-row push)
 * or on demand (pull).
 *
 * `communityUuid` must be passed in the context filters — the recordset
 * materializer receives `ctx.filters.communityUuid`.
 */
export async function buildGovernancePushData(
  ds: DataSource,
  communityUuid: string,
): Promise<VtcPushData['governance'] & {
  communityUuid: string; communityName: string | null; updatedAt: number | null;
  // The former VTN admin knobs (quorum / endorsementPolicies / witnessSelection /
  // rotationCadenceMs) have no source now; surfaced as typed convenience fields that
  // are reported unset for the exchange projection.
  quorum: number | null;
  endorsementPolicies: string[] | null;
  witnessSelection: string[] | null;
  rotationCadenceMs: number | null;
} | null> {
  const governance = await governanceRepo.findForCommunity(ds, communityUuid);
  if (!governance) return null;
  const community = await identitiesRepo.findByUuid(ds, communityUuid);

  // The former VTN knobs (quorum / endorsementPolicies / witnessSelection /
  // rotationCadenceMs) were never written by createVtc; they have no source and are
  // reported as unset.
  return {
    communityUuid,
    communityName: community?.name ?? null,
    adminThresholdM: governance.adminThresholdM,
    adminThresholdN: governance.adminThresholdN,
    parentCommunityUuid: governance.parentCommunityUuid ?? null,
    allowedClaimTypes: await resolveCommunityClaimTypes(ds, communityUuid),
    vtcGovernanceDigest: governance.vtcGovernanceDigest ?? null,
    updatedAt: governance.updatedAt ?? null,
    quorum: null,
    endorsementPolicies: null,
    witnessSelection: null,
    rotationCadenceMs: null,
  };
}

/**
 * Generic materializer for the `governance` recordset over a request context.
 * Used by the catalog's `materializeGovernance` for pull queries: the
 * requester's community memberships resolve to the communities they may read.
 * When `filters.communityUuid` is present (queue-row fanout) only that
 * community is returned.
 */
export async function materializeGovernance(
  ds: DataSource,
  ctx: { requester?: { uuid?: string; role?: string } | null; filters?: { communityUuid?: string } | null },
): Promise<Record<string, unknown>[]> {
  const requesterUuid = ctx?.requester?.uuid;
  const requestedCommunity = ctx?.filters?.communityUuid;

  if (requestedCommunity) {
    // Direct single-community read (queue-row / on-demand).
    const row = await buildGovernancePushData(ds, requestedCommunity);
    return row ? [row as unknown as Record<string, unknown>] : [];
  }

  if (!requesterUuid) return [];
  const memberships = await membershipsRepo.findForMemberByUuid(ds, requesterUuid);
  const communityUuids = [...new Set(memberships.map((m) => m.communityIdentityUuid))];
  const rows: Record<string, unknown>[] = [];
  for (const uuid of communityUuids) {
    const row = await buildGovernancePushData(ds, uuid);
    if (row) rows.push(row as unknown as Record<string, unknown>);
  }
  return rows;
}

/**
 * Wire the server-side materializers into the CRE catalog:
 *   - `vtc-membership` → buildVtcPushData (reuse; now carries claim types + digest)
 *   - `governance`     → materializeGovernance (thresholds + claim types)
 * Called unconditionally from the utility-server bootstrap.
 */
export function registerVtcMaterializers(): void {
  registerMaterializer('vtc-membership', async (ds: DataSource, ctx: { filters?: { communityUuid?: string } | null }) => {
    const communityUuid = ctx?.filters?.communityUuid;
    if (!communityUuid) {
      throw new ExchangeError('denied', 'vtc-membership requires filters.communityUuid');
    }
    const row = await buildVtcPushData(ds, communityUuid);
    return [row as unknown as Record<string, unknown>];
  });

  registerMaterializer('governance', (ds: DataSource, ctx: { requester?: { uuid?: string; role?: string } | null; filters?: { communityUuid?: string } | null }) =>
    materializeGovernance(ds, ctx),
  );
}

/**
 * Governance-proposal recordset materializer (Phase B). The delivery REF carries the
 * immutable proposal (its content is committed to by `proposal_hash`), so this returns
 * it verbatim — no cross-database read and no staleness concern. Registered alongside
 * the other server-side materializers from the bootstrap.
 */
export function registerGovernanceProposalMaterializer(): void {
  registerMaterializer('governance-proposal', async (_ds: DataSource, ctx: { filters?: Record<string, unknown> | null }) => {
    const ref = ctx?.filters ?? {};
    if (!ref.proposalId) {
      throw new ExchangeError('denied', 'governance-proposal requires filters.proposalId');
    }
    return [{
      proposalId: ref.proposalId,
      communityUuid: ref.communityUuid,
      communityDid: ref.communityDid,
      proposalHash: ref.proposalHash,
      scope: ref.scope,
      requiredApproverCount: ref.requiredApproverCount,
      change: ref.change,
      expiresAt: ref.expiresAt,
    }] as Record<string, unknown>[];
  });
}

/**
 * Ceremony-event recordset materializer.
 *
 * A ceremony nudge is a REFERENCE, not content: `{ communityUuid, threadId, step }`. The agent re-reads
 * `/api/ceremony-log` for the log it renders, so this returns the ref verbatim — no cross-database read, and
 * nothing that could go stale.
 */
export function registerCeremonyEventMaterializer(): void {
  registerMaterializer('ceremony-event', async (_ds: DataSource, ctx: { filters?: Record<string, unknown> | null }) => {
    const ref = ctx?.filters ?? {};
    if (!ref.threadId) {
      throw new ExchangeError('denied', 'ceremony-event requires filters.threadId');
    }
    return [{
      threadId: ref.threadId,
      step: ref.step ?? null,
      // Present only once the ceremony has crystallized — before that there is no community to name, which is
      // exactly why the audience travels as `adminUuids` rather than being resolved from a community row.
      communityUuid: ref.communityUuid ?? null,
      at: ref.at ?? null,
    }] as Record<string, unknown>[];
  });
}

// ── Phase 6 — credential recordset (exchange:credential) ──────────────────
// Minted community-governed credentials (VMC/VEC/VWC) are fanned out to the
// subject's agent via the durable queue, exactly like vtc-membership. The
// queue stores only the credential uuid reference; the full credential is
// materialized at send time (buildCredentialPushData).
export interface CredentialPushData {
  credentialUuid: string;
  vcType: string;
  issuerIdentityUuid: string;
  subjectIdentityUuid: string;
  w3cVcJson: string | null;
  claim: string | null;
  status: string;
  validFrom: number;
  validUntil: number | null;
  credentialDigest: string | null;
  createdAt: number | null;
  issuerDid: string | null;
  subjectDid: string | null;
}

/** Build the full credential payload for a recipient agent at send time. */
export async function buildCredentialPushData(ds: DataSource, credentialUuid: string): Promise<CredentialPushData | null> {
  const row = await ds.get<{
    vc_type: string; issuer_identity_uuid: string; subject_identity_uuid: string;
    w3c_vc_json: string | null; claim: string | null; status: string;
    valid_from: number; valid_until: number | null; credential_digest: string | null;
    created_at: number | null;
  }>(
    `SELECT c.vc_type, c.issuer_identity_uuid, c.subject_identity_uuid,
            c.w3c_vc_json, c.claim, c.status, c.valid_from, c.valid_until,
            c.credential_digest, c.created_at
     FROM credentials c
     WHERE c.uuid = ?`,
    credentialUuid,
  );
  if (!row) return null;

  const issuer = await identitiesRepo.findByUuid(ds, row.issuer_identity_uuid);
  const subject = await identitiesRepo.findByUuid(ds, row.subject_identity_uuid);
  const issuerDid = issuer
    ? (await ds.get<{ did: string }>(
        `SELECT did FROM did_documents WHERE identity_uuid = ? AND is_primary = 1 LIMIT 1`,
        issuer.uuid,
      ))?.did ?? issuer.did ?? null
    : null;
  const subjectDid = subject
    ? (await ds.get<{ did: string }>(
        `SELECT did FROM did_documents WHERE identity_uuid = ? AND is_primary = 1 LIMIT 1`,
        subject.uuid,
      ))?.did ?? subject.did ?? null
    : null;

  return {
    credentialUuid,
    vcType: row.vc_type,
    issuerIdentityUuid: row.issuer_identity_uuid,
    subjectIdentityUuid: row.subject_identity_uuid,
    w3cVcJson: row.w3c_vc_json,
    claim: row.claim,
    status: row.status,
    validFrom: row.valid_from,
    validUntil: row.valid_until,
    credentialDigest: row.credential_digest,
    createdAt: row.created_at,
    issuerDid,
    subjectDid,
  };
}

/**
 * Enqueue one durable `credential` delivery per founding admin's VMC.
 *
 * Creating a community mints a VMC for every founding admin (see
 * src/services/vtc.ts → createVtc step 3) and records its uuid on the
 * membership row (`membership_credential_uuid`). This is the DELIVERY half of
 * the creation ceremony: the `credential` recordset fans out per credential —
 * AgentDeliveryQueue.targets() resolves a credential REF to its
 * `subject_identity_uuid`, and the payload is re-materialized at send time
 * (buildCredentialPushData), so a founding admin who is offline at creation
 * receives their VMC on reconnect. Idempotent per credential (`cred_<uuid>`),
 * so a ceremony retry / reconcile re-run never double-queues.
 *
 * Best-effort by design (mirrors the vtc-membership fan-out): the community is
 * already committed, so a queue that cannot accept the row must not fail the
 * ceremony. Returns the number of queue rows enqueued (0 when the engine is not
 * wired — e.g. boot-time VTN creation — or when no VMC was minted).
 *
 * Callers must enqueue this AFTER the `vtc-membership` fan-out: the queue drains
 * in created_at order, so the community package (identity + governance +
 * memberships, incl. the membership_credential_uuid link) lands before the
 * credential it references.
 */
export async function enqueueFoundingAdminVmcFanout(
  foundingAdmins: readonly Pick<MembershipRow, 'membershipCredentialUuid'>[],
): Promise<number> {
  let queued = 0;
  for (const admin of foundingAdmins) {
    const credentialUuid = admin.membershipCredentialUuid;
    if (!credentialUuid) continue;
    try {
      const result = await tryEnqueueFanout('credential', { credentialUuid });
      if (result) queued += result.queued;
    } catch (err) {
      console.warn(
        `[vtc-push-data] VMC delivery enqueue failed for credential ${credentialUuid}: ${(err as Error)?.message ?? err}`,
      );
    }
  }
  return queued;
}

/**
 * Wire the Phase 6 `credential` materializer into the catalog (server-side).
 * The materializer reads a single credential by `ctx.filters.credentialUuid`.
 */
export function registerCredentialMaterializer(): void {
  registerMaterializer('credential', async (ds: DataSource, ctx: {
    requester?: { uuid?: string; role?: string } | null;
    filters?: { credentialUuid?: string } | null;
  }) => {
    // Single credential by uuid — used by the queue-row delivery path.
    const credentialUuid = ctx?.filters?.credentialUuid;
    if (credentialUuid) {
      const row = await buildCredentialPushData(ds, credentialUuid);
      return row ? [row as unknown as Record<string, unknown>] : [];
    }

    // Phase F — requester-scoped pull (a holder refreshes their own wallet).
    // Self-only by construction, mirroring recovery/rcard.
    const requesterUuid = ctx?.requester?.uuid;
    if (!requesterUuid) {
      throw new ExchangeError('denied', 'credential requires filters.credentialUuid or a requester identity');
    }
    const owned = await ds.all<{ uuid: string }>(
      'SELECT uuid FROM credentials WHERE subject_identity_uuid = ? ORDER BY created_at DESC',
      requesterUuid,
    );
    const rows: Record<string, unknown>[] = [];
    for (const c of owned) {
      const row = await buildCredentialPushData(ds, c.uuid);
      if (row) rows.push(row as unknown as Record<string, unknown>);
    }
    return rows;
  });
}
