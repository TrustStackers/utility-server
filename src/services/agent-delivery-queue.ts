// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * AgentDeliveryQueue — general-purpose delivery queue for utility-server-to-agent
 * data pushes. This is the CRE `ExchangeFanoutStore` implementation: the engine
 * fans out a recordset by calling `targets()` + `enqueue()`, and the queue
 * drains `pending_agent_deliveries` rows, materializing each payload AT SEND TIME
 * via the catalog materializer (`getMaterialize`) — never a stored snapshot.
 *
 * The `op_type` column holds the wire op (`exchange:vtc-membership`,
 * `exchange:governance`, `exchange:credential`, …), so the queue is entirely
 * data-driven: any catalog recordset with queue-row delivery is delivered by
 * this same service — no per-feature queue code.
 *
 * Backoff: exponential with jitter, starting at 30s, max 24h, max 10 attempts.
 * Agent online detection: flushForMember() can be called when an agent connects.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { TransactionManager } from '@p2p-trust-stack/core/tx/manager.js';
import { RemoteParticipant } from '@p2p-trust-stack/core/tx/participant.js';
import type { ParticipantTransport } from '@p2p-trust-stack/core/tx/participant.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import * as governanceRepo from '@p2p-trust-stack/core/db/repositories/governance-repo.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import { getMaterialize } from '@p2p-trust-stack/core/exchange/catalog.js';
import { assertSafeProjection } from '@p2p-trust-stack/core/exchange/engine.js';
import type { ExchangeFanoutStore, RecordSetName } from '@p2p-trust-stack/core/exchange/types.js';
import { bumpWatermark } from '@p2p-trust-stack/core/exchange/watermark.js';

interface PendingDeliveryRow {
  uuid: string;
  member_uuid: string;
  member_peer_id: string | null;
  member_did: string | null;
  op_type: string;
  op_params_json: string;
  status: string;
  attempts: number;
  max_attempts: number;
  last_error: string | null;
  next_retry_at: number | null;
  idempotency_key: string | null;
}

function calculateNextRetry(attempts: number): number {
  const baseDelayMs = 30_000;
  const maxDelayMs = 86_400_000;
  const delay = Math.min(baseDelayMs * Math.pow(2, attempts - 1), maxDelayMs);
  const jitter = delay * (0.8 + Math.random() * 0.4);
  return Math.floor(Date.now() / 1000) + Math.floor(jitter / 1000);
}

export class AgentDeliveryQueue implements ExchangeFanoutStore {
  private timer: ReturnType<typeof setInterval> | null = null;
  private readonly db: DataSource;
  private readonly manager: TransactionManager;
  private readonly transport: ParticipantTransport;
  private readonly intervalMs: number;
  private readonly watermark?: DataSource;
  /**
   * Event-fed connected-peer cache: maintained by markPeerConnected /
   * markPeerDisconnected (libp2p peer:connect / peer:disconnect). Used as the
   * primary reachability source when no transport check is available, and kept
   * reconciled with the authoritative connection table on every drain.
   */
  private readonly connectedPeers = new Set<string>();

  constructor(
    db: DataSource,
    manager: TransactionManager,
    transport: ParticipantTransport,
    intervalMs = 5_000,
    watermark?: DataSource,
  ) {
    this.db = db;
    this.manager = manager;
    this.transport = transport;
    this.intervalMs = intervalMs;
    this.watermark = watermark;
  }

  /**
   * ExchangeFanoutStore.targets — resolve the active member identity uuids that
   * a recordset fan-out ref addresses:
   *   - vtc-membership / governance → active members of `ref.communityUuid`
   *   - credential                 → the credential's subject identity
   */
  async targets(name: RecordSetName, ref: Record<string, unknown>): Promise<string[]> {
    if (name === 'vtc-membership' || name === 'governance') {
      const communityUuid = String(ref.communityUuid ?? '');
      if (!communityUuid) return [];
      const community = await identitiesRepo.findByUuid(this.db, communityUuid);
      if (!community) return [];
      const members = await membershipsRepo.findForCommunity(this.db, community.uuid);
      return members.filter((m) => m.status === 'active').map((m) => m.memberIdentityUuid);
    }
    if (name === 'governance-proposal') {
      // The required approver set is resolved by the server participant and carried on
      // the REF (the proposal lives in tx-coordinator.db, which this queue cannot read).
      const uuids = ref.approverUuids;
      if (!Array.isArray(uuids)) return [];
      return uuids.filter((u): u is string => typeof u === 'string' && u.length > 0);
    }
    if (name === 'ceremony-event') {
      // A ceremony nudge goes to the DECLARED FOUNDING ADMINS — the people who can co-sign it, and the ones
      // watching a founding. The audience is carried on the REF rather than derived from a community row,
      // because BEFORE crystallization there IS no community identity: the ceremony is what creates it.
      // (`proposal.adminUuids`, the same set the quorum is measured against.)
      const uuids = ref.adminUuids;
      if (!Array.isArray(uuids)) return [];
      return uuids.filter((u): u is string => typeof u === 'string' && u.length > 0);
    }
    if (name === 'credential') {
      const credentialUuid = String(ref.credentialUuid ?? '');
      if (!credentialUuid) return [];
      const row = await this.db.get<{ subject_identity_uuid: string }>(
        `SELECT subject_identity_uuid FROM credentials WHERE uuid = ?`,
        credentialUuid,
      );
      return row ? [row.subject_identity_uuid] : [];
    }
    return [];
  }

  /**
   * ExchangeFanoutStore.idempotencyKey — durable per-member key kept compatible
   * with the legacy enqueue scheme so re-runs remain no-ops:
   *   vtc-membership → `vtc_<community>_<member>`
   *   governance     → `gov_<community>_<member>_<updatedAt>` (policy-versioned)
   *   credential     → `cred_<credentialUuid>`
   */
  async idempotencyKey(name: RecordSetName, ref: Record<string, unknown>, memberUuid: string): Promise<string> {
    const communityUuid = String(ref.communityUuid ?? '');
    if (name === 'vtc-membership') {
      // Version the key by the community's roster shape (member count + last
      // activated timestamp) so ANY roster change — a new member accepting an
      // invite, or a member leaving — re-enqueues fresh deliveries to pre-existing
      // members instead of being dropped by the UNIQUE(idempotency_key)
      // constraint. Mirrors the governance key versioning.
      const row = await this.db.get<{ maxIssued: number | null; count: number }>(
        `SELECT MAX(issued_at) AS max_issued, COUNT(*) AS count
         FROM memberships WHERE community_identity_uuid = ?`,
        communityUuid,
      );
      return `vtc_${communityUuid}_${memberUuid}_${row?.maxIssued ?? 0}_${row?.count ?? 0}`;
    }
    if (name === 'governance') {
      const governance = await governanceRepo.findForCommunity(this.db, communityUuid);
      const updatedAt = governance?.updatedAt ?? Math.floor(Date.now() / 1000);
      return `gov_${communityUuid}_${memberUuid}_${updatedAt}`;
    }
    if (name === 'credential') {
      return `cred_${String(ref.credentialUuid ?? '')}`;
    }
    if (name === 'governance-proposal') {
      // One row per (proposal, approver) PER APPROVAL STATE.
      //
      // The proposal is immutable, but its PROGRESS is not: a partial approval has to reach the other
      // approvers so the Rules page's "1 of 2 verified" can update. Keying on the proposal alone would collide
      // with the BEGIN fan-out on UNIQUE(idempotency_key) and the progress nudge would never be delivered —
      // the same reason `vtc-membership` versions by roster shape and `governance` by `updatedAt`.
      //
      // `progressVersion` is supplied by the caller that KNOWS the new state (the approve handler, which holds
      // the approval list). The begin path omits it and keeps the stable `0` form, so BEGIN still enqueues
      // exactly one row per (proposal, approver).
      const version = ref.progressVersion ?? 0;
      return `govprop_${String(ref.proposalId ?? '')}_${memberUuid}_${version}`;
    }
    if (name === 'ceremony-event') {
      // Versioned by the STEP. A thread-only key would collide on UNIQUE(idempotency_key) for every step after
      // the first, and `enqueue` swallows a UNIQUE violation SILENTLY — so the nudge would never arrive and
      // nothing would say so. That is the same trap the governance-proposal progress nudge hit.
      return `ceremony_${String(ref.threadId ?? '')}_${String(ref.step ?? '')}_${memberUuid}`;
    }
    return `exchange:${name}:${memberUuid}`;
  }

  /**
   * ExchangeFanoutStore.enqueue — insert one durable pending row for a member.
   * `op_type` is `exchange:<name>` (the catalog wire op); `op_params_json` stores
   * ONLY the REF — the payload is materialized by deliverOne at send time.
   */
  async enqueue(
    name: RecordSetName,
    memberUuid: string,
    ref: Record<string, unknown>,
    idempotencyKey: string,
  ): Promise<void> {
    const adminIdentity = await identitiesRepo.findByUuid(this.db, memberUuid);
    let memberPeerId: string | null = null;
    if (adminIdentity) {
      const pe = await this.db.get<{ peer_id: string }>(
        `SELECT peer_id FROM peer_endpoints
         WHERE identity_uuid = ? AND is_active = 1
         ORDER BY updated_at DESC, created_at DESC LIMIT 1`,
        memberUuid,
      );
      memberPeerId = pe?.peer_id ?? null;
    }
    const now = Math.floor(Date.now() / 1000);
    try {
      const rowUuid = generateUuid();
      await this.db.run(
        `INSERT INTO pending_agent_deliveries
           (uuid, member_uuid, member_peer_id, member_did,
            op_type, op_params_json, status, max_attempts,
            idempotency_key, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, 'pending', 10, ?, ?, ?)`,
        rowUuid,
        memberUuid,
        memberPeerId,
        adminIdentity?.did ?? null,
        `exchange:${name}`,
        JSON.stringify(ref),
        idempotencyKey,
        now,
        now,
      );
    } catch (insertErr) {
      const msg = (insertErr as Error)?.message ?? '';
      if (!msg.includes('UNIQUE')) {
        console.error(`[AgentDeliveryQueue] enqueue error (${name}):`, msg);
      }
    }
  }

  start(): void {
    if (this.timer) return;
    console.log(`[AgentDeliveryQueue] starting (interval=${this.intervalMs}ms)`);
    // D-1 boot migration must finish BEFORE the first drain, or legacy rows would
    // be delivered under their old op names (deliverOne resolves by catalog op).
    void this.migrateLegacyOpTypes()
      .catch((err) =>
        console.error('[AgentDeliveryQueue] op_type migration error:', (err as Error)?.message ?? err),
      )
      .then(() => this.drain().catch(err =>
        console.error('[AgentDeliveryQueue] initial drain error:', (err as Error)?.message ?? err),
      ));
    this.timer = setInterval(() => this.drain(), this.intervalMs);
  }

  stop(): void {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
  }

  /**
   * Event-fed connectivity signals (libp2p peer:connect / peer:disconnect —
   * wired in utility-server/index.ts). The connected-peer cache lets the drain
   * skip provably-offline members with zero work, and the peer:connect flush
   * path delivers immediately without re-checking the connection table.
   */
  markPeerConnected(peerId: string): void {
    this.connectedPeers.add(peerId);
    void this.drain();
  }

  markPeerDisconnected(peerId: string): void {
    this.connectedPeers.delete(peerId);
  }

  /** Whether a peerId is currently in the event-fed connected set. */
  isPeerConnected(peerId: string): boolean {
    return this.connectedPeers.has(peerId);
  }

  async drain(): Promise<void> {
    try {
      const now = Math.floor(Date.now() / 1000);
      const pending = await this.db.all<PendingDeliveryRow>(
        `SELECT * FROM pending_agent_deliveries
         WHERE status = 'pending'
           AND (next_retry_at IS NULL OR next_retry_at <= ?)
         ORDER BY created_at ASC LIMIT 50`,
        now,
      );
      if (pending.length === 0) return;
      for (const row of pending) await this.deliverOne(row);
    } catch (err) {
      console.error('[AgentDeliveryQueue] drain error:', (err as Error)?.message ?? err);
    }
  }

  async flushForMember(memberUuid: string): Promise<void> {
    try {
      // Recover any permanently-failed deliveries for this member: when the agent
      // is reachable again (reconnect), a previous maxed-out queue entry becomes
      // valid and should be retried rather than left dead.
      await this.db.run(
        `UPDATE pending_agent_deliveries
         SET status = 'pending', next_retry_at = NULL
         WHERE member_uuid = ? AND status = 'failed'`, memberUuid,
      );

      const pending = await this.db.all<PendingDeliveryRow>(
        `SELECT * FROM pending_agent_deliveries
         WHERE member_uuid = ? AND status = 'pending'
         ORDER BY created_at ASC`, memberUuid,
      );
      if (pending.length === 0) return;
      // force=true — this is the peer:connect flush; we just observed the peer
      // come up, so skip the reachability gate (the send outcome check below
      // remains the authoritative source of truth).
      for (const row of pending) await this.deliverOne(row, { force: true });
    } catch (err) {
      console.error(`[AgentDeliveryQueue] flush error:`, (err as Error)?.message ?? err);
    }
  }

  /**
   * Deliver one pending row to its member.
   *
   * Connectivity-gated (Phase 8): the member's trustworthy peer is resolved and
   * the peer's reachability checked BEFORE any attempt is consumed or any catalog
   * materialization runs. For an offline member each drain costs only a couple of
   * indexed lookups + one O(1) connection-table check — never a 15s transport
   * poll, a backoff burn, or a payload build.
   *
   * @param opts.force Set on the reconnect-flush path (peer:connect): skip the
   *                   gate because we just observed the peer come up. The send
   *                   outcome check remains authoritative either way.
   */
  private async deliverOne(row: PendingDeliveryRow, opts: { force?: boolean } = {}): Promise<void> {
    // 1) Resolve the member's CURRENT reachable transport peer FIRST using
    //    trustworthy sources ONLY (cheap indexed queries):
    //      1. a live established relationship's remote_transport peer (the agent
    //         itself connected — carries the current peer, survives restart),
    //      2. the member's OWN identities.peer_id — but only if it is not shared
    //         with a DIFFERENT member (guards against an offline co-admin whose
    //         peer was mis-populated with the creator's peer being delivered to
    //         the wrong agent).
    //    The enqueue-time snapshot (row.member_peer_id) is never used: peerId is
    //    not a stable identity after restart, so a stale/wrong snapshot must not
    //    produce a misleading 'delivered'.
    const peerId = await this.resolveReachablePeerId(row.member_uuid);
    if (!peerId) {
      // No trustworthy peer — the member never registered a stable endpoint.
      // Leave the row pending; the peer:connect flush or a future drain will
      // pick it up. Zero cost on the blind timer.
      return;
    }

    // 2) Connectivity gate — skip WITHOUT consuming an attempt when the peer is
    //    provably unreachable (or absent from the event-fed set when no live
    //    connection-table check is available). The row stays 'pending' and is
    //    delivered by the peer:connect flush or the next drain once reachable.
    if (!opts.force && !this.isPeerReachable(peerId)) {
      return;
    }

    const now = Math.floor(Date.now() / 1000);
    // 3) Consume the attempt ONLY now that the peer is reachable. Check the
    //    affected-row count: if the claim UPDATE affected 0 rows, another
    //    deliverer (timer drain + peer:connect drain can run concurrently) already
    //    took this row — early-return without touching it.
    const claim = await this.db.run(
      `UPDATE pending_agent_deliveries
       SET status = 'in_flight', attempts = attempts + 1, updated_at = ?
       WHERE uuid = ? AND status = 'pending'`, now, row.uuid);
    if (claim.changes === 0) {
      return;
    }

    try {
      // The queue stores only a PENDING SEND STATE (a REF: communityUuid /
      // credentialUuid), never a full payload snapshot. At send time, the
      // payload is re-materialized through the CRE catalog materializer for
      // the op's recordset — so a delivery that becomes valid on reconnect
      // always transmits up-to-date data (invariant 1).
      const name = recordSetForOpType(row.op_type);
      if (!name) {
        throw new Error(`unknown exchange op_type '${row.op_type}' (uuid=${row.uuid})`);
      }
      const ref = JSON.parse(row.op_params_json) as Record<string, unknown>;
      const materialize = getMaterialize(name);
      const requester = { realDid: row.member_did ?? `uuid:${row.member_uuid}`, uuid: row.member_uuid, role: 'vta' };
      const rows = await materialize(this.db, { requester, filters: ref });
      assertSafeProjection(rows, name);
      // Fan-out recordsets are single-row payloads (one community / one
      // credential); rows[0] is the VtcPushData / GovernancePushData /
      // CredentialPushData transmitted on the wire.
      const payload = rows[0];
      if (!payload) {
        throw new Error(`${name} delivery materialized nothing (uuid=${row.uuid})`);
      }
      const vid = await this.resolveVidForMember(row.member_uuid);
      const remote = new RemoteParticipant(`peer:${vid}:${peerId}`, this.transport);
      const result = await this.manager.run(async (tx) => {
        tx.enlist(remote, [{ op: row.op_type, params: payload }]);
      });

      // Only mark 'delivered' when the transaction actually COMMITTED to the
      // agent. If it didn't (aborted / timed out), treat as a failure so the row
      // stays pending and is retried on the next drain or reconnect flush —
      // never a spurious 'delivered' that skips delivery to the real member.
      if (result.outcome !== 'committed') {
        throw new Error(`delivery tx ${String(result.txId).slice(0, 8)} not committed (outcome=${result.outcome})`);
      }

      await this.db.run(
        `UPDATE pending_agent_deliveries
         SET status = 'delivered', updated_at = ?
         WHERE uuid = ?`, now, row.uuid);

      // Phase 5 — server-side watermark parity: record the successful handoff
      // per (recordset, member) so the server has the same last-synced signal the
      // agent uses for ack-gating. The queue row remains the delivery truth; the
      // watermark is observability + future periodic-driver input.
      if (this.watermark) {
        try {
          await bumpWatermark(this.watermark, name, `member:${row.member_uuid}`);
        } catch (wmErr) {
          console.warn(`[AgentDeliveryQueue] watermark bump failed: ${(wmErr as Error)?.message ?? wmErr}`);
        }
      }
    } catch (err) {
      const nextRetry = calculateNextRetry(row.attempts);
      const isFinal = row.attempts >= row.max_attempts;
      await this.db.run(
        `UPDATE pending_agent_deliveries
         SET status = ?, last_error = ?, next_retry_at = ?, updated_at = ?
         WHERE uuid = ?`,
        isFinal ? 'failed' : 'pending',
        (err as Error)?.message ?? String(err),
        isFinal ? null : nextRetry,
        now,
        row.uuid);
    }
  }

  /** Resolve a member's current trustworthy transport peerId (or null). */
  private async resolveReachablePeerId(memberUuid: string): Promise<string | null> {
    // Best-effort lookups: a failure to resolve (e.g. a DB engine that can't run
    // the PostgreSQL-style remote_transport::jsonb query, as in unit tests)
    // degrades to null and we fall through to the next source — the authoritative
    // send-outcome check still guards correctness.
    let livePeer: string | null = null;
    try {
      livePeer = await this.resolveLivePeerIdForMember(memberUuid);
    } catch (err) {
      console.warn(`[AgentDeliveryQueue] live-peer lookup failed for ${memberUuid.slice(0, 8)}: ${(err as Error)?.message ?? err}`);
    }
    let selfPeer: string | null = null;
    try {
      selfPeer = await this.resolveCurrentPeerIdForMember(memberUuid);
    } catch (err) {
      console.warn(`[AgentDeliveryQueue] self-peer lookup failed for ${memberUuid.slice(0, 8)}: ${(err as Error)?.message ?? err}`);
    }

    let peerId = livePeer;
    if (!peerId && selfPeer && !(await this.isPeerSharedWithAnotherMember(memberUuid, selfPeer))) {
      peerId = selfPeer;
    }
    return peerId;
  }

  /**
   * Reachability gate — the libp2p connection table is authoritative when a
   * transport is wired (`transport.isConnected`, an O(1) connection-table look
   * up); the event-fed connected set is reconciled as we go so it stays accurate
   * for the flush fast-path and observability. When no transport check is
   * available, the event-fed set is the source of truth.
   */
  private isPeerReachable(peerId: string): boolean {
    // Optional-call form — NOT an extracted bare invocation. `transport.isConnected`
    // is a prototype method that dereferences `this` (TspParticipantTransport reads
    // `this.isConnectedFn`), so it must be called with `transport` as its receiver.
    // `transport?.isConnected?.(...)` preserves the receiver; an extracted
    // `const fn = transport.isConnected; fn(...)` would make `this` undefined and
    // throw `Cannot read properties of undefined (reading 'isConnectedFn')`.
    const up = this.transport?.isConnected?.(`peer:${peerId}`);
    if (up === undefined) {
      // No connectivity checker wired — the event-fed set is the source of truth.
      return this.connectedPeers.has(peerId);
    }
    if (up) this.connectedPeers.add(peerId);
    else this.connectedPeers.delete(peerId);
    return up;
  }

  private async resolveVidForMember(memberUuid: string): Promise<string> {
    // The TSP v3 VID is the member's DID string (not the CESR-encoded Ed25519
    // key, which was the v2 VID). Resolve the member's primary DID from
    // did_documents so the `peer:{vid}:{peerId}` pid and the sealed message's
    // vidReceiver use the DID the agent actually keys its relationship by.
    const docRow = await this.db.get<{ did: string }>(
      `SELECT d.did FROM did_documents d
       WHERE d.identity_uuid = ? AND d.is_primary = 1
       ORDER BY d.created_at DESC LIMIT 1`, memberUuid,
    );
    if (docRow?.did) {
      return docRow.did;
    }
    return memberUuid;
  }

  /**
   * Resolve an agent's CURRENT reachable libp2p peerId from the established
   * relationships recorded on the utility server. identities.peer_id can go
   * stale (the agent's peer may differ from what was stored at ceremony time),
   * but relationships.remote_transport is kept live by the TSP handshake.
   *
   * An agent is usually represented by TWO identity rows sharing the same
   * Ed25519 key: a did:peer:4 relationship stub (which carries the live
   * remote_transport) and the real did:scid:vh identity (which is the member
   * row in pending_agent_deliveries). We join to the stub via the shared key
   * and read its remote_transport.peerId.
   *
   * Returns null when no live peer can be determined (agent has no established
   * relationship, or the stub has no transport) — callers fall back to the
   * stored member_peer_id.
   */
  private async resolveLivePeerIdForMember(memberUuid: string): Promise<string | null> {
    const row = await this.db.get<{ peer_id: string | null }>(
      `SELECT r.remote_transport::jsonb ->> 'peerId' AS peer_id
       FROM relationships r
       JOIN identities stub ON stub.uuid = r.remote_identity_uuid
       JOIN keys stub_key ON stub_key.identity_uuid = stub.uuid
                         AND stub_key.key_type = 'ed25519'
       JOIN identities member ON member.uuid = ?
       JOIN keys member_key ON member_key.identity_uuid = member.uuid
                          AND member_key.key_type = 'ed25519'
       WHERE stub_key.public_key = member_key.public_key
         AND r.direction = 'bidirectional'
         AND r.status = 'established'
         AND r.remote_transport IS NOT NULL
       ORDER BY stub.created_at, stub.uuid DESC
       LIMIT 1`,
      memberUuid,
    );
    return row?.peer_id ?? null;
  }

  /**
   * Resolve the member's CURRENT peer from the ACTIVE peer_endpoints row. The
   * real VTA identity's endpoint is recorded on every agent connect/reconnect,
   * so this reflects a peerId changed by restart. It is more authoritative
   * than the enqueue-time snapshot in pending_agent_deliveries.member_peer_id,
   * which can be stale or wrong.
   */
  private async resolveCurrentPeerIdForMember(memberUuid: string): Promise<string | null> {
    const row = await this.db.get<{ peer_id: string }>(
      `SELECT peer_id FROM peer_endpoints
       WHERE identity_uuid = ? AND is_active = 1
       ORDER BY updated_at DESC, created_at DESC LIMIT 1`,
      memberUuid,
    );
    return row?.peer_id ?? null;
  }

  /**
   * Whether a peerId is currently ACTIVE on a DIFFERENT identity than this
   * member. Used to detect a wrongly-populated peer (an offline co-admin whose
   * peer was, e.g., the creator's peer) so we never deliver to the wrong agent.
   */
  private async isPeerSharedWithAnotherMember(memberUuid: string, peerId: string): Promise<boolean> {
    const row = await this.db.get<{ uuid: string }>(
      `SELECT uuid FROM peer_endpoints
       WHERE identity_uuid <> ? AND peer_id = ? AND is_active = 1 LIMIT 1`,
      memberUuid,
      peerId,
    );
    return row !== null;
  }

  /**
   * Boot migration (D-1): rewrite legacy `op_type` values on rows left in the
   * queue by a pre-CRE-completion server to the catalog wire ops, so deliverOne
   * can resolve every row through the catalog. Runs once at start() (before the
   * first drain) and is public so tests / tooling can run it deterministically.
   */
  async migrateLegacyOpTypes(): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    await this.db.run(
      `UPDATE pending_agent_deliveries
       SET op_type = 'exchange:vtc-membership', updated_at = ?
       WHERE op_type = 'receive_vtc' AND status IN ('pending', 'failed')`,
      now,
    );
    await this.db.run(
      `UPDATE pending_agent_deliveries
       SET op_type = 'exchange:credential', updated_at = ?
       WHERE op_type = 'receive_credential' AND status IN ('pending', 'failed')`,
      now,
    );
  }
}

/**
 * Map a queue row's `op_type` to its catalog recordset name. Rows created by
 * this workstream carry `exchange:<name>` directly; legacy `receive_*` values
 * are tolerated for robustness (boot migration rewrites them at start()).
 */
export function recordSetForOpType(opType: string): RecordSetName | null {
  if (opType.startsWith('exchange:')) {
    const name = opType.slice('exchange:'.length);
    return ['identity', 'rcard', 'vtc-membership', 'governance', 'governance-proposal', 'governance-events', 'credential', 'registry', 'recovery', 'witness-endorsement']
      .includes(name)
      ? (name as RecordSetName)
      : null;
  }
  if (opType === 'receive_vtc') return 'vtc-membership';
  if (opType === 'receive_credential') return 'credential';
  return null;
}

/**
 * Resolve the member (agent) UUID that owns a given libp2p transport peerId.
 *
 * Reverse of resolveLivePeerIdForMember: a live relationships row carries the
 * agent's current reachable peerId (remote_transport -> 'peerId'), pointing at the
 * did:peer:4 TSP-bridge stub identity. The stub shares an Ed25519 public key with
 * the agent's authoritative did:scid:vh VTA identity, which is the member row used
 * in pending_agent_deliveries. Used to trigger flushForMember() when an agent's
 * transport peer reconnects to the utility server.
 *
 * Returns null when no member can be determined for the peerId.
 */
export async function resolveMemberUuidForPeerId(ds: DataSource, peerId: string): Promise<string | null> {
  // Primary: the ACTIVE peer_endpoints row — a peer_id is the physical node key
  // of exactly one identity, so this is the authoritative reverse mapping.
  const endpoint = await ds.get<{ identity_uuid: string }>(
    `SELECT identity_uuid FROM peer_endpoints
     WHERE peer_id = ? AND is_active = 1 LIMIT 1`,
    peerId,
  );
  if (endpoint) {
    const member = await ds.get<{ uuid: string }>(
      `SELECT uuid FROM identities WHERE uuid = ? AND role = 'vta'`,
      endpoint.identity_uuid,
    );
    if (member?.uuid) return member.uuid;
  }

  // Fallback: a live relationships row carries the agent's current reachable
  // peerId (remote_transport -> 'peerId'), pointing at the did:peer:4 TSP-bridge
  // stub identity. The stub shares an Ed25519 public key with the agent's
  // authoritative did:scid:vh VTA identity, which is the member row used
  // in pending_agent_deliveries. Used to trigger flushForMember() when an
  // agent's transport peer reconnects to the utility server.
  const row = await ds.get<{ member_uuid: string }>(
    `SELECT member.uuid AS member_uuid
     FROM relationships r
     JOIN identities stub ON stub.uuid = r.remote_identity_uuid
     JOIN keys stub_key ON stub_key.identity_uuid = stub.uuid
                       AND stub_key.key_type = 'ed25519'
     JOIN keys member_key ON member_key.public_key = stub_key.public_key
                        AND member_key.key_type = 'ed25519'
     JOIN identities member ON member.uuid = member_key.identity_uuid
     WHERE r.remote_transport::jsonb ->> 'peerId' = ?
       AND r.direction = 'bidirectional'
       AND r.status = 'established'
       AND member.uuid <> stub.uuid
       AND member.role = 'vta'
     ORDER BY member.created_at, member.uuid
     LIMIT 1`,
    peerId,
  );
  return row?.member_uuid ?? null;
}
