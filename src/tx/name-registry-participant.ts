// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Name Registry Participant — wraps the name_register two-phase commit logic
 * as a TransactionCoordinator Participant.
 *
 * Handles 'name_register' and 'name_revoke' operations with a clean 2PC split:
 *
 *   prepare():  SELECT only — checks availability / ownership, verifies proof.
 *               No INSERT/UPDATE.  Records 'prepared' in tx_participant_state.
 *               Stashes operation params in undo_hooks for commit() retrieval.
 *
 *   commit():   SERIALIZABLE transaction — re-check + INSERT/UPDATE.
 *               Stores DID document in did_documents for backup/restoration.
 *               Marks 'committed'.
 *
 *   abort():    No cleanup needed (no writes were done in prepare).
 *               Marks 'aborted'.
 *
 * This split is safe for multi-YugabyteDB utility server clusters because:
 *   1. prepare() is a pure read — no write contention between servers
 *   2. The UNIQUE(namespace, name) constraint + SERIALIZABLE isolation in
 *      commit() guarantees exactly one winner across all servers
 *   3. The loser's commit() throws, the coordinator records the abort, and
 *      the agent's speculative rotation is discarded
 *
 * This replaces the legacy TspRequestStateMachine handler
 * (name-registry-server.ts) with a coordinator participant.
 *
 * pid: 'server:{serverId}' — identifies this as a utility server participant.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type {
  Operation,
  Outcome,
  Participant,
  Vote,
} from '@p2p-trust-stack/core/tx/types.js';
import { buildNameUri } from '@p2p-trust-stack/core/did/name-uri.js';
import type { DidDocument } from '@p2p-trust-stack/core/did/types.js';
import type { Vrc } from '@p2p-trust-stack/core/vtc/types.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import { getNamespaceConfig } from '../services/namespace-service.js';

/** Parameters for a name_register operation. */
export interface NameRegisterOpParams {
  namespace: string;
  name: string;
  did: string;
  profileUuid?: string;
  /**
   * Label of the profile to attach as this name's primary R-Card. The agent
   * passes the label (not a numeric id, which differs between agent and server
   * DBs). Resolved server-side at commit time — see commitNameRegistration.
   * Falls back to the identity's default profile when omitted.
   */
  primaryProfileLabel?: string;
  proof?: {
    type: 'alsoKnownAs' | 'vrc' | 'utility_managed';
    vrc?: Vrc;
  };
  /** The agent's DID document (with the name in alsoKnownAs) — stored for backup. */
  didDocument?: object;
}

/** Parameters for a name_revoke operation. */
export interface NameRevokeOpParams {
  namespace: string;
  name: string;
  did: string;
  proof?: { type: string; didDocument?: object };
}

/**
 * A Participant that handles name_register and name_revoke operations.
 *
 * prepare() performs availability/ownership checks and proof verification
 * (read-only).  commit() does the SERIALIZABLE INSERT/UPDATE.  abort() is
 * a no-op beyond marking the state.
 */
export class NameRegistryParticipant implements Participant {
  readonly pid: string;
  private readonly appDb: DataSource;   // YugabyteDB (application data)
  private readonly txDb: DataSource;    // SQLite (tx-coordinator.db)

  constructor(pid: string, appDb: DataSource, txDb: DataSource) {
    this.pid = pid;
    this.appDb = appDb;
    this.txDb = txDb;
  }

  handlesOperation(op: Operation): boolean {
    return op.op === 'name_register' || op.op === 'name_revoke';
  }

  // -----------------------------------------------------------------------
  // prepare() — read-only: check availability / ownership, verify proof
  // -----------------------------------------------------------------------

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    const stashedParams: Array<{ op: string; params: unknown }> = [];

    for (const op of operations) {
      if (op.op === 'name_register') {
        const p = op.params as unknown as NameRegisterOpParams;
        if (!p || !p.namespace || !p.name || !p.did) {
          console.log(`[name-registry-participant] prepare: missing required params for name_register`);
          return 'no';
        }

        try {
          // ── Namespace enforcement (only when a namespace is configured) ─
          // Names may only be registered inside the namespace this utility
          // server serves (the namespace VTN's namespace). The legacy
          // hardwired 'p2pts' default is rejected once a namespace is configured
          // — agents must use vta:<configured-namespace>:<name>. When no
          // namespace is configured (or namespace_config is absent, e.g.
          // legacy/edge deployments), registration is allowed as before.
          try {
            const nsCfg = await getNamespaceConfig(this.appDb);
            if (nsCfg && nsCfg.namespace !== p.namespace) {
              console.log(
                `[name-registry-participant] prepare: namespace '${p.namespace}' not served ` +
                `(configured: ${nsCfg.namespace})`,
              );
              return 'no';
            }
          } catch {
            // namespace_config table missing → no enforcement.
          }

          // ── Check availability (SELECT only, no INSERT) ──────────────
          const existing = await this.appDb.get<{ did: string }>(
            `SELECT did FROM name_registry
             WHERE namespace = ? AND name = ? AND revoked_at IS NULL`,
            p.namespace,
            p.name,
          );

          if (existing) {
            console.log(
              `[name-registry-participant] prepare: name '${p.namespace}:${p.name}' ` +
              `already taken by ${existing.did}`,
            );
            return 'no';
          }

          // ── Verify proof (read-only) ─────────────────────────────────
          const proofType = p.proof?.type ?? 'utility_managed';
          if (proofType === 'alsoKnownAs') {
            const nameUri = buildNameUri(p.namespace, p.name);
            let doc: DidDocument | null = null;
            if (p.didDocument && typeof p.didDocument === 'object') {
              doc = p.didDocument as DidDocument;
            } else {
              const docRow = await this.appDb.get<{ document_json: string }>(
                'SELECT document_json FROM did_documents WHERE did = ? AND is_primary = 1',
                p.did,
              );
              if (!docRow) {
                console.log(`[name-registry-participant] prepare: proof failed — DID ${p.did} not found`);
                return 'no';
              }
              doc = JSON.parse(docRow.document_json) as DidDocument;
            }

            const alsoKnownAs = doc.alsoKnownAs ?? [];
            if (!alsoKnownAs.includes(nameUri)) {
              console.log(
                `[name-registry-participant] prepare: proof failed — ` +
                `name '${nameUri}' not in alsoKnownAs`,
              );
              return 'no';
            }
            console.log(`[name-registry-participant] prepare: alsoKnownAs proof verified`);
          } else if (proofType === 'vrc') {
            if (!p.proof?.vrc) {
              console.log(`[name-registry-participant] prepare: proof failed — vrc proof requires vrc credential`);
              return 'no';
            }
            const docRow = await this.appDb.get<{ document_json: string }>(
              'SELECT document_json FROM did_documents WHERE did = ? AND is_primary = 1',
              p.did,
            );
            if (!docRow) {
              console.log(`[name-registry-participant] prepare: proof failed — DID ${p.did} not found`);
              return 'no';
            }
            const doc = JSON.parse(docRow.document_json) as DidDocument;
            const { verifyNameClaim } = await import('@p2p-trust-stack/core/did/name-vrc.js');
            if (!verifyNameClaim(p.proof.vrc, doc)) {
              console.log(`[name-registry-participant] prepare: proof failed — VRC signature invalid`);
              return 'no';
            }
            console.log(`[name-registry-participant] prepare: VRC proof verified`);
          }
          // utility_managed — accept without verification

          console.log(
            `[name-registry-participant] prepare: name '${p.namespace}:${p.name}' ` +
            `available for DID ${p.did}`,
          );

          // Stash params for commit()
          stashedParams.push({ op: 'name_register', params: p });
        } catch (err) {
          console.error(
            `[name-registry-participant] prepare error for tx ${txId}:`,
            (err as Error)?.message,
          );
          return 'no';
        }
      } else if (op.op === 'name_revoke') {
        const p = op.params as unknown as NameRevokeOpParams;
        if (!p || !p.namespace || !p.name || !p.did) {
          console.log(`[name-registry-participant] prepare: missing required params for name_revoke`);
          return 'no';
        }

        try {
          // ── Check ownership (SELECT only, no UPDATE) ─────────────────
          const existing = await this.appDb.get<{ did: string }>(
            `SELECT did FROM name_registry
             WHERE namespace = ? AND name = ? AND revoked_at IS NULL`,
            p.namespace,
            p.name,
          );

          if (!existing) {
            console.log(
              `[name-registry-participant] prepare: name '${p.namespace}:${p.name}' ` +
              `not found — cannot revoke`,
            );
            return 'no';
          }

          if (existing.did !== p.did) {
            console.log(
              `[name-registry-participant] prepare: name '${p.namespace}:${p.name}' ` +
              `owned by ${existing.did}, not ${p.did} — cannot revoke`,
            );
            return 'no';
          }

          console.log(
            `[name-registry-participant] prepare: name '${p.namespace}:${p.name}' ` +
            `owned by ${p.did} — eligible for revocation`,
          );

          // Stash params for commit()
          stashedParams.push({ op: 'name_revoke', params: p });
        } catch (err) {
          console.error(
            `[name-registry-participant] revoke prepare error for tx ${txId}:`,
            (err as Error)?.message,
          );
          return 'no';
        }
      }
    }

    // Durably record 'prepared' BEFORE voting yes.
    // Stash the operation params in undo_hooks so commit() can retrieve them.
    await this.txDb.run(
      `INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome, undo_hooks)
       VALUES (?, ?, 'prepared', ?)`,
      txId,
      this.pid,
      JSON.stringify(stashedParams),
    );

    console.log(
      `[name-registry-participant] ${txId.slice(0, 8)} prepared → voting yes ` +
      `(${stashedParams.length} op(s))`,
    );
    return 'yes';
  }

  // -----------------------------------------------------------------------
  // commit() — SERIALIZABLE INSERT/UPDATE + store DID document for backup
  // -----------------------------------------------------------------------

  async commit(txId: string): Promise<void> {
    // Retrieve the stashed params from the participant state.
    const stateRow = await this.txDb.get<{ undo_hooks: string | null }>(
      `SELECT undo_hooks FROM tx_participant_state WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );

    let stashedParams: Array<{ op: string; params: unknown }> = [];
    if (stateRow?.undo_hooks) {
      try {
        stashedParams = JSON.parse(stateRow.undo_hooks);
      } catch { /* ignore parse errors */ }
    }

    if (stashedParams.length === 0) {
      console.log(
        `[name-registry-participant] commit: no stashed params for tx ${txId} — ` +
        `skipping`,
      );
      await this.txDb.run(
        `UPDATE tx_participant_state SET outcome = 'committed'
         WHERE tx_id = ? AND pid = ?`,
        txId,
        this.pid,
      );
      return;
    }

    for (const { op, params } of stashedParams) {
      if (op === 'name_register') {
        const p = params as NameRegisterOpParams;
        try {
          await this.commitNameRegistration(p);
        } catch (err) {
          console.error(
            `[name-registry-participant] commit error for tx ${txId}:`,
            (err as Error)?.message,
          );
          // Mark as aborted — the coordinator will handle recovery.
          await this.txDb.run(
            `UPDATE tx_participant_state SET outcome = 'aborted'
             WHERE tx_id = ? AND pid = ?`,
            txId,
            this.pid,
          );
          throw err;
        }
      } else if (op === 'name_revoke') {
        const p = params as NameRevokeOpParams;
        try {
          await this.commitNameRevocation(p);
        } catch (err) {
          console.error(
            `[name-registry-participant] revoke commit error for tx ${txId}:`,
            (err as Error)?.message,
          );
          await this.txDb.run(
            `UPDATE tx_participant_state SET outcome = 'aborted'
             WHERE tx_id = ? AND pid = ?`,
            txId,
            this.pid,
          );
          throw err;
        }
      }
    }

    // Mark committed in the coordinator state.
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'committed'
       WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );

    console.log(`[name-registry-participant] ${txId.slice(0, 8)} committed`);
  }

  // -----------------------------------------------------------------------
  // abort() — no cleanup needed (no writes were done in prepare)
  // -----------------------------------------------------------------------

  async abort(txId: string): Promise<void> {
    // No pending writes to roll back — prepare() only did SELECTs.
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'aborted'
       WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );
    console.log(`[name-registry-participant] ${txId.slice(0, 8)} aborted (no cleanup needed)`);
  }

  async compensate(txId: string): Promise<void> {
    await this.abort(txId);
  }

  async inquiry(txId: string): Promise<Outcome> {
    const row = await this.txDb.get<{ outcome: string }>(
      'SELECT outcome FROM tx_participant_state WHERE tx_id = ? AND pid = ?',
      txId,
      this.pid,
    );
    return (row?.outcome as Outcome) ?? 'unknown';
  }

  // -----------------------------------------------------------------------
  // Commit helpers — SERIALIZABLE INSERT/UPDATE
  // -----------------------------------------------------------------------

  /**
   * Commit a name registration: SERIALIZABLE re-check + INSERT + store DID
   * document for backup.
   *
   * The UNIQUE(namespace, name) constraint + SERIALIZABLE isolation guarantees
   * exactly one winner across all utility servers in a multi-server cluster.
   */
  private async commitNameRegistration(p: NameRegisterOpParams): Promise<void> {
    const proofType = p.proof?.type ?? 'utility_managed';

    // Compute proof reference
    let proofRef: string | null = null;
    if (proofType === 'vrc' && p.proof?.vrc?.digest) {
      proofRef = Buffer.from(p.proof.vrc.digest).toString('base64');
    }

    console.log(
      `[name-registry-participant] commit: registering ` +
      `vta:${p.namespace}:${p.name} → DID ${p.did} (proof: ${proofType})`,
    );

    // ── SERIALIZABLE transaction — the core value of YugabyteDB ─────────
    const result = await this.appDb.transaction(async (tx) => {
      // Re-check for conflict (race guard — another server may have
      // committed between our prepare and commit)
      const existing = await tx.get<{ did: string }>(
        `SELECT did FROM name_registry
         WHERE namespace = ? AND name = ? AND revoked_at IS NULL`,
        p.namespace,
        p.name,
      );

      if (existing) {
        console.log(
          `[name-registry-participant] commit conflict: ` +
          `name already registered to ${existing.did}`,
        );
        return { conflict: true, existingDid: existing.did };
      }

      const now = Math.floor(Date.now() / 1000);
      const rowUuid = generateUuid();

      // ── Resolve the canonical primary R-Card profile for the name ──────
      // The agent names the profile by label (or we fall back to the
      // identity's default profile). Because the nested identity_push child
      // transaction applied profiles during prepare(), the row is already
      // visible by commit time — so we can set profile_id + profile_uuid
      // atomically with the INSERT instead of relying on a later, lossy push.
      const canonicalProfile = await tx.get<{ uuid: string }>(
        p.primaryProfileLabel
          ? `SELECT p.uuid FROM profiles p
             JOIN identities i ON i.uuid = p.identity_uuid
             JOIN did_documents d ON d.identity_uuid = i.uuid
             WHERE d.did = ? AND p.label = ?
             ORDER BY p.uuid ASC LIMIT 1`
          : `SELECT p.uuid FROM profiles p
             JOIN identities i ON i.uuid = p.identity_uuid
             JOIN did_documents d ON d.identity_uuid = i.uuid
             WHERE d.did = ? AND p.is_default = 1
             ORDER BY p.uuid ASC LIMIT 1`,
        ...(p.primaryProfileLabel ? [p.did, p.primaryProfileLabel] : [p.did]),
      );

      await tx.run(
        `INSERT INTO name_registry
         (namespace, name, did, identity_uuid, profile_uuid,
          proof_type, proof_reference, claimed_at, uuid)
         VALUES (?, ?, ?, (SELECT i.uuid FROM identities i JOIN did_documents d ON d.identity_uuid = i.uuid WHERE d.did = ?), ?, ?, ?, ?, ?)`,
        p.namespace,
        p.name,
        p.did,
        p.did,
        canonicalProfile?.uuid ?? p.profileUuid ?? null,  // canonical wins; agent uuid is only a fallback
        proofType,
        proofRef,
        now,
        rowUuid,
      );

      console.log(
        `[name-registry-participant] ✓ INSERT into name_registry: ` +
        `vta:${p.namespace}:${p.name} → ${p.did}`,
      );

      // ── Store DID document for backup/restoration ──────────────────
      if (p.didDocument && typeof p.didDocument === 'object') {
        try {
          const existingDoc = await tx.get<{ uuid: string }>(
            `SELECT uuid FROM did_documents WHERE did = ? AND is_primary = 1`,
            p.did,
          );
          if (existingDoc) {
            await tx.run(
              `UPDATE did_documents SET document_json = ? WHERE uuid = ?`,
              JSON.stringify(p.didDocument),
              existingDoc.uuid,
            );
            console.log(
              `[name-registry-participant] ✓ upserted DID document for ${p.did}`,
            );
          }
        } catch (docErr) {
          console.warn(
            `[name-registry-participant] failed to upsert DID document: ` +
            `${(docErr as Error).message}`,
          );
          // Non-fatal — the name registration succeeded even if the DID
          // document backup failed. NOTE: this block must not itself error,
          // because on PostgreSQL a failed statement aborts the enclosing
          // SERIALIZABLE transaction and rolls back the name_registry INSERT
          // above — exactly what happened when this code called the removed
          // `did_documents.id` column.
        }
      }

      return { conflict: false };
    });

    if (result.conflict) {
      throw new Error(
        `The name '${p.namespace}:${p.name}' was claimed by another user ` +
        `while registering. Please try a different name.`,
      );
    }
  }

  /**
   * Commit a name revocation: SERIALIZABLE re-check + UPDATE revoked_at.
   */
  private async commitNameRevocation(p: NameRevokeOpParams): Promise<void> {
    const now = Math.floor(Date.now() / 1000);

    console.log(
      `[name-registry-participant] commit: revoking ` +
      `vta:${p.namespace}:${p.name} (DID: ${p.did})`,
    );

    const result = await this.appDb.transaction(async (tx) => {
      // Re-check ownership
      const existing = await tx.get<{ did: string }>(
        `SELECT did FROM name_registry
         WHERE namespace = ? AND name = ? AND revoked_at IS NULL`,
        p.namespace,
        p.name,
      );

      if (!existing) {
        return { revokeApplied: false };
      }

      if (existing.did !== p.did) {
        return { revokeApplied: false };
      }

      const res = await tx.run(
        `UPDATE name_registry SET revoked_at = ?
         WHERE namespace = ? AND name = ? AND revoked_at IS NULL AND did = ?`,
        now,
        p.namespace,
        p.name,
        p.did,
      );

      return { revokeApplied: res.changes > 0 };
    });

    if (!result.revokeApplied) {
      throw new Error(
        `Name '${p.namespace}:${p.name}' could not be revoked. ` +
        `It may have already been revoked or transferred.`,
      );
    }

    console.log(
      `[name-registry-participant] ✓ revoked name: ` +
      `vta:${p.namespace}:${p.name}`,
    );
  }
}