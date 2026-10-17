// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Exchange Push Participant — server-side coordinator participant that applies
 * CRE `exchange:identity` / `exchange:rcard` pushes from agents.
 *
 * This is the Phase 2 load-bearing path for the durable identity/profile push:
 * the agent's durable outbox replays `exchange:identity` as a 2PC, and this
 * participant reuses IdentityPushParticipant's apply logic (upsert with
 * custody='remote', recorded_by_node='agent-push', linkCanonicalProfileToNames)
 * so the R-Card/profile data is applied exactly as the legacy identity_push did.
 *
 * pid: 'server:{serverId}' — shares the pid with the other server participants;
 * the coordinator dispatches to it via handlesOperation() for `exchange:*` ops.
 */
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { Operation, Outcome, Participant, Vote } from '@p2p-trust-stack/core/tx/types.js';
import type { IdentityPushPayload } from '@p2p-trust-stack/core/tsp-handlers/types.js';
import { IdentityPushParticipant } from './identity-push-participant.js';

/** Unwrap a payload that may have been wrapped in a single-element array. */
function unwrapPayload(p: unknown): IdentityPushPayload | null {
  if (Array.isArray(p)) return (p[0] as IdentityPushPayload) ?? null;
  if (p && typeof p === 'object') return p as IdentityPushPayload;
  return null;
}

export class ExchangePushParticipant implements Participant {
  readonly pid: string;
  private readonly identityPush: IdentityPushParticipant;

  constructor(pid: string, appDb: DataSource, txDb: DataSource) {
    this.pid = pid;
    this.identityPush = new IdentityPushParticipant(pid, appDb, txDb);
  }

  handlesOperation(op: Operation): boolean {
    // Claim ONLY the identity push (the durable agent→server profile sync).
    // Do NOT claim exchange:rcard here — rcard is a PULL recordset handled by
    // ExchangeQueryParticipant; claiming both would make the coordinator
    // dispatch rcard to the wrong participant.
    return op.op === 'exchange:identity';
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    for (const op of operations) {
      if (op.op !== 'exchange:identity') continue;
      const params = op.params as { payload?: unknown } | undefined;
      const payload = unwrapPayload(params?.payload);
      if (!payload || !payload.realDid) return 'no';
      try {
        await this.identityPush.applyIdentityPushPayload(payload);
      } catch (err) {
        console.error(`[exchange-push-participant] prepare failed for tx ${txId}:`, (err as Error)?.message);
        return 'no';
      }
    }

    // Record durable 'prepared' state (same tx_participant_state row as the
    // identity push participant — shared pid).
    await this.identityPush.prepare(txId, []);
    return 'yes';
  }

  async commit(txId: string): Promise<void> {
    await this.identityPush.commit(txId);
  }

  async abort(txId: string): Promise<void> {
    await this.identityPush.abort(txId);
  }

  async compensate(txId: string): Promise<void> {
    await this.identityPush.compensate(txId);
  }

  async inquiry(txId: string): Promise<Outcome> {
    return this.identityPush.inquiry(txId);
  }
}
