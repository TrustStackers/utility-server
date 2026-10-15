/**
 * Shared identity-push apply logic — used by the CRE exchange:identity path
 * (ExchangePushParticipant delegates here).
 *
 * Receives an agent's public identity data (DID document, public keys,
 * profiles, credentials) and persists it to the utility server's application
 * database. The old standalone `identity_push` coordinator op was retired;
 * this class provides the shared apply + participant-state primitives.
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
import type { IdentityPushPayload } from '@p2p-trust-stack/core/tsp-handlers/types.js';
import { createRemoteVta } from '@p2p-trust-stack/core/services/vta.js';
import { persistPushedRotationLog } from '@p2p-trust-stack/core/services/rotation-log-sync.js';
import * as profilesService from '@p2p-trust-stack/core/services/profiles.js';
import * as relationshipsRepo from '@p2p-trust-stack/core/db/repositories/relationships-repo.js';
import { v5 } from 'uuid';

/** Namespace for deterministic relationship-pair UUIDs (RFC 4122 DNS namespace). */
const REL_NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';

/**
 * Deterministic UUIDv5 for a relationship pair so that the local→remote and
 * remote→local pushes from the two agents of a VRC ceremony merge into ONE
 * `relationships` row (CRDT lattice join in upsertFromReplication), rather than
 * creating two duplicate rows for the same physical pair.
 */
function pairRelationshipUuid(a: string, b: string): string {
  const [x, y] = [a, b].sort();
  return v5(`rel:${x}:${y}`, REL_NAMESPACE);
}

/**
 * Shared identity-push apply logic for the CRE exchange:identity path.
 *
 * The standalone `identity_push` coordinator op was retired (both producer
 * sites now enlist `exchange:identity`, handled by ExchangePushParticipant,
 * which delegates here). This class no longer claims any op itself — it IS
 * the shared apply + participant-state primitives beneath ExchangePushParticipant.
 */
export class IdentityPushParticipant implements Participant {
  readonly pid: string;
  private readonly appDb: DataSource;   // YugabyteDB (application data)
  private readonly txDb: DataSource;    // SQLite (tx-coordinator.db)

  constructor(pid: string, appDb: DataSource, txDb: DataSource) {
    this.pid = pid;
    this.appDb = appDb;
    this.txDb = txDb;
  }

  /**
   * Public entry for the CRE ExchangePushParticipant: applies one full identity
   * push payload (same logic as prepare() uses for identity_push ops).
   */
  public async applyIdentityPushPayload(payload: IdentityPushPayload): Promise<void> {
    await this.applyIdentityPush(payload);
  }

  // Retired: no longer claims any coordinator op (`identity_push` producers were
  // migrated to `exchange:identity`). ExchangePushParticipant drives this class
  // directly for the exchange:identity push.
  handlesOperation(_op: Operation): boolean {
    return false;
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    for (const op of operations) {
      if (op.op !== 'identity_push') continue;

      const payload = op.params as unknown as IdentityPushPayload;
      if (!payload || !payload.realDid) return 'no';

      try {
        await this.applyIdentityPush(payload);
      } catch (err) {
        console.error(`[identity-push-participant] prepare failed for tx ${txId}:`, (err as Error)?.message);
        return 'no';
      }
    }

    // Durably record 'prepared' BEFORE voting yes.
    await this.txDb.run(
      `INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome)
       VALUES (?, ?, 'prepared')`,
      txId,
      this.pid,
    );

    return 'yes';
  }

  async commit(txId: string): Promise<void> {
    // Effects are already applied in the application DB during prepare().
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'committed'
       WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );
  }

  async abort(txId: string): Promise<void> {
    // The identity_push is an idempotent upsert; a precise rollback would
    // delete the created identity + profiles + credentials. For now, mark
    // aborted and rely on the next push to reconcile state.
    // TODO: Track created identity UUIDs in undo_hooks for precise rollback.
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'aborted'
       WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );
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
  // Persistence logic (mirrors identity-push-server.ts)
  // -----------------------------------------------------------------------

  private async applyIdentityPush(payload: IdentityPushPayload): Promise<void> {
    const { identity, didDocument } = await createRemoteVta(this.appDb, {
      realDid: payload.realDid,
      uuid: payload.identityUuid,
      name: payload.name,
      subjectKind: (payload.subjectKind as any) ?? 'human',
      didDocument: payload.didDocument,
      publicKeys: payload.publicKeys,
      peerId: payload.peerId,
      // Live dialable addresses (see IdentityPushPayload.multiaddrs) so the
      // server's member re-dial stage has a direct path to this agent, not only
      // the bootstrap relay.
      multiaddrs: payload.multiaddrs,
      recordedByNode: 'agent-push',
    });

    const identityUuid = identity.uuid;

    // ── Persist the pushed did:scid:vh rotation log (BEST-EFFORT, NON-FATAL) ─
    //
    // WHY it must not fail: this runs inside the coordinator's prepare(). A
    // throw here votes 'no', aborts the whole push, and the agent's durable
    // outbox then replays it forever (the same failure mode documented in
    // syncRemotePublicKeys). The document/key/profile sync above is the
    // load-bearing part; the log is what lets the public resolver serve a
    // VERIFIED resolution (source: 'log') instead of a cached snapshot.
    //
    // Idempotent by design: the agent re-sends the WHOLE log on every push, and
    // persistPushedRotationLog inserts only versions not already held.
    if (Array.isArray(payload.rotationLog) && payload.rotationLog.length > 0) {
      try {
        const synced = await persistPushedRotationLog(this.appDb, didDocument.uuid, payload.rotationLog);
        if (synced.inserted > 0) {
          console.log(
            `[identity-push-participant] rotation log for ${payload.realDid}: ` +
            `+${synced.inserted} of ${synced.total} entr${synced.total === 1 ? 'y' : 'ies'} ` +
            `(${synced.skipped} already held)`,
          );
        }
      } catch (err) {
        console.warn(
          `[identity-push-participant] rotation log persist failed for ${payload.realDid} ` +
          `(push continues): ${(err as Error)?.message ?? err}`,
        );
      }
    }

    // Resolve a UUID to a live identity id+uuid. Prefers the resolveVta path
    // (finds a real, endpoint-bearing VTA via shared Ed25519 key when the given
    // uuid currently points at a TSP-bridge fake).
    const resolveUuid = async (uuid: string): Promise<{ uuid: string } | null> => {
      const ident = await this.appDb.get<{ uuid: string }>(
        'SELECT uuid FROM identities WHERE uuid = $1', uuid,
      );
      if (!ident) return null;

      const hasEndpoint = await this.appDb.get<{ uuid: string }>(
        `SELECT pe.uuid FROM peer_endpoints pe
         WHERE pe.identity_uuid = $1 LIMIT 1`,
        uuid,
      );
      if (hasEndpoint) return ident;

      const real = await this.appDb.get<{ uuid: string }>(
        `SELECT i.uuid FROM identities i
         JOIN keys k ON k.identity_uuid = i.uuid
         JOIN keys k2 ON k2.public_key = k.public_key AND k2.key_type = 'ed25519'
         JOIN identities i2 ON i2.uuid = k2.identity_uuid
         JOIN peer_endpoints pe ON pe.identity_uuid = i.uuid
         WHERE i2.uuid = $1 AND i.role = 'vta'
         ORDER BY i.created_at, i.uuid`,
        ident.uuid,
      );
      return real ?? ident;
    };

    // Store profile data if included
    if (payload.profiles && payload.profiles.length > 0) {
      for (const p of payload.profiles) {
        const existing = await this.appDb.get<{ uuid: string }>(
          'SELECT uuid FROM profiles WHERE identity_uuid = ? AND label = ?',
          identity.uuid,
          p.label,
        );

        let profileUuid: string;
        if (existing) {
          profileUuid = existing.uuid;
          await this.appDb.run(
            'UPDATE profiles SET purpose = ?, visibility = ?, updated_at = ? WHERE uuid = ?',
            p.purpose ?? null,
            p.visibility,
            Math.floor(Date.now() / 1000),
            profileUuid,
          );
          await this.appDb.run('DELETE FROM profile_claims WHERE profile_uuid = ?', profileUuid);
        } else {
          const profile = await profilesService.createProfile(this.appDb, {
            identityUuid: identity.uuid,
            label: p.label,
            purpose: p.purpose,
            visibility: p.visibility as any,
          });
          profileUuid = profile.uuid;
        }

        for (const c of p.claims) {
          const profileRow = existing
            ? existing
            : (await this.appDb.get<{ uuid: string }>(
              'SELECT uuid FROM profiles WHERE identity_uuid = ? AND label = ?',
              identityUuid,
              p.label,
            ));
          await profilesService.addClaim(this.appDb, {
            profileUuid: profileRow!.uuid,
            claimKey: c.claimKey,
            claimValue: c.claimValue,
            valueType: c.valueType as any,
            disclosure: c.disclosure as any,
          });
        }
      }

      await this.linkCanonicalProfileToNames(identityUuid);
    }

    // Store credential data if included (DTG sync)
    if (payload.credentials && payload.credentials.length > 0) {
      for (const c of payload.credentials) {
        const issuer = await resolveUuid(c.issuerIdentityUuid);
        const subject = await resolveUuid(c.subjectIdentityUuid);

        if (!issuer || !subject) {
          console.warn(`[identity-push-participant] credential ${c.uuid}: identity not found, skipping`);
          continue;
        }

        const now = Math.floor(Date.now() / 1000);
        // First-wins dedup on TWO independent keys so the same logical VRC can
        // never be written twice by the two agents' identity pushes:
        //   1. the exact credential_digest (an identical re-push), AND
        //   2. any 'vrc' row for the same (issuer, subject) peer pair that
        //      already carries a w3c_vc_json envelope.
        // The two agents of one ceremony each push BOTH their minted VRC
        // (digest = claim digest) AND their mirrored copy of the peer's VRC
        // (digest = VC digest); those digests never collide, so digest-only
        // dedup let each logical VRC be inserted twice. The mirrored copy is
        // byte-identical to the minted envelope, so merging into the existing
        // row loses nothing.
        let existing = c.credentialDigest
          ? (await this.appDb.get<{ uuid: string }>(
              'SELECT uuid FROM credentials WHERE credential_digest = ?', c.credentialDigest,
            )) ?? null
          : null;
        if (!existing) {
          existing = await this.appDb.get<{ uuid: string }>(
            `SELECT uuid FROM credentials
             WHERE vc_type = 'vrc' AND issuer_identity_uuid = ? AND subject_identity_uuid = ?
               AND w3c_vc_json IS NOT NULL
             ORDER BY created_at DESC LIMIT 1`,
            issuer.uuid, subject.uuid,
          ) ?? null;
        }

        if (existing) {
          await this.appDb.run(
            'UPDATE credentials SET status = ?, w3c_vc_json = COALESCE(?, w3c_vc_json), claim = COALESCE(?, claim), replicated_at = ? WHERE uuid = ?',
            c.status, c.w3cVcJson, c.claim, now, existing.uuid,
          );
        } else {
          await this.appDb.run(
            `INSERT INTO credentials
              (vc_type, issuer_identity_uuid,
               subject_identity_uuid,
               w3c_vc_json, claim, status, threshold_required,
               valid_from, valid_until, credential_digest,
               uuid, recorded_by_node, replicated_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            c.vcType, issuer.uuid,
            subject.uuid,
            c.w3cVcJson, c.claim, c.status, c.thresholdRequired,
            c.validFrom, c.validUntil, c.credentialDigest,
            c.uuid, 'agent-push', now, c.createdAt ?? now,
          );
        }
      }

      // Store credential signatures
      if (payload.credentialSignatures && payload.credentialSignatures.length > 0) {
        for (const s of payload.credentialSignatures) {
          const cred = await this.appDb.get<{ uuid: string }>(
            'SELECT uuid FROM credentials WHERE uuid = ?', s.credentialUuid,
          );
          if (!cred) continue;

          const existingSig = await this.appDb.get<{ uuid: string }>(
            'SELECT uuid FROM credential_signatures WHERE credential_uuid = ? AND signer_identity_uuid = ?',
            s.credentialUuid, s.signerIdentityUuid,
          );
          if (!existingSig) {
            await this.appDb.run(
              `INSERT INTO credential_signatures (credential_uuid, signer_identity_uuid, signature, uuid, signed_at)
               VALUES (?, ?, ?, ?, ?)`,
              s.credentialUuid, s.signerIdentityUuid,
              Buffer.from(s.signature, 'base64'),
              crypto.randomUUID(),
              s.signedAt ?? Math.floor(Date.now() / 1000),
            );
          }
        }
      }
    }

    // Persist an established bidirectional relationship (VRC pair) if carried.
    // Keyed by a deterministic pair UUID so the two agents' pushes merge into
    // one `relationships` row (CRDT direction lattice join), and so
    // `createVtc`'s hasEstablishedVrcBetween governance check sees it.
    const relationship = payload.relationship;
    if (relationship) {
      const rLocal = await resolveUuid(relationship.localUuid);
      const rRemote = await resolveUuid(relationship.remoteUuid);
      if (!rLocal || !rRemote) {
        console.warn('[identity-push-participant] relationship: identity not resolvable, skipping');
      } else {
        try {
          await relationshipsRepo.upsertFromReplication(this.appDb, {
            localIdentityUuid: rLocal.uuid,
            remoteIdentityUuid: rRemote.uuid,
            direction: 'bidirectional',
            status: 'established',
            remoteTransport: relationship.remoteTransport ?? undefined,
            uuid: pairRelationshipUuid(relationship.localUuid, relationship.remoteUuid),
            recordedByNode: 'agent-push',
            replicatedAt: Math.floor(Date.now() / 1000),
          });
          console.log(
            `[identity-push-participant] recorded established relationship ${rLocal.uuid.slice(0, 8)}↔${rRemote.uuid.slice(0, 8)}`,
          );
        } catch (err) {
          console.error('[identity-push-participant] relationship persist failed:', (err as Error)?.message ?? err);
        }
      }
    }
  }

  /**
   * Link every active name_registry row for an identity to its canonical
   * primary R-Card profile: the default profile (first created), falling back
   * to the lowest-id profile. Deterministic and idempotent — a name resolves
   * to exactly one card, and the card is stable across pushes regardless of
   * profile order in the payload. Retries once to cover the registration
   * commit landing between our prepare and this update.
   */
  private async linkCanonicalProfileToNames(identityUuid: string): Promise<void> {
    const primary = await this.appDb.get<{ uuid: string }>(
      'SELECT uuid FROM profiles WHERE identity_uuid = ? ORDER BY is_default DESC, uuid ASC LIMIT 1',
      identityUuid,
    );
    if (!primary) {
      console.log('[identity-push-participant] no profiles to link for name_registry');
      return;
    }

    const doUpdate = async () => {
      const result = await this.appDb.run(
        `UPDATE name_registry SET profile_uuid = ?, updated_at = ?
         WHERE identity_uuid = ? AND revoked_at IS NULL`,
        primary.uuid,
        Math.floor(Date.now() / 1000),
        identityUuid,
      );
      return result.changes;
    };

    let matched = await doUpdate();
    if (matched === 0) {
      await new Promise((r) => setTimeout(r, 200));
      matched = await doUpdate();
      if (matched === 0) {
        console.warn('[identity-push-participant] name_registry linkage matched 0 rows — registration row may not exist yet');
      }
    }
  }
}
