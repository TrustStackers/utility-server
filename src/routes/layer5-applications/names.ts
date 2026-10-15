/**
 * Name Registry REST API — read-only view of the name_registry table.
 *
 * GET /names — list all registered names with proof metadata
 * GET /names/resolve?nameUri=... — resolve a name URI to its bound DID
 */

import type { FastifyInstance } from 'fastify';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';

interface NameRegistryRow {
  uuid: string;
  namespace: string;
  name: string;
  did: string;
  profile_uuid: string | null;
  credential_uuid: string | null;
  proof_type: string | null;
  proof_reference: string | null;
  claimed_at: number;
  updated_at: number | null;
  expires_at: number | null;
  revoked_at: number | null;
}

export function registerNameRoutes(app: FastifyInstance, db: DataSource): void {
  // ── List all registered names ────────────────────────────────────────
  app.get('/names', async (_req, reply) => {
    try {
      const rows = await db.all<NameRegistryRow>(
        `SELECT uuid, namespace, name, did, profile_uuid, credential_uuid, proof_type, proof_reference,
                claimed_at, updated_at, expires_at, revoked_at
         FROM name_registry
         WHERE revoked_at IS NULL
         ORDER BY claimed_at DESC
         LIMIT 200`,
      );

      return rows.map(r => ({
        uuid: r.uuid,
        namespace: r.namespace,
        name: r.name,
        nameUri: `vta:${r.namespace}:${r.name}`,
        did: r.did,
        profileUuid: r.profile_uuid,
        credentialUuid: r.credential_uuid,
        proofType: r.proof_type,
        proofReference: r.proof_reference,
        claimedAt: r.claimed_at,
        updatedAt: r.updated_at,
        expiresAt: r.expires_at,
        revokedAt: r.revoked_at,
      }));
    } catch (err) {
      return reply.code(500).send({ error: (err as Error).message });
    }
  });

  // ── Resolve a name URI ───────────────────────────────────────────────
  app.get('/names/resolve', async (req, reply) => {
    const { nameUri } = req.query as { nameUri?: string };
    if (!nameUri) {
      return reply.code(400).send({ error: 'nameUri query parameter is required' });
    }

    // Parse vta:<namespace>:<name> with optional /claimKey1,claimKey2 suffix
    // Strip the suffix for name_registry lookup, use it for R-Card filtering
    let baseUri = String(nameUri);
    let requestedKeys: string[] = [];
    const slashIdx = baseUri.indexOf('/');
    if (slashIdx >= 0) {
      requestedKeys = baseUri.substring(slashIdx + 1).split(',').map(k => k.trim()).filter(k => k.length > 0);
      baseUri = baseUri.substring(0, slashIdx);
    }

    const match = /^vta:([^:]+):(.+)$/.exec(baseUri);
    if (!match) {
      return reply.code(400).send({ error: 'Invalid name URI format. Expected: vta:<namespace>:<name>' });
    }

    const namespace = match[1];
    const name = match[2];

    try {
      const row = await db.get<NameRegistryRow>(
        `SELECT uuid, namespace, name, did, profile_uuid, credential_uuid, proof_type, proof_reference,
                claimed_at, updated_at, expires_at, revoked_at
         FROM name_registry
         WHERE namespace = ? AND name = ? AND revoked_at IS NULL`,
        namespace, name,
      );

      if (!row) {
        return { found: false };
      }

      // Look up R-Card via UUID-based join
      let rCard: object | undefined;
      let resolvedProfileUuid: string | undefined;
      if (row.profile_uuid) {
        try {
          const profileRow = await db.get<{ uuid: string }>(
            'SELECT uuid FROM profiles WHERE uuid = ?',
            row.profile_uuid,
          );
          if (profileRow) {
            const { getProfileCard } = await import('../../services/profiles.js');
            rCard = await getProfileCard(db, profileRow.uuid, requestedKeys);
            resolvedProfileUuid = profileRow.uuid;
          }
        } catch { /* ignore */ }
      }

      return {
        found: true,
        uuid: row.uuid,
        namespace: row.namespace,
        name: row.name,
        nameUri: `vta:${row.namespace}:${row.name}`,
        did: row.did,
        profileUuid: resolvedProfileUuid ?? row.profile_uuid,
        credentialUuid: row.credential_uuid,
        proofType: row.proof_type,
        proofReference: row.proof_reference,
        claimedAt: row.claimed_at,
        updatedAt: row.updated_at,
        expiresAt: row.expires_at,
        revokedAt: row.revoked_at,
        rCard,
      };
    } catch (err) {
      return reply.code(500).send({ error: (err as Error).message });
    }
  });

  // ── Link a profile to an existing name registration ──────────────────
  app.put('/names/profile', async (req, reply) => {
    const { nameUri, profileUuid } = (req.body || {}) as { nameUri?: string; profileUuid?: string };
    if (!nameUri || !profileUuid) {
      return reply.code(400).send({ error: 'nameUri and profileUuid are required' });
    }

    const match = /^vta:([^:]+):(.+)$/.exec(String(nameUri));
    if (!match) {
      return reply.code(400).send({ error: 'Invalid name URI format. Expected: vta:<namespace>:<name>' });
    }

    try {
      const result = await db.run(
        'UPDATE name_registry SET profile_uuid = ?, updated_at = ? WHERE namespace = ? AND name = ? AND revoked_at IS NULL',
        profileUuid,
        Math.floor(Date.now() / 1000),
        match[1],
        match[2],
      );
      if (result.changes === 0) {
        return reply.code(404).send({ error: 'Name not found or already revoked' });
      }
      return { ok: true, updated: result.changes };
    } catch (err) {
      return reply.code(500).send({ error: (err as Error).message });
    }
  });
}