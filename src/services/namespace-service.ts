/**
 * namespace-service — reads/writes the singleton `namespace_config` table that
 * binds the utility server's namespace string to its namespace VTN identity.
 *
 * The namespace is modeled as a VTN (`role='vtn'`); active membership in that
 * VTN (role founding_admin/admin) equals utility-server administration. This
 * module is the single authority for that binding and for the membership gate.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';

export interface NamespaceConfigRow {
  uuid: string;
  vtnIdentityUuid: string;
  namespace: string;
  createdAt: number;
  updatedAt: number;
}

interface RawRow {
  uuid: string;
  vtn_identity_uuid: string;
  namespace: string;
  created_at: number;
  updated_at: number;
}

function toNamespaceConfig(row: RawRow): NamespaceConfigRow {
  return {
    uuid: row.uuid,
    vtnIdentityUuid: row.vtn_identity_uuid,
    namespace: row.namespace,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/** Read the configured namespace binding (single row, or null when unconfigured). */
export async function getNamespaceConfig(db: DataSource): Promise<NamespaceConfigRow | null> {
  const row = await db.get<RawRow>('SELECT * FROM namespace_config ORDER BY created_at ASC LIMIT 1');
  return row ? toNamespaceConfig(row) : null;
}

/** Read the namespace binding for a specific VTN identity. */
export async function getNamespaceByVtn(db: DataSource, vtnIdentityUuid: string): Promise<NamespaceConfigRow | null> {
  const row = await db.get<RawRow>('SELECT * FROM namespace_config WHERE vtn_identity_uuid = ?', vtnIdentityUuid);
  return row ? toNamespaceConfig(row) : null;
}

/** True when the given namespace is the one this server currently serves. */
export async function isNamespaceServed(db: DataSource, namespace: string): Promise<boolean> {
  const row = await db.get<{ uuid: string }>(
    'SELECT uuid FROM namespace_config WHERE namespace = ? LIMIT 1',
    namespace,
  );
  return row != null;
}

/**
 * Create or update the singleton namespace binding.
 * Idempotent; in practice there is exactly one row per utility server.
 */
export async function setNamespaceConfig(
  db: DataSource,
  input: { vtnIdentityUuid: string; namespace: string },
): Promise<NamespaceConfigRow> {
  if (!input.vtnIdentityUuid || !input.namespace?.trim()) {
    throw new Error('vtnIdentityUuid and namespace are required');
  }
  const namespace = input.namespace.trim();
  const now = Math.floor(Date.now() / 1000);

  const existing = await getNamespaceConfig(db);
  if (existing) {
    await db.run(
      `UPDATE namespace_config SET vtn_identity_uuid = ?, namespace = ?, updated_at = ? WHERE uuid = ?`,
      input.vtnIdentityUuid, namespace, now, existing.uuid,
    );
    return (await getNamespaceConfig(db))!;
  }

  const rowUuid = generateUuid();
  await db.run(
    `INSERT INTO namespace_config (uuid, vtn_identity_uuid, namespace, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?)`,
    rowUuid, input.vtnIdentityUuid, namespace, now, now,
  );
  return (await getNamespaceConfig(db))!;
}

/**
 * Whether `memberUuid` holds an ACTIVE admin/founding_admin membership in the
 * namespace VTN `vtnIdentityUuid`. This is the authorization gate for the
 * founder-admin configuration page.
 */
export async function isNamespaceAdmin(
  db: DataSource,
  memberUuid: string,
  vtnIdentityUuid: string,
): Promise<boolean> {
  const row = await db.get<{ uuid: string }>(
    `SELECT uuid FROM memberships
     WHERE member_identity_uuid = ? AND community_identity_uuid = ?
       AND role IN ('founding_admin', 'admin') AND status = 'active'
     LIMIT 1`,
    memberUuid,
    vtnIdentityUuid,
  );
  return row != null;
}

/** Resolve the namespace VTN identity uuid, or null when unconfigured. */
export async function getNamespaceVtnUuid(db: DataSource): Promise<string | null> {
  const cfg = await getNamespaceConfig(db);
  return cfg?.vtnIdentityUuid ?? null;
}
