-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0018_namespace_config.sql
-- Namespace ↔ VTN binding (utility-server only — no core src/db counterpart).
--
-- The utility server serves ONE namespace at a time. The namespace is modeled
-- as a VTN identity (role='vtn'); this singleton table binds that VTN identity
-- to the human-readable namespace string used to build agent names
-- (vta:<namespace>:<name>). Active membership in this VTN (role founding_admin /
-- admin) equals utility-server administration.
--
-- Applied only to the utility server's YugabyteDB: see utility-server/src/index.ts
-- (MIGRATIONS_DIR = utility-server/src/db/migrations). The core src/db/ SQLite
-- schema used by the agent-app intentionally does NOT include this table, so the
-- agent's local identity cache stays schema-version 19.

CREATE TABLE IF NOT EXISTS namespace_config (
  uuid              TEXT PRIMARY KEY,     -- UUIDv7 (cross-node dedup)
  vtn_identity_uuid TEXT NOT NULL UNIQUE, -- identities.uuid (role='vtn')
  namespace         TEXT NOT NULL UNIQUE, -- dot-separated, e.g. 'p2pts.mainnet'
  created_at        INTEGER NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
  updated_at        INTEGER NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE INDEX IF NOT EXISTS idx_namespace_config_vtn ON namespace_config(vtn_identity_uuid);
