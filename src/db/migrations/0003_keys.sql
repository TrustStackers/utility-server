-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0003_keys.sql
-- Key material — only ever populated for identities with custody='local';
-- encrypted_secret_key is NULL for remotely-pushed identities (public_key only).
--
-- identity_uuid / did_document_uuid = distributed references
--
-- ⚠ NOTE — the wide key_type CHECK below is deliberate (see the SQLite twin for
-- the full note). Pre-release, an in-place change is acceptable; change BOTH
-- migration sets together and test/db/schema-policy.test.ts fails if they drift.

CREATE TABLE IF NOT EXISTS keys (
  uuid                  TEXT PRIMARY KEY,     -- UUIDv7 for cross-node dedup
  identity_uuid         TEXT NOT NULL,        -- identities.uuid FK target
  did_document_uuid     TEXT,                 -- did_documents.uuid FK target
  key_type              TEXT NOT NULL CHECK(key_type IN ('ed25519', 'x25519', 'ml_dsa_65', 'mlkem768_x25519')),
  public_key            BYTEA NOT NULL,
  encrypted_secret_key  BYTEA,                -- NULL when custody='remote'
  salt                  BYTEA,
  nonce                 BYTEA,
  auth_tag              BYTEA,
  rotation_version      INTEGER NOT NULL DEFAULT 0,
  recorded_by_node      TEXT,
  replicated_at         INTEGER,
  created_at            INTEGER,
  UNIQUE(identity_uuid, did_document_uuid, key_type, rotation_version)
);

CREATE INDEX IF NOT EXISTS idx_keys_identity_uuid ON keys(identity_uuid);