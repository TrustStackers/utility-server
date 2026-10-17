// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * YugabyteDB-backed RotationLogStore for the utility server's own VTA.
 *
 * Mirrors src/did/rotation-log-store.ts but uses DataSource (YugabyteDB)
 * instead of DatabaseSync (SQLite). The utility server stores its own
 * rotation log entries in the shared `rotation_log` table in YugabyteDB.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { DidDocument, DidParameters } from '@p2p-trust-stack/core/did/types.js';
import type { RotationLogEntry } from '@p2p-trust-stack/core/did/rotation-types.js';

// ---------------------------------------------------------------------------
// Serialization (copied from src/did/rotation-log-store.ts)
// ---------------------------------------------------------------------------

function packSignedEntry(
  didDocument: DidDocument,
  parameters: DidParameters | undefined,
  digest: Uint8Array,
  signature: Uint8Array,
): Uint8Array {
  const docJson = new TextEncoder().encode(JSON.stringify(didDocument));
  const paramsJson = new TextEncoder().encode(JSON.stringify(parameters ?? null));
  const packed = new Uint8Array(4 + docJson.length + 4 + paramsJson.length + digest.length + signature.length);
  const view = new DataView(packed.buffer);
  view.setUint32(0, docJson.length, false);
  packed.set(docJson, 4);
  view.setUint32(4 + docJson.length, paramsJson.length, false);
  packed.set(paramsJson, 4 + docJson.length + 4);
  const offset = 4 + docJson.length + 4 + paramsJson.length;
  packed.set(digest, offset);
  packed.set(signature, offset + digest.length);
  return packed;
}

function unpackSignedEntry(packed: Uint8Array): {
  parameters?: DidParameters;
  didDocument: DidDocument;
  digest: Uint8Array;
  signature: Uint8Array;
} {
  const view = new DataView(packed.buffer, packed.byteOffset, packed.byteLength);
  const docLen = view.getUint32(0, false);
  const docJson = new TextDecoder().decode(packed.slice(4, 4 + docLen));
  const paramsLenOffset = 4 + docLen;
  const paramsLen = view.getUint32(paramsLenOffset, false);
  const paramsJson = new TextDecoder().decode(packed.slice(paramsLenOffset + 4, paramsLenOffset + 4 + paramsLen));
  const offset = paramsLenOffset + 4 + paramsLen;
  const digest = packed.slice(offset, offset + 32);
  const signature = packed.slice(offset + 32, offset + 32 + 64);
  let parameters: DidParameters | undefined;
  try {
    parameters = JSON.parse(paramsJson) ?? undefined;
  } catch { /* legacy format */ }
  return { parameters, didDocument: JSON.parse(docJson) as DidDocument, digest, signature };
}

function parseNextKeyCommitments(raw: Uint8Array): Uint8Array[] {
  try {
    const json = new TextDecoder().decode(raw);
    const arr = JSON.parse(json) as string[];
    return arr.map(b64 => new Uint8Array(Buffer.from(b64, 'base64')));
  } catch {
    return [new Uint8Array(raw)];
  }
}

interface RotationLogRow {
  uuid: string;
  did_document_uuid: string;
  version: number;
  previous_hash: Buffer | Uint8Array | null;
  new_public_key: Buffer | Uint8Array;
  signed_entry: Buffer | Uint8Array;
  created_at: number | null;
}

// ---------------------------------------------------------------------------
// YugabyteRotationLogStore
// ---------------------------------------------------------------------------

export class YugabyteRotationLogStore {
  private db: DataSource;

  constructor(db: DataSource) {
    this.db = db;
  }

  async appendEntry(didDocumentUuid: string, entry: RotationLogEntry): Promise<void> {
    const packed = packSignedEntry(entry.didDocument, entry.parameters, entry.digest, entry.signature);
    const rowUuid = crypto.randomUUID();

    await this.db.run(
      `INSERT INTO rotation_log
       (did_document_uuid, version, previous_hash,
        new_public_key, signed_entry, uuid, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      didDocumentUuid,
      entry.version,
      entry.prevHash ? Buffer.from(entry.prevHash) : null,
      Buffer.from(JSON.stringify(entry.nextKeyCommitments.map(k => Buffer.from(k).toString('base64')))),
      Buffer.from(packed),
      rowUuid,
      entry.createdAt,
    );
  }

  async getLog(didDocumentUuid: string): Promise<RotationLogEntry[]> {
    const rows = await this.db.all<RotationLogRow>(
      `SELECT * FROM rotation_log WHERE did_document_uuid = ? ORDER BY version ASC`,
      didDocumentUuid,
    );
    return rows.map(r => {
      const unpacked = unpackSignedEntry(new Uint8Array(r.signed_entry));
      return {
        version: r.version,
        parameters: unpacked.parameters,
        didDocument: unpacked.didDocument,
        prevHash: r.previous_hash ? new Uint8Array(r.previous_hash) : null,
        nextKeyCommitments: parseNextKeyCommitments(new Uint8Array(r.new_public_key)),
        createdAt: r.created_at ?? 0,
        digest: unpacked.digest,
        signature: unpacked.signature,
        witnessAttestations: [],
      };
    });
  }
}