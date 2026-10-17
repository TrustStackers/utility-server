// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Layer 5 — Trust Applications: GET /graph/edges
 *
 * DTG (Delegated Trust Graph)-conformant edge list. Per
 * ../../../../docs/utility-server-api-plan.md section 4 "Layer 5", the DTG
 * models trust as signed credentials and delegations. Layer-2 libp2p peer
 * links (the `relationships` table) are also surfaced as 'peer' edges when
 * ?format=graph is requested, since the utility server's own connection to
 * each VTA is otherwise invisible in the visualization.
 *
 * ## Ephemeral did:peer:4 handshake identities
 *
 * Every RFI/RFA handshake between an agent and this server creates an
 * *ephemeral* `did:peer:4` identity row (did_documents.method='did:peer:4',
 * recorded_by_node='tsp-bridge', is_primary=0) — this is just the transport
 * handshake identity, not the agent's real VTA. The agent's real VTA
 * identity arrives separately via `identity_push`
 * (did_documents.is_primary=1, recorded_by_node='agent-push').
 *
 * Both the ephemeral and the real identity rows share the *same* Ed25519 /
 * X25519 public key bytes (same underlying key material, resolved via two
 * different DID methods) — this is the only reliable, data-driven way to
 * recognize they refer to the same agent. Integer `id` columns are
 * meaningless once replicated across nodes; only the shared public key
 * (and downstream, the canonical identity's `uuid`) can be trusted.
 *
 * Credentials minted client-side during the personhood ceremony
 * (`mintPeerVrc`) reference the *ephemeral* peer identity's UUID as
 * issuer/subject (the agent only has the raw VID to resolve against at
 * ceremony time). This route canonicalizes every ephemeral identity UUID to
 * its real VTA counterpart's UUID before building nodes/edges, so:
 *   - the graph never displays throwaway did:peer:4 handshake nodes,
 *   - credential edges connect the two real VTAs to each other, and
 *   - peer edges connect the utility server's real VTA to each agent's real VTA.
 *
 * Optionally scoped to a single identity via ?identityId=, returning only
 * edges where that identity is the source or target.
 *
 * Query param ?format=graph returns a full {nodes, edges} payload with
 * identity metadata for Cytoscape.js / visualization consumers.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import * as credentialsRepo from '@p2p-trust-stack/core/db/repositories/credentials-repo.js';
import * as delegationsRepo from '@p2p-trust-stack/core/db/repositories/delegations-repo.js';

interface GraphEdgesQuery {
  identityUuid?: string;
  format?: string;
}

interface GraphMember {
  uuid: string;
  label: string;
  role: string;
}

interface GraphNode {
  id: string;           // canonical identity uuid
  label: string;
  role: string;
  subjectKind: string;
  identityUuid: string;
  did: string | null;       // primary DID string (did_documents.did)
  members?: GraphMember[];  // active VTC members (role === 'vtc' only)
}

type GraphEdge =
  | {
      kind: 'credential';
      id: string;
      from: string;
      to: string;
      vcType: string;
      status: string;
      credentialId: string;
    }
  | {
      kind: 'delegation';
      id: string;
      from: string;   // identity uuid
      to: string;     // identity uuid
      relationshipType: string;
      delegationId: string; // delegation uuid
    };

// ---------------------------------------------------------------------------
// Ephemeral did:peer:4 → real VTA UUID canonicalization
// ---------------------------------------------------------------------------

interface IdentityMetaRow {
  identity_uuid: string;
  name: string | null;
  role: string;
  subject_kind: string | null;
  is_ephemeral_peer4: number;
  ed25519_hex: string | null;
  did: string | null;
}

/**
 * Build a UUID canonicalization map: ephemeral did:peer:4 handshake
 * identity uuid -> its real VTA counterpart's uuid, joined on shared
 * Ed25519 public key bytes (the only stable cross-identity signal — never
 * integer ids, which are meaningless post-replication).
 *
 * Also returns identity metadata (name/role/subjectKind) keyed by uuid,
 * for building node labels.
 */
async function buildCanonicalizationMap(db: DataSource): Promise<{
  canonicalize: Map<string, string>; // ephemeral uuid -> canonical uuid
  metaByUuid: Map<string, { name: string | null; role: string; subjectKind: string; did: string | null }>;
  ephemeralUuids: Set<string>;
}> {
  const rows = await db.all<IdentityMetaRow>(`
    SELECT
      i.uuid AS identity_uuid,
      i.name AS name,
      i.role AS role,
      i.subject_kind AS subject_kind,
      CASE WHEN NOT EXISTS (
        SELECT 1 FROM did_documents dd2
        WHERE dd2.identity_uuid = i.uuid
          AND NOT (dd2.method = 'did:peer:4' AND dd2.recorded_by_node = 'tsp-bridge' AND dd2.is_primary = 0)
      ) THEN 1 ELSE 0 END AS is_ephemeral_peer4,
      encode(k.public_key, 'hex') AS ed25519_hex,
      (SELECT dd2.did FROM did_documents dd2
        WHERE dd2.identity_uuid = i.uuid
        ORDER BY dd2.is_primary DESC LIMIT 1) AS did
    FROM identities i
    LEFT JOIN keys k ON k.identity_uuid = i.uuid AND k.key_type = 'ed25519' AND k.rotation_version = 0
  `);

  const byKey = new Map<string, IdentityMetaRow[]>();
  for (const row of rows) {
    if (!row.ed25519_hex) continue;
    const group = byKey.get(row.ed25519_hex) ?? [];
    group.push(row);
    byKey.set(row.ed25519_hex, group);
  }

  const canonicalize = new Map<string, string>();
  const metaByUuid = new Map<string, { name: string | null; role: string; subjectKind: string; did: string | null }>();
  const ephemeralUuids = new Set<string>();

  for (const row of rows) {
    metaByUuid.set(row.identity_uuid, {
      name: row.name,
      role: row.role,
      subjectKind: row.subject_kind ?? 'human',
      did: row.did,
    });
  }

  for (const [, group] of byKey) {
    const real = group.find(r => r.is_ephemeral_peer4 === 0);
    const ephemerals = group.filter(r => r.is_ephemeral_peer4 === 1);
    if (real && ephemerals.length > 0) {
      for (const eph of ephemerals) {
        canonicalize.set(eph.identity_uuid, real.identity_uuid);
        ephemeralUuids.add(eph.identity_uuid);
      }
    }
  }

  return { canonicalize, metaByUuid, ephemeralUuids };
}

function resolveUuid(canonicalize: Map<string, string>, uuid: string): string {
  return canonicalize.get(uuid) ?? uuid;
}

export function registerGraphEdgesRoute(app: FastifyInstance, db: DataSource): void {
  app.get('/graph/edges', async (req: FastifyRequest<{ Querystring: GraphEdgesQuery }>, reply: FastifyReply) => {
    const { identityUuid, format } = req.query;

    if (format === 'graph') {
      return sendGraphFormat(db, reply);
    }

    return sendLegacyFormat(db, identityUuid, reply);
  });
}

// ---------------------------------------------------------------------------
// format=graph — UUID-canonicalized {nodes, edges}
// ---------------------------------------------------------------------------

async function sendGraphFormat(db: DataSource, reply: FastifyReply) {
  const { canonicalize, metaByUuid } = await buildCanonicalizationMap(db);

  const credRows = await db.all<{
    uuid: string; issuer_identity_uuid: string; subject_identity_uuid: string;
    vc_type: string; status: string;
    claim: string | null; valid_from: number; valid_until: number | null; threshold_required: number | null;
  }>(`SELECT uuid, issuer_identity_uuid, subject_identity_uuid, vc_type, status,
             claim, valid_from, valid_until, threshold_required
      FROM credentials WHERE status NOT IN ('revoked', 'expired')`);

  const delRows = await db.all<{
    uuid: string; principal_identity_uuid: string; dependent_identity_uuid: string;
    relationship_type: string;
  }>(`SELECT uuid, principal_identity_uuid, dependent_identity_uuid, relationship_type
      FROM delegations WHERE revoked_at IS NULL`);

  const relRows = await db.all<{
    uuid: string; local_identity_uuid: string; remote_identity_uuid: string;
    direction: string; status: string;
  }>(`SELECT uuid, local_identity_uuid, remote_identity_uuid, direction, status FROM relationships`);

  const nodeUuids = new Set<string>();
  const graphEdges: Array<{
    id: string; source: string; target: string; kind: string; label: string;
    vcType?: string; status?: string; relationshipType?: string; direction?: string;
    claim?: string | null; validFrom?: number; validUntil?: number | null; thresholdRequired?: number | null;
  }> = [];

  for (const c of credRows) {
    const source = resolveUuid(canonicalize, c.issuer_identity_uuid);
    const target = resolveUuid(canonicalize, c.subject_identity_uuid);
    if (source === target) continue;
    nodeUuids.add(source);
    nodeUuids.add(target);
    graphEdges.push({
      id: `credential:${c.uuid}`, source, target,
      kind: 'credential', label: c.vc_type, vcType: c.vc_type, status: c.status,
      claim: c.claim, validFrom: c.valid_from, validUntil: c.valid_until,
      thresholdRequired: c.threshold_required,
    });
  }

  for (const d of delRows) {
    const source = resolveUuid(canonicalize, d.principal_identity_uuid);
    const target = resolveUuid(canonicalize, d.dependent_identity_uuid);
    if (source === target) continue;
    nodeUuids.add(source);
    nodeUuids.add(target);
    graphEdges.push({
      id: `delegation:${d.uuid}`, source, target,
      kind: 'delegation', label: d.relationship_type, relationshipType: d.relationship_type,
    });
  }


  // Layer-2 peer links — surfaced as 'peer' edges so the utility server's
  // own node visibly connects to each VTA it has a relationship with.
  // remote_identity_uuid is almost always the ephemeral did:peer:4
  // handshake identity; canonicalize it to the real VTA.
  for (const r of relRows) {
    const source = resolveUuid(canonicalize, r.local_identity_uuid);
    const target = resolveUuid(canonicalize, r.remote_identity_uuid);
    if (source === target) continue;
    nodeUuids.add(source);
    nodeUuids.add(target);
    graphEdges.push({
      id: `peer:${r.uuid}`, source, target,
      kind: 'peer', label: 'peer', status: r.status, direction: r.direction,
    });
  }

  // Fresh namespace with no edges yet — show all non-ephemeral identities
  // as standalone nodes instead of a blank canvas.
  if (nodeUuids.size === 0) {
    for (const [uuid] of metaByUuid) {
      if (canonicalize.has(uuid)) continue; // skip ephemeral peer4 identities
      nodeUuids.add(uuid);
    }
  }

  // VTC membership — collect the active members of each community so the
  // frontend can list them when a VTC node is clicked.
  const memberRows = await db.all<{
    community_identity_uuid: string; member_identity_uuid: string; role: string;
  }>(`SELECT community_identity_uuid, member_identity_uuid, role
      FROM memberships WHERE status = 'active'`);

  const membersByCommunity = new Map<string, GraphMember[]>();
  for (const m of memberRows) {
    const community = resolveUuid(canonicalize, m.community_identity_uuid);
    const memberUuid = resolveUuid(canonicalize, m.member_identity_uuid);
    if (community === memberUuid) continue;
    const memberMeta = metaByUuid.get(memberUuid);
    const list = membersByCommunity.get(community) ?? [];
    list.push({
      uuid: memberUuid,
      label: memberMeta?.name || `#${memberUuid.slice(0, 8)}`,
      role: m.role,
    });
    membersByCommunity.set(community, list);
  }

  const nodes: GraphNode[] = [];
  for (const uuid of nodeUuids) {
    const meta = metaByUuid.get(uuid);
    const role = meta?.role ?? 'vta';
    nodes.push({
      id: uuid,
      label: meta?.name || `#${uuid.slice(0, 8)}`,
      role,
      subjectKind: meta?.subjectKind ?? 'human',
      identityUuid: uuid,
      did: meta?.did ?? null,
      members: role === 'vtc' ? (membersByCommunity.get(uuid) ?? []) : undefined,
    });
  }

  return reply.code(200).send({
    nodes,
    edges: graphEdges,
    edgeCount: graphEdges.length,
  });
}


// ---------------------------------------------------------------------------
// Legacy edge-list format (integer identity ids) — unchanged behavior
// ---------------------------------------------------------------------------

async function sendLegacyFormat(
  db: DataSource,
  filterIdentityUuid: string | undefined,
  reply: FastifyReply,
) {
  const edges: GraphEdge[] = [];

  const credentials = await credentialsRepo.list(db);
  for (const credential of credentials) {
    if (credential.status === 'revoked' || credential.status === 'expired') continue;
    if (
      filterIdentityUuid !== undefined &&
      credential.issuerIdentityUuid !== filterIdentityUuid &&
      credential.subjectIdentityUuid !== filterIdentityUuid
    ) {
      continue;
    }
    edges.push({
      kind: 'credential',
      id: `credential:${credential.uuid}`,
      from: credential.issuerIdentityUuid,
      to: credential.subjectIdentityUuid,
      vcType: credential.vcType,
      status: credential.status,
      credentialId: credential.uuid,
    });
  }

  const delegations = await delegationsRepo.list(db);
  for (const delegation of delegations) {
    if (delegation.revokedAt !== null) continue;
    if (
      filterIdentityUuid !== undefined &&
      delegation.principalIdentityUuid !== filterIdentityUuid &&
      delegation.dependentIdentityUuid !== filterIdentityUuid
    ) {
      continue;
    }
    edges.push({
      kind: 'delegation',
      id: `delegation:${delegation.uuid}`,
      from: delegation.principalIdentityUuid,
      to: delegation.dependentIdentityUuid,
      relationshipType: delegation.relationshipType,
      delegationId: delegation.uuid,
    });
  }

  return reply.code(200).send({
    edgeCount: edges.length,
    edges,
  });
}
