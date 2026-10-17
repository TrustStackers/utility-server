// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Layer 5 — Trust Applications: GET /dashboard/summary
 *
 * Top-level counts for the UI dashboard (ui/index.html): total VTAs, VTCs,
 * VTNs, VRCs, and "Other Credentials" (every non-VRC credential type
 * combined: vmc + vec + custom_endorsement + delegation), plus a breakdown
 * of VTAs by subject_kind. A read-only composition over identities +
 * credentials, per docs/vta-dashboard-ui-plan.md.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance } from 'fastify';

interface CountRow {
  count: number;
}

interface SubjectKindCountRow {
  subject_kind: string | null;
  count: number;
}

export function registerSummaryRoute(app: FastifyInstance, db: DataSource): void {
  app.get('/dashboard/summary', async () => {
    const countByRole = async (role: 'vta' | 'vtc' | 'vtn'): Promise<number> => {
      const row = await db.get<CountRow>(
        `SELECT COUNT(*)::int as count FROM identities i
         JOIN did_documents dd ON dd.identity_uuid = i.uuid AND dd.is_primary = 1
         WHERE i.role = ?`,
        role,
      );
      return row?.count ?? 0;
    };

    const vrcRow = await db.get<CountRow>(
      `SELECT COUNT(*)::int as count FROM credentials WHERE vc_type = 'vrc'`,
    );
    const vrcCount = vrcRow?.count ?? 0;

    const otherRow = await db.get<CountRow>(
      `SELECT COUNT(*)::int as count FROM credentials WHERE vc_type != 'vrc'`,
    );
    const otherCredentialCount = otherRow?.count ?? 0;

    const nameRow = await db.get<CountRow>(
      `SELECT COUNT(*)::int as count FROM name_registry WHERE revoked_at IS NULL`,
    );
    const nameCount = nameRow?.count ?? 0;

    const subjectKindRows = await db.all<SubjectKindCountRow>(
      `SELECT i.subject_kind, COUNT(*)::int as count
       FROM identities i
       JOIN did_documents dd ON dd.identity_uuid = i.uuid AND dd.is_primary = 1
       WHERE i.role = 'vta'
       GROUP BY i.subject_kind`,
    );

    const vtaBySubjectKind: Record<string, number> = {};
    for (const row of subjectKindRows) {
      vtaBySubjectKind[row.subject_kind ?? 'unknown'] = row.count;
    }

    return {
      names: nameCount,
      vtas: await countByRole('vta'),
      vtcs: await countByRole('vtc'),
      vtns: await countByRole('vtn'),
      vrcs: vrcCount,
      otherCredentials: otherCredentialCount,
      vtaBySubjectKind,
    };
  });
}