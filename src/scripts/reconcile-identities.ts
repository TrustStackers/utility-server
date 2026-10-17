// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Identity / DID-document / verification-key reconciliation for the utility
 * server's database (YugabyteDB — the same connection the server uses).
 *
 * REPORT ONLY by default; nothing is written unless you pass --fix:
 *
 *   npm run reconcile:identities            # report
 *   npm run reconcile:identities -- --fix   # apply the in-identity repairs
 *
 * What --fix does (all within a single identity row — no cross-identity merging,
 * no identity deletion):
 *   1. an identity with more than one primary did_documents row → keeps the best,
 *      demotes the rest;
 *   2. an identity with no primary document (handshake stubs) → promotes the best
 *      candidate, which is what makes `Identity.did` resolve again instead of
 *      falling back to a UUID (the D12 symptom);
 *   3. duplicate active keys rows for one (identity, key_type, rv=0) → keeps the
 *      row linked to the primary document, removes the others.
 *
 * Reported but NOT applied — these need a human decision:
 *   - non-canonical identities (uuid ≠ UUIDv5(primaryDid)) — the pre-v3
 *     VID-keyed stubs — including whether a canonical row already exists;
 *   - orphan identities with no did_documents row at all.
 *
 * Safe to re-run: every fix is idempotent and the report is deterministic.
 */
import { loadConfig } from '../config.js';
import { YugabyteDataSource } from '../db/yugabyte-data-source.js';
import { reconcileIdentities, type ReconcileReport } from '@p2p-trust-stack/core/db/reconcile-identities.js';

function printReport(report: ReconcileReport, fix: boolean): void {
  const { scanned } = report;
  console.log(
    `\n[reconcile] scanned ${scanned.identities} identit(ies), ${scanned.documents} did_document(s), ` +
    `${scanned.keyRows} active key row(s)\n`,
  );

  const section = (title: string, items: string[]): void => {
    console.log(`[reconcile] ${title}: ${items.length}`);
    for (const line of items) console.log(`           ${line}`);
  };

  section('identities with MULTIPLE primary documents', report.multiplePrimaries.map((f) =>
    `${f.identityUuid} keep ${f.keptDid} (${f.keptDocUuid.slice(0, 8)}…) demote ${f.otherDocUuids.length}`,
  ));
  section('identities with NO primary document', report.missingPrimary.map((f) =>
    `${f.identityUuid} promote ${f.keptDid} (${f.keptDocUuid.slice(0, 8)}…)`,
  ));
  section('duplicate ACTIVE keys for one (identity, type)', report.duplicateActiveKeys.map((f) =>
    `${f.identityUuid} ${f.keyType} keep ${f.keptKeyUuid.slice(0, 8)}… remove ${f.removedKeyUuids.length}`,
  ));
  section('NON-CANONICAL identities (uuid ≠ UUIDv5(primaryDid)) — report only', report.nonCanonicalIdentities.map((i) =>
    `${i.identityUuid} → expected ${i.expectedUuid}${i.canonicalRowExists ? ' (CANONICAL ROW ALSO EXISTS — merge candidate)' : ''} did=${i.primaryDid}`,
  ));
  section('ORPHAN identities (no did_documents row) — report only', report.orphanIdentities.map((i) =>
    `${i.identityUuid} custody=${i.custody} name=${JSON.stringify(i.name)}`,
  ));

  if (fix) {
    console.log(
      `\n[reconcile] APPLIED: ${report.applied.documentFixes} document fix(es), ${report.applied.keyFixes} key fix(es)\n`,
    );
  } else {
    const actionable =
      report.multiplePrimaries.length + report.missingPrimary.length + report.duplicateActiveKeys.length;
    console.log(
      actionable > 0
        ? `\n[reconcile] REPORT ONLY — ${actionable} repair(s) available. Re-run with --fix to apply.\n`
        : '\n[reconcile] REPORT ONLY — nothing to repair.\n',
    );
  }
}

async function main(): Promise<void> {
  const fix = process.argv.includes('--fix');
  const config = loadConfig();

  console.log(
    `[reconcile] connecting to YugabyteDB at ${config.ybHost}:${config.ybPort}/${config.ybDatabase} ` +
    `(mode: ${fix ? 'APPLY (--fix)' : 'report only'})`,
  );
  const ds = new YugabyteDataSource({
    host: config.ybHost,
    port: config.ybPort,
    database: config.ybDatabase,
    user: config.ybUser,
    password: config.ybPassword,
    poolMin: config.ybPoolMin,
    poolMax: config.ybPoolMax,
  });

  try {
    const report = await reconcileIdentities(ds, { fix });
    printReport(report, fix);
  } finally {
    await ds.close();
  }
}

main().catch((err: unknown) => {
  console.error('[reconcile] failed:', (err as Error)?.message ?? err);
  process.exitCode = 1;
});
