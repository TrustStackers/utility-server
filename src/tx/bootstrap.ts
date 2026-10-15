/**
 * Transaction Coordinator Bootstrap — initializes the transaction
 * coordination layer for the utility server.
 *
 * This module:
 *   1. Opens the dedicated tx-coordinator.db SQLite database
 *   2. Applies the schema
 *   3. Creates the TransactionLog, TransactionCoordinator,
 *      CompensationExecutor, and TransactionManager
 *   4. Registers the VtcCreationParticipant
 *   5. Starts the TTL janitor
 *   6. Recovers any interrupted transactions from the log
 *
 * Usage (in utility-server/src/index.ts):
 *   const tx = await bootstrapTxCoordinator(appDb, { serverId: 'us-1' });
 *   // tx.manager is the TransactionManager
 *   // tx.coordinator is the TransactionCoordinator
 *   // tx.vtcParticipant is the VtcCreationParticipant
 */

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import {
  DataSourceLogSink,
  TransactionLog,
  TransactionCoordinator,
  makePreparedPidResolver,
  CompensationExecutor,
  TransactionManager,
  TxJanitor,
  TX_SCHEMA_SQL,
  applyTxSchemaAdditions,
  CeremonyStore,
  createDedupedTxInbound,
} from '@p2p-trust-stack/core/tx/index.js';
import type { Transaction, TxWireMessage, DedupedTxInboundResult } from '@p2p-trust-stack/core/tx/index.js';
import { VtcCreationParticipant } from './vtc-participant.js';
import { CeremonyCoordinatorParticipant } from './ceremony-participant.js';
import { GovernanceChangeParticipant } from './governance-change-participant.js';
import { NameRegistryParticipant } from './name-registry-participant.js';
import { ExchangeQueryParticipant, RECORD_SETS } from '@p2p-trust-stack/core/exchange/index.js';
import type { Participant } from '@p2p-trust-stack/core/tx/types.js';
import { ExchangePushParticipant } from './exchange-push-participant.js';
import { registerVtcMaterializers, registerCredentialMaterializer, registerGovernanceProposalMaterializer, registerCeremonyEventMaterializer } from '../services/vtc-push-data.js';

/**
 * Assert the coordinator's `handlesOperation` dispatch partition: every known
 * coordinator op must be claimed by exactly ONE participant (no overlap, no
 * vacuum). Throws with a descriptive message otherwise so a mis-claimed op
 * fails fast at boot instead of being silently swallowed or double-dispatched.
 */
export function assertDispatchPartition(
  participants: readonly Participant[],
): void {
  // The ops that actually cross the wire as coordinator ops today. The
  // exchange:* names are derived from the catalog, EXCLUDING recordsets that
  // are not coordinator-dispatched: queue-row (delivered by AgentDeliveryQueue)
  // and pubsub/utilities broadcast (delivered by ExchangePubsubParticipant over
  // the replication topic, not the 2PC coordinator).
  const knownOps = [
    'name_register',
    'name_revoke',
    'name_check',
    'vtc_join',
    'vtc_invite',
    'vtc_accept',
    'ceremony_begin',
    'ceremony_approve',
    'ceremony_query',
    'ceremony_reset',
    'ceremony_reconcile',
    ...RECORD_SETS
      .filter((d) => d.transport.delivery !== 'queue-row' && d.transport.delivery !== 'pubsub')
      .map((d) => `exchange:${d.name}`),
  ];

  for (const op of knownOps) {
    const claimers = participants.filter(
      (p) => typeof p.handlesOperation === 'function' && p.handlesOperation!({ op, params: {} }),
    );
    if (claimers.length === 0) {
      throw new Error(`dispatch partition: op '${op}' claimed by NO participant (vacuum)`);
    }
    if (claimers.length > 1) {
      throw new Error(
        `dispatch partition: op '${op}' claimed by ${claimers.length} participants (overlap): ` +
          claimers.map((c) => c.pid).join(', '),
      );
    }
  }
}

export interface TxBootstrapOptions {
  /** Server identifier for participant pids (default: 'us-1'). */
  serverId?: string;
  /** Path to the tx-coordinator.db file (default: 'data/tx/tx-coordinator.db'). */
  dbPath?: string;
}

export interface TxBootstrapResult {
  manager: TransactionManager;
  coordinator: TransactionCoordinator;
  compensation: CompensationExecutor;
  janitor: TxJanitor;
  vtcParticipant: VtcCreationParticipant;
  ceremonyParticipant: CeremonyCoordinatorParticipant;
  governanceChangeParticipant: GovernanceChangeParticipant;
  nameRegistryParticipant: NameRegistryParticipant;
  ceremonyStore: CeremonyStore;
  txDataSource: DataSource;
  /**
   * Inbound 2PC entry point, DEDUPED on `(txId, messageId)` (H7 / decision D-4a).
   * Route inbound tx_* messages through this, not `coordinator.handleInboundTxMessage`
   * directly — `recover()` re-drives and outbox retries produce replays by design, and
   * the operations they carry are not idempotent in general.
   *
   * `duplicate: true` means "recognised and deliberately dropped": treat it as HANDLED.
   */
  handleInboundTxMessage: (msg: TxWireMessage) => Promise<DedupedTxInboundResult>;
  /** Exchange query participant (CRE) — answers pull queries. */
  exchangeQueryParticipant: ExchangeQueryParticipant;
  /** Exchange push participant (CRE) — applies exchange:identity pushes. */
  exchangePushParticipant: ExchangePushParticipant;
  /** Shut down the transaction layer cleanly. */
  shutdown: () => Promise<void>;
}

export async function bootstrapTxCoordinator(
  appDb: DataSource,
  options: TxBootstrapOptions = {},
): Promise<TxBootstrapResult> {
  const serverId = options.serverId ?? 'us-1';
  const dbPath = options.dbPath ?? 'data/tx/tx-coordinator.db';

  // Open the dedicated SQLite database for the transaction coordinator.
  // SqliteDataSource handles directory creation internally.
  const txDataSource = new SqliteDataSource(dbPath);

  // Apply schema
  await txDataSource.exec(TX_SCHEMA_SQL);
  // Existing databases keep their original tables (CREATE TABLE IF NOT EXISTS
  // never alters one), so columns added in later builds are applied here.
  const addedColumns = await applyTxSchemaAdditions(txDataSource);
  console.log(`[tx-bootstrap] tx-coordinator.db initialized at ${dbPath}`
    + (addedColumns.length > 0 ? ` (schema additions: ${addedColumns.join(', ')})` : ''));

  // Create the log sink and transaction log
  const sink = new DataSourceLogSink(txDataSource);
  const log = new TransactionLog(sink);

  // Create the coordinator. The prepared-pid resolver lets a commit/abort/inquiry
  // that arrives after a server restart reach the participant that actually
  // prepared — the case that made `tx_commit` commit the WRONG participant.
  const coordinator = new TransactionCoordinator(log, {
    resolvePreparedPid: makePreparedPidResolver(txDataSource),
  });

  // Create the compensation executor
  const compensation = new CompensationExecutor();

  // Nested child transactions register a `_compensateChild` descriptor on their
  // parent; this handler is what makes a parent abort undo an already-committed
  // child instead of logging `no CompensationHandler registered`. (The server
  // still drives its `undo_hooks` in-process; this covers any nested scope.)
  compensation.register({
    type: '_compensateChild',
    async execute(desc) {
      const child = (desc as unknown as { child?: Transaction }).child;
      if (!child) return;
      await child.compensate();
    },
  });

  // Create the VTC creation participant
  const vtcParticipant = new VtcCreationParticipant(
    `server:${serverId}`,
    appDb,
    txDataSource,
  );
  coordinator.registerParticipant(vtcParticipant);

  // Create the ceremony coordinator participant (agent-facing ceremony lifecycle)
  const ceremonyParticipant = new CeremonyCoordinatorParticipant(
    `server:${serverId}`,
    appDb,
    txDataSource,
  );
  coordinator.registerParticipant(ceremonyParticipant);

  // Governance-change consent participant (Phase B): proposes a community rule/
  // threshold change, collects signed approvals, and crystallizes via the cataloged
  // `governance-change` ceremony (policy gate + apply effect).
  const governanceChangeParticipant = new GovernanceChangeParticipant(
    `server:${serverId}`,
    appDb,
    txDataSource,
  );
  coordinator.registerParticipant(governanceChangeParticipant);

  // The identity push leg IS the CRE exchange:identity path — ExchangePushParticipant
  // delegates to IdentityPushParticipant.applyIdentityPushPayload (shared apply
  // logic). The standalone `identity_push` op + registration were retired with the
  // ceremony-site migration (see utility-server plan P4).

  // Create the name registry participant (agent → server name registration)
  const nameRegistryParticipant = new NameRegistryParticipant(
    `server:${serverId}`,
    appDb,
    txDataSource,
  );
  coordinator.registerParticipant(nameRegistryParticipant);

  // ── Exchange Query Participant (CRE, Phase 1) ───────────────────────────
  // Answers `exchange:<name>` pull queries from the RecordSet catalog.
  // Registered unconditionally since Phase C — the agents send `exchange:*`
  // coordinators in all paths (identity push is outbox-backed regardless of
  // the legacy flag), so the read side must always be present.
  // Register the server-side vtc-membership + governance recordset materializers
  // (buildVtcPushData now carries claim types + the governance digest; the
  // governance materializer serves thresholds + claim types for pull/queue-row).
  registerVtcMaterializers();
  console.log('[tx-bootstrap] vtc-membership + governance materializers registered');

  registerGovernanceProposalMaterializer();
  registerCeremonyEventMaterializer();
  console.log('[tx-bootstrap] governance-proposal materializer registered');

  // Phase 6: the credential recordset materializer (receive_credential).
  registerCredentialMaterializer();
  console.log('[tx-bootstrap] credential materializer registered');

  const exchangeQueryParticipant = new ExchangeQueryParticipant(
    `server:${serverId}`,
    appDb,
    txDataSource,
  );
  coordinator.registerParticipant(exchangeQueryParticipant);
  console.log('[tx-bootstrap] ExchangeQueryParticipant registered');

  // The durable identity/profile push path. The agent's outbox replays
  // `exchange:identity` as a 2PC; this participant applies it with the same
  // logic as the legacy IdentityPushParticipant.
  const exchangePushParticipant = new ExchangePushParticipant(
    `server:${serverId}`,
    appDb,
    txDataSource,
  );
  coordinator.registerParticipant(exchangePushParticipant);
  console.log('[tx-bootstrap] ExchangePushParticipant registered');

  // ── Dispatch partition assertion (Phase C) ─────────────────────────────
  // Every coordinator op the agents send must be claimed by exactly ONE
  // participant. No overlap, no vacuum. This is the guardrail that caught the
  // Phase 3 `exchange:identity`-swallowed-by-ExchangeQueryParticipant bug and
  // keeps legacy ops from being silently shadowed as they are retired.
  assertDispatchPartition([
    vtcParticipant,
    ceremonyParticipant,
    governanceChangeParticipant,
    nameRegistryParticipant,
    exchangeQueryParticipant,
    exchangePushParticipant,
  ]);
  console.log('[tx-bootstrap] dispatch partition assertion passed');

  // Create the transaction manager
  const manager = new TransactionManager(coordinator, compensation);

  // Create the ceremony store (Phase 3 — same tx-coordinator.db)
  const ceremonyStore = new CeremonyStore(txDataSource);

  // Start the TTL janitor
  const janitor = new TxJanitor(txDataSource);
  janitor.start();

  // Recover any interrupted transactions from the log
  try {
    const recovered = await coordinator.recover();
    if (recovered.length > 0) {
      console.log(`[tx-bootstrap] recovered ${recovered.length} interrupted transaction(s):`,
        recovered.map((r) => `${r.txId}=${r.outcome}`).join(', '));
    }
  } catch (err) {
    console.error('[tx-bootstrap] recovery error:', (err as Error)?.message ?? err);
  }

  // Subscribe to status events for logging
  manager.onStatus((event) => {
    console.log(`[tx ${event.txId.slice(0, 8)}] ${event.state}${event.detail ? `: ${event.detail}` : ''}`);
  });

  console.log(`[tx-bootstrap] transaction coordinator ready (serverId=${serverId})`);

  return {
    manager,
    coordinator,
    compensation,
    janitor,
    vtcParticipant,
    ceremonyParticipant,
    governanceChangeParticipant,
    nameRegistryParticipant,
    ceremonyStore,
    txDataSource,
    // H7 wiring: the ONE inbound 2PC entry point, deduped on (txId, messageId).
    handleInboundTxMessage: createDedupedTxInbound(
      (msg) => coordinator.handleInboundTxMessage(msg),
      txDataSource,
    ),
    exchangeQueryParticipant,
    exchangePushParticipant,
    shutdown: async () => {
      janitor.stop();
      await txDataSource.close();
      console.log('[tx-bootstrap] transaction coordinator shut down');
    },
  };
}