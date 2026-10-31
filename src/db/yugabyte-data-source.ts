// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * YugabyteDataSource — PostgreSQL/YugabyteDB-backed DataSource using `pg.Pool`.
 *
 * Key differences from SQLite:
 * - Async (PG driver is Promise-based)
 * - `?` → `$1, $2, ...` parameter placeholder conversion
 * - `exec()` sends multi-statement SQL directly (pg supports this natively)
 * - `transaction()` wraps with `BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE`
 *   and retries on serialization failures (40001) with exponential backoff.
 */

import type { DataSource, QueryResult } from '@p2p-trust-stack/core/db/data-source.js';

// Top-level dynamic import — ESM project, no require().
// Top-level await is supported in ES modules since Node 14.8+.
const { Pool } = (await import('pg')) as typeof import('pg');

export interface YugabyteConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  poolMax?: number;
  poolMin?: number;
  /**
   * Server-side per-statement deadline (ms), applied as the `statement_timeout`
   * startup parameter. `0` disables. Default 15_000.
   */
  statementTimeoutMs?: number;
  /**
   * Client-side deadline for reading a query's result (ms), enforced by `pg`
   * itself. `0` disables. Default 20_000 — deliberately ABOVE statementTimeoutMs
   * so a slow statement is cancelled by the SERVER first and the caller sees the
   * real PostgreSQL error (57014) instead of an opaque client-side socket timeout.
   */
  queryTimeoutMs?: number;
  /** Max time to wait for a pooled connection (ms). Default 10_000. */
  connectionTimeoutMs?: number;
  /** Close idle pool clients after this long (ms). Default 30_000. */
  idleTimeoutMs?: number;
  /**
   * Reap a transaction left `idle in transaction` (ms), applied as the
   * `idle_in_transaction_session_timeout` startup parameter. `0` disables.
   * Default 30_000.
   *
   * WHY THIS MATTERS HERE SPECIFICALLY: `transaction()` runs every unit of work
   * at SERIALIZABLE and retries serialization failures, so a client that stalls
   * mid-transaction (a slow `await` between statements, a dropped socket) holds
   * its row locks for as long as that client lives. A leaked `idle in
   * transaction` session is a well-known way to stall a tablet server — the same
   * `tserver_shared_mem.cc` "Timed out waiting kResponseSent" failure this class
   * now also retries.
   */
  idleInTransactionTimeoutMs?: number;
  /**
   * Attempts for a TRANSIENT error on a non-transactional query
   * (`get`/`all`/`run`/`exec`). Default 3; `1` disables retrying.
   */
  queryRetryAttempts?: number;
}

function convertPlaceholders(sql: string): string {
  let index = 0;
  return sql.replace(/\?/g, () => {
    index++;
    return `$${index}`;
  });
}

/**
 * Connection-level failure: the statement PROVABLY never executed (the socket
 * died, or the server refused before running it). ANY statement — read or write —
 * may therefore be retried without changing its meaning.
 */
function isConnectionLevelTransient(err: unknown): boolean {
  const e = err as { code?: string } | null;
  if (!e || typeof e.code !== 'string') return false;
  return e.code.startsWith('08') || e.code.startsWith('57P0') || e.code === '53300';
}

/**
 * Failure whose VERDICT IS UNKNOWN: the statement may or may not have executed.
 * Retryable for READS only — retrying a write could double-apply it.
 *
 * `57014` is our own `statement_timeout` firing; `XX000` is the YugabyteDB
 * internal RPC timeout described below.
 */
function isAmbiguousTransient(err: unknown): boolean {
  const e = err as { code?: string; message?: string } | null;
  if (!e) return false;
  if (e.code === '57014') return true;
  return e.code === 'XX000' && /Timed out waiting kResponseSent/i.test(e.message ?? '');
}

/**
 * The YugabyteDB internal RPC timeout this class was hardened for.
 *
 * The YSQL backend gave up waiting for a tablet server: `severity ERROR`,
 * `code XX000`, `file tserver_shared_mem.cc`. It arrives as an ordinary thrown
 * error and carries NO verdict about whether the statement ran.
 *
 * Observed 2026-10-29 on the utility server: "Timed out waiting kResponseSent,
 * state: kProcessingRequest". EVERY DB touchpoint reported it — the delivery
 * drain, the connectivity member list, and the TSP bridge's peer lookup — and the
 * unretried bridge failure is what terminated the process.
 */
function isTransientDbError(err: unknown): boolean {
  return isConnectionLevelTransient(err) || isAmbiguousTransient(err);
}

/** Jittered exponential backoff for a retried query (`attempt` is 0-based). */
function retryDelayMs(attempt: number): number {
  const base = 50 * Math.pow(2, attempt);
  return Math.floor(base * (0.8 + Math.random() * 0.4));
}

export class YugabyteDataSource implements DataSource {
  private _pool: InstanceType<typeof Pool>;
  private _closed: boolean = false;
  /** Attempts for a transient error on a non-transactional query (>= 1). */
  private readonly _retryAttempts: number;

  constructor(config: YugabyteConfig) {
    const statementTimeoutMs = config.statementTimeoutMs ?? 15_000;
    const queryTimeoutMs = config.queryTimeoutMs ?? 20_000;
    const idleInTransactionTimeoutMs = config.idleInTransactionTimeoutMs ?? 30_000;

    this._retryAttempts = Math.max(1, config.queryRetryAttempts ?? 3);

    this._pool = new Pool({
      host: config.host,
      port: config.port,
      database: config.database,
      user: config.user,
      password: config.password,
      max: config.poolMax ?? 10,
      min: config.poolMin ?? 2,
      // ── Deadlines ────────────────────────────────────────────────────────
      // Previously the pool had ONLY max/min, so a stalled tablet server left
      // every query pending forever: the drain, the member list and the TSP
      // bridge all hung on one tserver hiccup and the process had no way to give
      // up and move on. `statement_timeout` is the SERVER's own deadline (so the
      // backend is cancelled and the locks it held are released);
      // `query_timeout` is `pg`'s client-side read deadline, set above it.
      connectionTimeoutMillis: config.connectionTimeoutMs ?? 10_000,
      idleTimeoutMillis: config.idleTimeoutMs ?? 30_000,
      keepAlive: true,
      application_name: 'p2p-trust-stack',
      ...(statementTimeoutMs > 0 ? { statement_timeout: statementTimeoutMs } : {}),
      ...(queryTimeoutMs > 0 ? { query_timeout: queryTimeoutMs } : {}),
      ...(idleInTransactionTimeoutMs > 0
        ? { idle_in_transaction_session_timeout: idleInTransactionTimeoutMs }
        : {}),
    });

    this._pool.on('error', (err: Error) => {
      console.error('[YugabyteDataSource] Pool error:', err.message);
    });
  }

  /**
   * Run `fn`, retrying only classified TRANSIENT failures.
   *
   * `readsOnly` distinguishes the two safety classes (see
   * {@link isConnectionLevelTransient} / {@link isAmbiguousTransient}): a read may
   * be retried whenever the failure is transient, a WRITE only when the statement
   * provably never executed. That asymmetry is the whole point — a lost verdict on
   * an INSERT must not be silently converted into a second INSERT.
   *
   * NOT used inside `transaction()`: a per-statement retry there would run
   * against a transaction the server has already abandoned. That method owns its
   * own retry loop.
   */
  private async withTransientRetry<T>(fn: () => Promise<T>, readsOnly: boolean): Promise<T> {
    const attempts = this._retryAttempts;
    for (let attempt = 0; ; attempt++) {
      try {
        return await fn();
      } catch (err) {
        const retryable = readsOnly ? isTransientDbError(err) : isConnectionLevelTransient(err);
        if (!retryable || attempt >= attempts - 1) throw err;
        const delay = retryDelayMs(attempt);
        console.warn(
          `[YugabyteDataSource] transient DB error (attempt ${attempt + 1}/${attempts}), ` +
          `retrying in ${delay}ms: ${(err as Error)?.message ?? err}`,
        );
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }

  async all<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T[]> {
    const converted = convertPlaceholders(sql);
    return this.withTransientRetry(async () => {
      const result = await this._pool.query(converted, params);
      return result.rows as T[];
    }, true);
  }

  async get<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T | null> {
    const converted = convertPlaceholders(sql);
    return this.withTransientRetry(async () => {
      const result = await this._pool.query(converted, params);
      return (result.rows[0] as T) ?? null;
    }, true);
  }

  async run(sql: string, ...params: unknown[]): Promise<QueryResult> {
    // readsOnly=false: a write is retried only when the statement provably never
    // executed (see withTransientRetry).
    return this.withTransientRetry(async () => {
      const trimmed = sql.trim();
      const isSimpleInsert = /^\s*INSERT\s+/i.test(trimmed) &&
        !/ON\s+CONFLICT/i.test(trimmed) &&
        !/RETURNING\s+/i.test(trimmed);

      if (isSimpleInsert) {
        // Try RETURNING id first; if the table has no "id" column (e.g. schema_migrations),
        // fall back to a plain INSERT. No savepoint needed — outside a transaction,
        // a failed query doesn't abort anything.
        try {
          const finalSql = convertPlaceholders(sql).replace(/;\s*$/, '') + ' RETURNING id';
          const result = await this._pool.query(finalSql, params);
          const lastId = result.rows.length > 0 ? result.rows[0].id : undefined;
          return { changes: result.rowCount ?? 0, lastInsertRowid: lastId };
        } catch (err) {
          if ((err as { code?: string }).code === '42703') {
            const result = await this._pool.query(convertPlaceholders(sql), params);
            return { changes: result.rowCount ?? 0, lastInsertRowid: undefined };
          }
          throw err;
        }
      }

      const result = await this._pool.query(convertPlaceholders(sql), params);
      return { changes: result.rowCount ?? 0, lastInsertRowid: undefined };
    }, false);
  }

  async exec(sql: string): Promise<void> {
    // pg supports multi-statement queries natively.
    // readsOnly=false — DDL/multi-statement exec is not safe to re-run blindly.
    await this.withTransientRetry(async () => {
      await this._pool.query(sql);
    }, false);
  }

  async transaction<T>(fn: (ds: DataSource) => Promise<T>): Promise<T> {
    const maxRetries = 3;
    const baseDelayMs = 50;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      const client = await this._pool.connect();
      // Set immediately BEFORE the COMMIT is issued — see the catch below. Once the
      // COMMIT is in flight the server may have applied the transaction even though
      // the response was lost, so no failure at or after this point may be retried.
      let commitIssued = false;
      try {
        await client.query('BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE');

        const txDs: DataSource = {
          all: async <R = Record<string, unknown>>(s: string, ...p: unknown[]) => {
            const r = await client.query(convertPlaceholders(s), p);
            return r.rows as R[];
          },
          get: async <R = Record<string, unknown>>(s: string, ...p: unknown[]) => {
            const r = await client.query(convertPlaceholders(s), p);
            return (r.rows[0] as R) ?? null;
          },
          run: async (s: string, ...p: unknown[]) => {
            const trimmed = s.trim();
            const isSimpleInsert = /^\s*INSERT\s+/i.test(trimmed) &&
              !/ON\s+CONFLICT/i.test(trimmed) &&
              !/RETURNING\s+/i.test(trimmed);

            if (isSimpleInsert) {
              // Use a savepoint so a failed RETURNING id doesn't abort the transaction.
              try {
                await client.query('SAVEPOINT tx_run_sp');
                const finalSql = convertPlaceholders(s).replace(/;\s*$/, '') + ' RETURNING id';
                const r = await client.query(finalSql, p);
                await client.query('RELEASE SAVEPOINT tx_run_sp');
                const lastId = r.rows.length > 0 ? r.rows[0].id : undefined;
                return { changes: r.rowCount ?? 0, lastInsertRowid: lastId };
              } catch (err) {
                await client.query('ROLLBACK TO SAVEPOINT tx_run_sp');
                if ((err as { code?: string }).code === '42703') {
                  const r = await client.query(convertPlaceholders(s), p);
                  return { changes: r.rowCount ?? 0, lastInsertRowid: undefined };
                }
                throw err;
              }
            }

            const r = await client.query(convertPlaceholders(s), p);
            return { changes: r.rowCount ?? 0, lastInsertRowid: undefined };
          },
          exec: async (s: string) => {
            // pg supports multi-statement queries natively.
            await client.query(s);
          },
          transaction: async <R2>(inner: (ds2: DataSource) => Promise<R2>) => inner(txDs),
          close: async () => { /* no-op */ },
        };

        const result = await fn(txDs);
        commitIssued = true;
        await client.query('COMMIT');
        return result;
      } catch (err: unknown) {
        // A failed ROLLBACK must not REPLACE the original error — the caller needs
        // to classify that one (and on a dead connection there is nothing to roll
        // back anyway).
        try {
          await client.query('ROLLBACK');
        } catch {
          // Connection already gone.
        }

        const pgErr = err as { code?: string };
        const serializationFailure = pgErr?.code === '40001';
        // Retry a TRANSIENT failure only while no COMMIT has been issued. A
        // connection-level failure (the transaction was never executed / was lost
        // entirely) is safe to replay; an ambiguous one (XX000 kResponseSent,
        // 57014 statement_timeout) is NOT, because the work may have been applied.
        const retryableTransient = !commitIssued && isConnectionLevelTransient(err);
        if ((serializationFailure || retryableTransient) && attempt < maxRetries - 1) {
          const delay = baseDelayMs * Math.pow(2, attempt);
          console.warn(
            `[YugabyteDataSource] ${serializationFailure ? 'Serialization failure' : 'Transient DB error'}, ` +
            `retrying in ${delay}ms (attempt ${attempt + 1}/${maxRetries})`,
          );
          await new Promise((resolve) => setTimeout(resolve, delay));
          continue;
        }
        throw err;
      } finally {
        client.release();
      }
    }
    throw new Error('[YugabyteDataSource] Transaction failed after all retries');
  }

  async close(): Promise<void> {
    if (this._closed) return;
    this._closed = true;
    await this._pool.end();
  }
}