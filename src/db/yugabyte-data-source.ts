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
}

function convertPlaceholders(sql: string): string {
  let index = 0;
  return sql.replace(/\?/g, () => {
    index++;
    return `$${index}`;
  });
}

export class YugabyteDataSource implements DataSource {
  private _pool: InstanceType<typeof Pool>;
  private _closed: boolean = false;

  constructor(config: YugabyteConfig) {
    this._pool = new Pool({
      host: config.host,
      port: config.port,
      database: config.database,
      user: config.user,
      password: config.password,
      max: config.poolMax ?? 10,
      min: config.poolMin ?? 2,
    });

    this._pool.on('error', (err: Error) => {
      console.error('[YugabyteDataSource] Pool error:', err.message);
    });
  }

  async all<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T[]> {
    const converted = convertPlaceholders(sql);
    const result = await this._pool.query(converted, params);
    return result.rows as T[];
  }

  async get<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T | null> {
    const converted = convertPlaceholders(sql);
    const result = await this._pool.query(converted, params);
    return (result.rows[0] as T) ?? null;
  }

  async run(sql: string, ...params: unknown[]): Promise<QueryResult> {
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
  }

  async exec(sql: string): Promise<void> {
    // pg supports multi-statement queries natively.
    await this._pool.query(sql);
  }

  async transaction<T>(fn: (ds: DataSource) => Promise<T>): Promise<T> {
    const maxRetries = 3;
    const baseDelayMs = 50;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      const client = await this._pool.connect();
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
        await client.query('COMMIT');
        return result;
      } catch (err: unknown) {
        await client.query('ROLLBACK');
        const pgErr = err as { code?: string };
        if (pgErr?.code === '40001' && attempt < maxRetries - 1) {
          const delay = baseDelayMs * Math.pow(2, attempt);
          console.warn(`[YugabyteDataSource] Serialization failure, retrying in ${delay}ms (attempt ${attempt + 1}/${maxRetries})`);
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