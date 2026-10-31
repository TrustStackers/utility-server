// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests: YugabyteDataSource — transient-error classification and retry.
 *
 * WHY: on 2026-10-29 a single YugabyteDB internal RPC timeout
 * (`XX000`, `tserver_shared_mem.cc`: "Timed out waiting kResponseSent, state:
 * kProcessingRequest") was raised on EVERY DB touchpoint of the utility server.
 * The pool had no deadlines and no retry, so the error travelled straight out of
 * the TSP bridge's peer lookup and terminated the process.
 *
 * These tests pin the contract that replaced that:
 *   - a READ retries an ambiguous transient failure (XX000 kResponseSent, 57014);
 *   - a WRITE does NOT retry it (the statement may already have been applied);
 *   - a WRITE DOES retry a connection-level failure (provably never executed);
 *   - a deterministic failure (23505 unique violation) is never retried;
 *   - the pool is actually configured with the query deadlines.
 *
 * The real class is exercised against a scripted fake pool (swapped in via its
 * private `_pool`), so this is not a re-implementation of the logic under test.
 *
 * Run with:
 *   node --conditions=development --experimental-strip-types --loader ../test-loader.mjs \
 *     --test test/db/yugabyte-data-source-retry.test.ts
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { YugabyteDataSource } from '../../src/db/yugabyte-data-source.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** The exact error shape the field log carried. */
function ybRpcTimeout(): Error {
  return Object.assign(
    new Error('Timed out waiting kResponseSent, state: kProcessingRequest'),
    { code: 'XX000', severity: 'ERROR', file: 'tserver_shared_mem.cc', line: '214' },
  );
}

function connectionFailure(): Error {
  return Object.assign(new Error('Connection terminated unexpectedly'), { code: '08006' });
}

function uniqueViolation(): Error {
  return Object.assign(
    new Error('duplicate key value violates unique constraint'),
    { code: '23505' },
  );
}

type Step = Error | { rows: unknown[]; rowCount: number };

/** Minimal stand-in for `pg.Pool`: records every query and replays a script. */
function makeFakePool(script: Step[]): {
  pool: Record<string, unknown>;
  calls: Array<{ sql: string; params: unknown[] }>;
} {
  const calls: Array<{ sql: string; params: unknown[] }> = [];
  let index = 0;
  const pool: Record<string, unknown> = {
    on(): unknown {
      return pool;
    },
    async query(sql: string, params?: unknown[]): Promise<unknown> {
      calls.push({ sql, params: params ?? [] });
      const step = script[Math.min(index, script.length - 1)];
      index++;
      if (step instanceof Error) throw step;
      return step;
    },
    async connect(): Promise<never> {
      throw new Error('fake pool: connect() is not exercised by these tests');
    },
    async end(): Promise<void> {
      /* noop */
    },
  };
  return { pool, calls };
}

function makeDs(overrides: Record<string, unknown> = {}): YugabyteDataSource {
  return new YugabyteDataSource({
    host: '127.0.0.1',
    port: 5433,
    database: 'yugabyte',
    user: 'yugabyte',
    password: 'yugabyte',
    queryRetryAttempts: 3,
    ...overrides,
  });
}

/** Swap the class's private pool for a scripted fake. */
function swapPool(ds: YugabyteDataSource, pool: unknown): void {
  (ds as unknown as { _pool: unknown })._pool = pool;
}

// ---------------------------------------------------------------------------
// Pool configuration
// ---------------------------------------------------------------------------

describe('YugabyteDataSource — pool deadlines', () => {
  it('configures statement / client / idle-in-transaction deadlines on the pool', () => {
    const ds = makeDs();
    const options = (ds as unknown as { _pool: { options: Record<string, unknown> } })._pool.options;

    // Before this change the pool had ONLY max/min, so a stalled tablet server
    // left every query pending indefinitely.
    assert.equal(options.statement_timeout, 15_000);
    assert.equal(options.query_timeout, 20_000);
    assert.equal(options.idle_in_transaction_session_timeout, 30_000);
    assert.equal(options.connectionTimeoutMillis, 10_000);
    assert.equal(options.keepAlive, true);
    void ds.close();
  });

  it('honours explicit overrides and omits a deadline set to 0', () => {
    const ds = makeDs({ statementTimeoutMs: 5_000, idleInTransactionTimeoutMs: 0 });
    const options = (ds as unknown as { _pool: { options: Record<string, unknown> } })._pool.options;

    assert.equal(options.statement_timeout, 5_000);
    assert.ok(!('idle_in_transaction_session_timeout' in options), 'a 0 deadline must be omitted');
    void ds.close();
  });
});

// ---------------------------------------------------------------------------
// Read retry
// ---------------------------------------------------------------------------

describe('YugabyteDataSource — read retry', () => {
  it('get() retries an ambiguous YB RPC timeout and returns the row', async () => {
    const { pool, calls } = makeFakePool([
      ybRpcTimeout(),
      ybRpcTimeout(),
      { rows: [{ uuid: 'did-doc-1' }], rowCount: 1 },
    ]);
    const ds = makeDs();
    swapPool(ds, pool);

    const row = await ds.get<{ uuid: string }>('SELECT * FROM did_documents WHERE uuid = ?', 'x');

    assert.deepEqual(row, { uuid: 'did-doc-1' });
    assert.equal(calls.length, 3, 'two transient failures then success');
    void ds.close();
  });

  it('all() rethrows the ORIGINAL error once attempts are exhausted', async () => {
    const { pool, calls } = makeFakePool([ybRpcTimeout()]);
    const ds = makeDs({ queryRetryAttempts: 3 });
    swapPool(ds, pool);

    await assert.rejects(
      () => ds.all('SELECT * FROM peer_endpoints'),
      (err: Error & { code?: string }) => err.code === 'XX000',
    );
    assert.equal(calls.length, 3, 'exactly queryRetryAttempts attempts');
    void ds.close();
  });

  it('queryRetryAttempts: 1 disables read retrying', async () => {
    const { pool, calls } = makeFakePool([ybRpcTimeout()]);
    const ds = makeDs({ queryRetryAttempts: 1 });
    swapPool(ds, pool);

    await assert.rejects(() => ds.get('SELECT 1'));
    assert.equal(calls.length, 1);
    void ds.close();
  });
});

// ---------------------------------------------------------------------------
// Write safety — the asymmetry that matters
// ---------------------------------------------------------------------------

describe('YugabyteDataSource — write retry safety', () => {
  it('run() does NOT retry an ambiguous YB RPC timeout (may already be applied)', async () => {
    const { pool, calls } = makeFakePool([ybRpcTimeout()]);
    const ds = makeDs();
    swapPool(ds, pool);

    await assert.rejects(
      () => ds.run('UPDATE identities SET name = ? WHERE uuid = ?', 'n', 'u'),
      (err: Error & { code?: string }) => err.code === 'XX000',
    );
    assert.equal(calls.length, 1, 'a lost verdict on a write must not become a second write');
    void ds.close();
  });

  it('run() DOES retry a connection-level failure (provably never executed)', async () => {
    const { pool, calls } = makeFakePool([connectionFailure(), { rows: [], rowCount: 1 }]);
    const ds = makeDs();
    swapPool(ds, pool);

    const result = await ds.run('UPDATE identities SET name = ? WHERE uuid = ?', 'n', 'u');

    assert.equal(result.changes, 1);
    assert.equal(calls.length, 2, '08006 is retried for writes');
    void ds.close();
  });

  it('never retries a deterministic failure such as a unique violation', async () => {
    const { pool, calls } = makeFakePool([uniqueViolation()]);
    const ds = makeDs();
    swapPool(ds, pool);

    await assert.rejects(
      () => ds.get('SELECT 1'),
      (err: Error & { code?: string }) => err.code === '23505',
    );
    assert.equal(calls.length, 1, '23505 is not transient');
    void ds.close();
  });

  it('a simple INSERT still retries a connection-level failure', async () => {
    // The INSERT path runs `RETURNING id` first and falls back on 42703; a
    // connection-level failure must be retried before either branch gives up.
    const { pool, calls } = makeFakePool([connectionFailure(), { rows: [{ id: 7 }], rowCount: 1 }]);
    const ds = makeDs();
    swapPool(ds, pool);

    const result = await ds.run('INSERT INTO schema_migrations (version) VALUES (?)', '1');

    assert.equal(result.changes, 1);
    assert.equal(result.lastInsertRowid, 7);
    assert.equal(calls.length, 2);
    assert.match(calls[1].sql, /RETURNING id$/);
    void ds.close();
  });
});
