// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests: AgentDeliveryQueue — drain re-entrancy and forced-flush throttling.
 *
 * WHY: `drain()` was invoked from a 5 s timer AND from every `peer:connect`
 * AND from the connectivity supervisor's reconnect path, with no re-entrancy
 * guard; and `flushForMember()` forced delivery on every reconnect with no
 * interval and no in-flight guard.
 *
 * Field failure, 2026-10-29: relay/bootstrap churn reconnected the same member
 * roughly every 90 s, and each cycle re-materialized and re-transmitted the SAME
 * pending row — identical 81,820-byte `tx_prepare` frames in the log, one per
 * cycle, forever, with no backoff. Overlapping drains also each read the same
 * pending rows and each materialized them.
 *
 * Run with:
 *   node --conditions=development --experimental-strip-types --loader ../test-loader.mjs \
 *     --test test/services/agent-delivery-queue.test.ts
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { AgentDeliveryQueue } from '../../src/services/agent-delivery-queue.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

interface DbCounters {
  all: number;
  run: number;
  get: number;
}

/**
 * A DataSource stand-in that counts calls and can be made slow, so overlapping
 * invocations are observable. Returns NO pending rows, which keeps `deliverOne`
 * (and the exchange catalog materializers) out of these tests — the guards under
 * test run before any of that.
 */
function makeDb(options: { rows?: unknown[]; delayMs?: number } = {}): {
  db: Record<string, unknown>;
  counters: DbCounters;
} {
  const counters: DbCounters = { all: 0, run: 0, get: 0 };
  const delay = (): Promise<void> =>
    new Promise((r) => setTimeout(r, options.delayMs ?? 20));

  const db: Record<string, unknown> = {
    async all(): Promise<unknown[]> {
      counters.all++;
      await delay();
      return options.rows ?? [];
    },
    async get(): Promise<null> {
      counters.get++;
      return null;
    },
    async run(): Promise<{ changes: number; lastInsertRowid: undefined }> {
      counters.run++;
      return { changes: 1, lastInsertRowid: undefined };
    },
    async exec(): Promise<void> {
      /* noop */
    },
    async close(): Promise<void> {
      /* noop */
    },
  };
  return { db, counters };
}

/** The queue under test. `intervalMs` is irrelevant — these tests drive it directly. */
function makeQueue(db: Record<string, unknown>): AgentDeliveryQueue {
  return new AgentDeliveryQueue(
    db as never,
    {} as never,
    {} as never,
    60_000,
  );
}

// ---------------------------------------------------------------------------
// drain() re-entrancy
// ---------------------------------------------------------------------------

describe('AgentDeliveryQueue — drain re-entrancy', () => {
  it('a concurrent second drain() is a no-op while the first is running', async () => {
    const { db, counters } = makeDb({ delayMs: 40 });
    const queue = makeQueue(db);

    // Both start in the same tick — the shape produced by the 5 s timer firing
    // while a peer:connect flush is already draining.
    await Promise.all([queue.drain(), queue.drain()]);

    assert.equal(counters.all, 1, 'overlapping drains must not each query the queue');
  });

  it('the guard is released, so a later drain() still runs', async () => {
    const { db, counters } = makeDb();
    const queue = makeQueue(db);

    await queue.drain();
    await queue.drain();

    assert.equal(counters.all, 2, 'sequential drains must both run');
  });

  it('releases the guard even when the query fails', async () => {
    let calls = 0;
    const db: Record<string, unknown> = {
      async all(): Promise<unknown[]> {
        calls++;
        throw Object.assign(new Error('Timed out waiting kResponseSent, state: kProcessingRequest'), {
          code: 'XX000',
        });
      },
    };
    const queue = makeQueue(db);

    // Both rejections are swallowed by drain()'s own catch.
    await queue.drain();
    await queue.drain();

    assert.equal(calls, 2, 'a failed drain must not wedge the queue permanently');
  });
});

// ---------------------------------------------------------------------------
// flushForMember() throttling
// ---------------------------------------------------------------------------

describe('AgentDeliveryQueue — forced-flush throttling', () => {
  it('a second flush for the SAME member inside the window is skipped', async () => {
    const { db, counters } = makeDb();
    const queue = makeQueue(db);

    await queue.flushForMember('member-1');
    await queue.flushForMember('member-1');

    assert.equal(counters.run, 1, 'the reconnect-storm re-send must be throttled');
    assert.equal(counters.all, 1);
  });

  it('throttling is per member — another member still flushes', async () => {
    const { db, counters } = makeDb();
    const queue = makeQueue(db);

    await queue.flushForMember('member-1');
    await queue.flushForMember('member-2');

    assert.equal(counters.run, 2);
  });

  it('concurrent flushes for the same member collapse into one', async () => {
    const { db, counters } = makeDb({ delayMs: 40 });
    const queue = makeQueue(db);

    await Promise.all([
      queue.flushForMember('member-1'),
      queue.flushForMember('member-1'),
    ]);

    assert.equal(counters.run, 1, 'the in-flight guard must admit one flush per member');
  });
});

