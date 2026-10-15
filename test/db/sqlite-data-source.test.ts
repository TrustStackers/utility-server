/**
 * Tests: SqliteDataSource — verifies the async wrapper around DatabaseSync.
 */
import { describe, it, beforeEach, afterEach } from 'node:test';
import { deepStrictEqual, strictEqual, ok } from 'node:assert';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';

describe('SqliteDataSource', () => {
  let ds: SqliteDataSource;

  beforeEach(() => {
    ds = new SqliteDataSource(':memory:');
  });

  afterEach(async () => {
    await ds.close();
  });

  it('basic CRUD: run, get, all', async () => {
    await ds.exec('CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)');

    const r1 = await ds.run('INSERT INTO test (name) VALUES (?)', 'alice');
    strictEqual(r1.changes, 1);
    ok(typeof r1.lastInsertRowid === 'number');

    const row = await ds.get<{ id: number; name: string }>('SELECT * FROM test WHERE id = ?', r1.lastInsertRowid);
    ok(row);
    strictEqual(row.name, 'alice');

    await ds.run('INSERT INTO test (name) VALUES (?)', 'bob');
    const rows = await ds.all<{ id: number; name: string }>('SELECT * FROM test ORDER BY id');
    strictEqual(rows.length, 2);
    deepStrictEqual(rows.map(r => r.name), ['alice', 'bob']);
  });

  it('transaction commit', async () => {
    await ds.exec('CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)');

    await ds.transaction(async (tx) => {
      await tx.run('INSERT INTO test (name) VALUES (?)', 'alice');
      await tx.run('INSERT INTO test (name) VALUES (?)', 'bob');
    });

    const rows = await ds.all<{ name: string }>('SELECT name FROM test ORDER BY id');
    strictEqual(rows.length, 2);
  });

  it('transaction rollback on error', async () => {
    await ds.exec('CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)');

    try {
      await ds.transaction(async (tx) => {
        await tx.run('INSERT INTO test (name) VALUES (?)', 'alice');
        throw new Error('boom');
      });
    } catch {
      // expected
    }

    const rows = await ds.all<{ name: string }>('SELECT name FROM test');
    strictEqual(rows.length, 0);
  });

  it('close prevents further queries', async () => {
    const ds2 = new SqliteDataSource(':memory:');
    await ds2.exec('CREATE TABLE test (x INTEGER)');
    await ds2.close();
    try {
      await ds2.get('SELECT 1');
      ok(false, 'expected error after close');
    } catch {
      // expected
    }
  });
});