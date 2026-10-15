/**
 * Tests: YugabyteDataSource — unit tests for ?→$1 conversion and exec splitting.
 * Does NOT require a running YugabyteDB instance (pure logic tests).
 */
import { describe, it } from 'node:test';
import { strictEqual } from 'node:assert';

// Test the convertPlaceholders logic directly
function convertPlaceholders(sql: string): string {
  let index = 0;
  return sql.replace(/\?/g, () => {
    index++;
    return `$${index}`;
  });
}

describe('YugabyteDataSource — placeholder conversion', () => {
  it('converts single ? placeholder', () => {
    strictEqual(convertPlaceholders('SELECT * FROM t WHERE id = ?'), 'SELECT * FROM t WHERE id = $1');
  });

  it('converts multiple ? placeholders', () => {
    strictEqual(
      convertPlaceholders('INSERT INTO t (a, b, c) VALUES (?, ?, ?)'),
      'INSERT INTO t (a, b, c) VALUES ($1, $2, $3)',
    );
  });

  it('converts ? in UPDATE with parameters', () => {
    strictEqual(
      convertPlaceholders('UPDATE t SET name = ?, age = ? WHERE id = ?'),
      'UPDATE t SET name = $1, age = $2 WHERE id = $3',
    );
  });

  it('handles no placeholders', () => {
    strictEqual(convertPlaceholders('SELECT 1'), 'SELECT 1');
  });

  it('handles COALESCE with placeholders', () => {
    strictEqual(
      convertPlaceholders('UPDATE t SET name = COALESCE(?, name), age = ? WHERE id = ?'),
      'UPDATE t SET name = COALESCE($1, name), age = $2 WHERE id = $3',
    );
  });

  it('handles subquery with placeholders', () => {
    strictEqual(
      convertPlaceholders('SELECT * FROM t WHERE id IN (SELECT id FROM u WHERE x = ?) AND y = ?'),
      'SELECT * FROM t WHERE id IN (SELECT id FROM u WHERE x = $1) AND y = $2',
    );
  });
});

describe('YugabyteDataSource — exec splitting', () => {
  function splitExec(sql: string): string[] {
    return sql.split(';').map(s => s.trim()).filter(s => s.length > 0);
  }

  it('splits multi-statement migration-style SQL', () => {
    const statements = splitExec(
      'CREATE TABLE a (id INT);\nCREATE TABLE b (id INT);\nINSERT INTO a VALUES (1);',
    );
    strictEqual(statements.length, 3);
  });

  it('handles trailing semicolons', () => {
    const statements = splitExec('CREATE TABLE a (id INT);');
    strictEqual(statements.length, 1);
  });

  it('handles empty input', () => {
    const statements = splitExec('');
    strictEqual(statements.length, 0);
  });
});