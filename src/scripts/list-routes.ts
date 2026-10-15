/**
 * `npm run routes` — print every registered API route to the console,
 * without booting SQLite migrations, the libp2p node, or the TSP bridge.
 *
 * Builds a Fastify app instance the exact same way index.ts does (via
 * `buildServer()`), but backs it with an in-memory (`:memory:`) SQLite
 * database and never calls `.listen()` — so this starts and prints
 * instantly, and is safe to run whether or not the real server is
 * currently up.
 *
 * This is the CLI counterpart to the `GET /help` HTTP endpoint
 * (src/routes/help.ts); both are driven by the same `onRoute` route
 * registry, so their output stays in sync automatically as routes are
 * added, renamed, or removed.
 */

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { buildServer } from '../server.js';
import { collectRoutes } from '../routes/help.js';
import { startLibp2pNode } from '../node/libp2p-node.js';

async function main(): Promise<void> {
  const db = new SqliteDataSource(':memory:');
  // A throwaway libp2p node on an ephemeral port — this script never sends
  // any traffic, it just needs a live `Libp2p` instance to satisfy
  // buildServer()'s AppDeps so the Layer 2 routes can be registered.
  const node = await startLibp2pNode({ port: 0 });
  const app = buildServer({ db, node, keyStorePath: ':memory:' });

  // Ensure all deferred/async route registration has settled before we read
  // the route registry back out.
  await app.ready();

  const routes = collectRoutes(app);

  const methodWidth = Math.max(...routes.map((r) => r.method.length), 6);
  const pathWidth = Math.max(...routes.map((r) => r.path.length), 4);

  console.log(`utility-server — ${routes.length} registered route(s)\n`);
  for (const route of routes) {
    const method = route.method.padEnd(methodWidth);
    const path = route.path.padEnd(pathWidth);
    const description = route.description ?? '';
    console.log(`  ${method}  ${path}  ${description}`);
  }
  console.log(
    '\nTip: once the server is running, the same data (plus live service info) is available at GET /help.',
  );

  await app.close();
  await node.stop();
  await db.close();
}

main().catch((err) => {
  console.error('[list-routes] failed to enumerate routes:', err);
  process.exit(1);
});
