# utility-server

The first "utility server" for the P2P Trust Stack (P2PTS).

A standalone TypeScript/Node application, backed by **YugabyteDB** (distributed SQL
with PostgreSQL wire protocol), that implements the full P2P Trust Stack
data schema (see `../mockup/data-schema-notes.md`) and exposes it as a REST API —
organized layer by layer, matching the stack itself:

1. **Infrastructure** — identities, DID documents, keys, rotation log, witness attestations
2. **Trust Spanning** — relationships (Layer-2 peer links) + live libp2p/TSP messaging
3. **Trust Tasks** — credentials (VMC/VEC/VRC/custom_endorsement/delegation), status lists, nonces
4. **Governance** — memberships, personhood events, governance docs, delegations, grants
5. **Trust Applications** — cross-cutting composed views (profiles, dashboards, DTG graph)

The utility server requires YugabyteDB for **serializable transaction isolation** —
name registration, VTC governance, and VRC issuance require deterministic conflict
resolution across multiple utility server instances. SQLite remains the correct tool
for the edge (agent-app) and bootstrap server layers, where data is naturally
conflict-free.

The server is a first-class VTA on the libp2p/TSP network itself, not just a database
behind a REST wall. It reuses the same transport, crypto, DID, and TSP componentry
from `../src/` that every other node in this repo uses.

## Status

See `../docs/utility-server-api-plan.md` for the full API-by-API build plan.
Layer 1 (Infrastructure), Layer 2 (Trust Spanning), Layer 3 (Trust
Tasks — credentials/VCs, status lists, nonces), Layer 4 (Governance —
memberships, personhood events, governance docs, delegations, grants), and
Layer 5 (Trust Applications — composed profile/dashboard/graph views) are
fully implemented.

**Phase 5 (YugabyteDB Integration)**: See `../docs/phase5-yugabyte-integration-plan.md`
for the full implementation plan. The utility server now uses YugabyteDB for all
trust task data, with serializable transaction isolation for name registration and
VTC governance.

## Running

### Prerequisites

- Node.js 22+
- Docker Desktop (for local YugabyteDB)
- No other dependencies

### First-time setup

```sh
cd utility-server
npm install

# Start YugabyteDB (runs in background, data persists across restarts)
docker compose up -d

# Wait for YugabyteDB to be healthy (≈15 seconds)
docker compose ps   # should show "healthy"

# Start the utility server (auto-runs migrations against YugabyteDB)
npm start
```

### Daily development

```sh
cd utility-server

# Ensure YugabyteDB is running
docker compose up -d

# Start the server
npm start
```

### Stopping

- **Stop server**: `Ctrl+C` in the terminal running `npm start`
- **Stop YugabyteDB** (preserves data): `docker compose stop`
- **Stop and delete all data**: `docker compose down -v`

### Config

Config is read from environment variables (see `src/config.ts`).

The **bootstrap/relay** address and peer ID are **not** environment variables —
they come from a gitignored `.env` written by `npm run init:bootstrap` (see
`.env.example`). With no `.env`, the server runs in LAN-only mode (the setup
wizard still works).

```sh
# Derive this server's bootstrap seed / peer ID from a BIP-39 phrase file and
# write ./.env (run from the utility-server repo root)
npm run init:bootstrap -- --words-file ./phrase.txt --host mediator.fpndtg.com
```

The tool lives in `scripts/init-bootstrap-env.ts` and is **self-contained** — it
only ever writes this repo's `./.env`, so no `--component` flag is needed.

| Var | Default | Meaning |
|---|---|---|
| `PORT` | `8787` | Fastify HTTP port |
| `LIBP2P_PORT` | `4003` | TCP port for the libp2p/TSP node |
| `NODE_NAME` | `utility-server` | Human-readable name for this server's own VTA identity |
| `YB_HOST` | `localhost` | YugabyteDB YSQL host |
| `YB_PORT` | `5433` | YugabyteDB YSQL port |
| `YB_DATABASE` | `yugabyte` | YugabyteDB database name |
| `YB_USER` | `yugabyte` | YugabyteDB user |
| `YB_PASSWORD` | `yugabyte` | YugabyteDB password |
| `YB_POOL_MIN` | `2` | PG connection pool minimum |
| `YB_POOL_MAX` | `10` | PG connection pool maximum |
| `RESOLVER_PORT` | `8788` | Port for the **public did:scid:vh resolver** listener (separate from `PORT`) |
| `RESOLVER_HOST` | `0.0.0.0` | Bind host for the resolver listener (set `127.0.0.1` when a local proxy is the only entry point) |
| `RESOLVER_ENABLED` | `1` | Set to `0` to keep the resolver listener off entirely |

### Public DID resolution (second listener)

The utility server starts a **second, separate Fastify instance** on
`RESOLVER_PORT` (default `8788`) that serves public `did:scid:vh` resolution.
It is the only listener intended to face the internet; it has **no session
auth, no admin routes, and no admin UI**, so the administrator dashboard stays
private. See [`../docs/did-resolution-endpoint.md`](../docs/did-resolution-endpoint.md)
for the full surface. Quick check:

```sh
curl -s http://localhost:8788/health
curl -s 'http://localhost:8788/1.0/identifiers/did:scid:vh:1:<SCID>' \
     -H 'accept: application/did+ld+json'
open 'http://localhost:8788/1.0/identifiers/did:scid:vh:1:<SCID>'   # annotated HTML
```

To expose it through a TLS reverse proxy (recommended over exposing the port
directly), bind it to localhost and let the proxy terminate TLS:

```sh
RESOLVER_HOST=127.0.0.1 npm start
```

### Troubleshooting: `EADDRINUSE: address already in use 0.0.0.0:8787`

This means a previous `npm start` process is still bound to the port. Find and stop it:

```sh
lsof -nP -iTCP:8787 -sTCP:LISTEN   # shows the PID holding the port
kill <PID>                          # stop it
npm start                           # retry
```

Or run on a different port:

```sh
PORT=9797 npm start
```

### Troubleshooting: Port 7000 conflict

YugabyteDB's Master UI defaults to port 7000. If something else is using that port,
the Docker Compose file maps it to **7001** instead. The Master UI dashboard is at
`http://localhost:7001`.

### Troubleshooting: Database connection errors

If you see `database "yugabyte" does not exist`, ensure YugabyteDB is running:

```sh
docker compose ps    # should show "healthy"
docker compose logs  # check for startup errors
```

If you see migration errors, the database may have partially-applied migrations
from a previous failed startup. Nuke and restart:

```sh
docker compose down -v   # delete all data
docker compose up -d     # fresh start
npm start
```

## Testing / discovering the API

Once the server is running:

- **`GET /help`** — an HTTP endpoint listing every registered route:
  ```sh
  curl -s http://localhost:8787/help | jq
  ```

- **`npm run routes`** — a standalone CLI script that prints the route listing
  without needing a running server:
  ```sh
  npm run routes
  ```

Also useful:

- **`GET /health`** — basic liveness check (`{ status, service, time }`)
- **`GET /`** — redirects to `/ui/index.html` (the dashboard)

## Automated tests

Tests use `SqliteDataSource` with in-memory SQLite for speed — no Docker or
YugabyteDB needed. 23 tests across 4 suites:

```sh
npm test
```

Test suites:

| Suite | Tests | Coverage |
|---|---|---|
| `test/db/sqlite-data-source.test.ts` | 4 | Async CRUD, transactions, rollback, close safety |
| `test/db/yugabyte-data-source.test.ts` | 9 | `?→$1` conversion, exec splitting, edge cases |
| `test/db/identities-repo.test.ts` | 4 | UUIDv5 creation, custody defaults, role filters, upsert |
| `test/tsp-handlers/name-registry-handler.test.ts` | 6 | Register, duplicate rejection, resolve, revoke, validation |

## Layout

```
src/
  config.ts              env-driven config
  db/
    yugabyte-data-source.ts   Async DataSource backed by pg.Pool
    migrations/                PostgreSQL-compatible migration files
  node/
    vta.ts                     Server's own VTA identity
    libp2p-node.ts             Boots a libp2p node
    tsp-bridge.ts              Routes inbound TSP messages → DB
  plugins/
    auth.ts                    No-op passthrough; future auth hook point
    error-handler.ts
  routes/
    health.ts
    help.ts                    GET /help — self-describing API route listing
    layer1-infrastructure/     (fully implemented)
    layer2-spanning/           (fully implemented)
    layer3-tasks/              (fully implemented, name registry with SERIALIZABLE txns)
    layer4-governance/         (fully implemented)
    layer5-applications/       (fully implemented)
  scripts/
    list-routes.ts             npm run routes — CLI route listing
  server.ts                 Fastify app builder
  index.ts                   Entry point (YugabyteDB → migrate → VTA → TSP → listen)
test/
  db/                       DataSource + repository tests
  tsp-handlers/             Name registry serializable transaction tests
```

Shared infrastructure in the repo root (`../src/`):

```
src/db/
  data-source.ts             DataSource interface (async Promise-based)
  sqlite-data-source.ts      Test-only async SQLite wrapper
  migrate.ts                 Sync migration runner (agent-app, bootstrap)
  migrate-via-datasource.ts  Async migration runner (utility-server)
  repositories/              Hand-written SQL repos (17 modules, all async)
src/services/                Composed business logic (7 modules, all async)
```

## Architecture Notes

- **YugabyteDB required at runtime** — the utility server serves shared namespaces
  and requires serializable transaction isolation. There is no SQLite fallback at
  runtime. Tests use `SqliteDataSource` (in-memory) for speed.
- **No ORM**: every repository module is hand-written SQL, matched to either
  `DataSource` (async) or `DatabaseSync` (sync, for SQLite-only components).
- **Migrations**: The utility server uses its own PostgreSQL-compatible migration
  copies in `src/db/migrations/`. The originals in `../src/db/migrations/` remain
  SQLite-compatible for the agent-app and bootstrap server.
- **Auth is deferred** entirely — `src/plugins/auth.ts` is a no-op passthrough
  wired in as the future hook point.
- The server imports `../../src/**` (crypto, did, vtc, relationship, transport,
  TSP, keystore, repositories) via relative paths, using the same
  `--experimental-strip-types` execution style as the rest of the repo — no build
  step required for dev.

## License

**Dual-licensed:**

- **AGPL-3.0-only** — see [`LICENSE`](./LICENSE); or
- a **commercial license** where AGPL-3.0 obligations (copyleft, source
  disclosure, and the section 13 network-interaction requirement) are not
  acceptable — see [`COMMERCIAL-LICENSE.md`](./COMMERCIAL-LICENSE.md).

[`NOTICE`](./NOTICE) declares the `LicenseRef-TrustStackers-Commercial`
reference and lists third-party attribution.

**Operating a utility server for the public network is free under the AGPL
branch.** Because this is the component most likely to be offered as a hosted
service, note that section 13 applies: if you modify the software and let users
interact with it over a network, you must offer them the Corresponding Source of
your modified version. A link to the tagged commit you deploy is sufficient.

[`TRADEMARK.md`](./TRADEMARK.md) covers the marks ("Trust Stackers", "P2P Trust
Stack"), which no license grants. All contributions require the
[CLA](./CLA.md) — see [CONTRIBUTING.md](./CONTRIBUTING.md).
