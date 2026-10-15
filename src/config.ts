/**
 * Env-driven config for the utility server.
 *
 * Requires YugabyteDB connection (YB_HOST) at startup — the utility server
 * serves shared namespaces and requires serializable transaction isolation.
 * For local development, use Docker Compose (docker-compose.yml).
 */

import type { PolicyEngineConfig } from '@p2p-trust-stack/core/services/policy-engine-config.js';
import { resolvePolicyEngineConfig } from '@p2p-trust-stack/core/services/policy-engine-config.js';

export interface UtilityServerConfig {
  /** Fastify HTTP port. */
  port: number;
  /** TCP port for the libp2p/TSP node. 0 = OS-assigned. */
  libp2pPort: number;
  /** Human-readable name for this server's own VTA identity. */
  nodeName: string;

  // ── Auth / sessions ────────────────────────────────────────────────────
  /** DID of the designated utility server admin (bootstrap admin). */
  utilityAdminDid: string | undefined;

  // ── Public DID resolution surface ──────────────────────────────────────
  /**
   * Port for the public did:scid:vh resolver listener.
   *
   * Deliberately SEPARATE from `port`: the resolver is the one surface intended
   * to be reachable from the internet (router port map / TLS reverse proxy),
   * and the administrator web UI must not share its listener.
   */
  resolverPort: number;
  /**
   * Bind host for the resolver listener. Defaults to `0.0.0.0` so a router port
   * map or a reverse proxy can reach it; set `RESOLVER_HOST=127.0.0.1` when a
   * local proxy is the only intended entry point.
   */
  resolverHost: string;
  /** Set `RESOLVER_ENABLED=0` to keep the resolver listener off entirely. */
  resolverEnabled: boolean;

  // ── YugabyteDB connection ─────────────────────────────────────────────
  /** YugabyteDB YSQL host (required). */
  ybHost: string;
  /** YugabyteDB YSQL port (default: 5433). */
  ybPort: number;
  /** YugabyteDB database name (default: 'yugabyte'). */
  ybDatabase: string;
  /** YugabyteDB user (default: 'yugabyte'). */
  ybUser: string;
  /** YugabyteDB password (default: 'yugabyte'). */
  ybPassword: string;
  /** PG pool min connections (default: 2). */
  ybPoolMin: number;
  /** PG pool max connections (default: 10). */
  ybPoolMax: number;

  // ── Policy engine ──────────────────────────────────────────────────────
  /**
   * PolicyEngine configuration, resolved from `TSP_POLICY_ENGINE` and
   * `TSP_POLICY_UNKNOWN_FACT`.
   *
   * There is deliberately **no 'off'** — an unrecognised value warns and falls back
   * to the default, because an off switch is how the policy layer gets silently
   * bypassed. What a community may *do* is its policy bindings, edited per
   * community at runtime; this only selects the engine.
   */
  policyEngine: PolicyEngineConfig;
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function loadConfig(): UtilityServerConfig {
  return {
    port: envInt('PORT', 8787),
    libp2pPort: envInt('LIBP2P_PORT', 4003),
    nodeName: process.env.NODE_NAME ?? 'utility-server',

    utilityAdminDid: process.env.UTILITY_ADMIN_DID || undefined,

    resolverPort: envInt('RESOLVER_PORT', 8788),
    resolverHost: process.env.RESOLVER_HOST || '0.0.0.0',
    resolverEnabled: (process.env.RESOLVER_ENABLED ?? '1') !== '0',

    ybHost: process.env.YB_HOST ?? 'localhost',
    ybPort: envInt('YB_PORT', 5433),
    ybDatabase: process.env.YB_DATABASE ?? 'yugabyte',
    ybUser: process.env.YB_USER ?? 'yugabyte',
    ybPassword: process.env.YB_PASSWORD ?? 'yugabyte',
    ybPoolMin: envInt('YB_POOL_MIN', 2),
    ybPoolMax: envInt('YB_POOL_MAX', 10),

    policyEngine: resolvePolicyEngineConfig(),
  };
}