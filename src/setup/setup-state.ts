/**
 * setup-state — first-launch configuration model + persistence for the
 * utility server.
 *
 * Mirrors the crowdfund app's `crowdfund/server/src/setup/setup-state.ts`,
 * but persists into the utility server's existing `data/config.json` (the same
 * file index.ts uses for libp2p/identity seeds + the HMAC session secret),
 * under a `setup` sub-key, so there is a single per-instance config file.
 *
 * When `setup.configured === false` (or the key is absent), the instance is
 * unconfigured and the setup wizard runs instead of the normal dashboard.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Same data directory index.ts writes (utility-server/data). From this module's
// location (utility-server/src/setup) that is two levels up. Overridable in
// tests via UTILITY_DATA_DIR (resolved lazily so tests can set it per-case).
const __dirname = dirname(fileURLToPath(import.meta.url));
const CONFIG_FILENAME = 'config.json';

function dataDir(): string {
  return process.env.UTILITY_DATA_DIR ?? join(__dirname, '..', '..', 'data');
}

// ── Types ──────────────────────────────────────────────────────────

export type InstanceMode = 'vtn_host' | 'vtn_affiliate' | 'standalone_vtc';

/** Public/announced network parameters. Bound listen stays 0.0.0.0. */
export interface NetworkConfig {
  /** IP/hostname the libp2p peer advertises (multiaddr + OOBI + bootstrap). */
  advertisedHost: string;
  /** Fastify HTTP API port. */
  httpPort: number;
  /** libp2p/TSP node TCP port. */
  libp2pPort: number;
}

export const DEFAULT_NETWORK: NetworkConfig = {
  advertisedHost: '127.0.0.1',
  httpPort: 8787,
  libp2pPort: 4003,
};

/** The persisted `setup` block in data/config.json. */
export interface SetupConfig {
  version: number;
  configured: boolean;
  mode: InstanceMode | null;
  /** Founder-admin VTA identity (uuid). */
  adminVtaUuid: string | null;
  /** Founder-admin VTA DID. */
  adminVtaDid: string | null;
  /** The configured namespace (e.g. 'p2pts.mainnet'). */
  namespace: string | null;
  /** Namespace VTN identity uuid (role='vtn'). */
  vtnUuid: string | null;
  /** Namespace VTN DID. */
  vtnDid: string | null;
  network: NetworkConfig;
  createdAt: string | null;
  updatedAt: string | null;
}

/** In-memory wizard state machine (per setup session). */
export interface SetupState {
  mode?: InstanceMode;
  adminVtaUuid?: string;
  adminVtaDid?: string;
  vtnName?: string;
  namespace?: string;
  vtnUuid?: string;
  vtnDid?: string;
  network?: NetworkConfig;
  currentStep: number;
  completed: boolean;
}

// ── Raw config read/write ─────────────────────────────────────────

/** Full path to the instance config file (co-located with seeds/session secret). */
export function configFilePath(): string {
  return join(dataDir(), CONFIG_FILENAME);
}

/** Read the raw config.json object (empty object when missing/unparseable). */
function readRawConfig(): Record<string, unknown> {
  try {
    return JSON.parse(readFileSync(configFilePath(), 'utf8')) as Record<string, unknown>;
  } catch {
    return {};
  }
}

// ── Public API ────────────────────────────────────────────────────

/** Load the persisted setup configuration (defaults when absent). */
export function loadSetupConfig(): SetupConfig {
  const raw = readRawConfig();
  const s = (raw.setup ?? {}) as Partial<SetupConfig> & { network?: Partial<NetworkConfig> };
  return {
    version: s.version ?? 1,
    configured: s.configured === true,
    mode: s.mode ?? null,
    adminVtaUuid: s.adminVtaUuid ?? null,
    adminVtaDid: s.adminVtaDid ?? null,
    namespace: s.namespace ?? null,
    vtnUuid: s.vtnUuid ?? null,
    vtnDid: s.vtnDid ?? null,
    network: { ...DEFAULT_NETWORK, ...(s.network ?? {}) },
    createdAt: s.createdAt ?? null,
    updatedAt: s.updatedAt ?? null,
  };
}

/** Whether the instance has completed first-launch configuration. */
export function isConfigured(): boolean {
  return existsSync(configFilePath()) && loadSetupConfig().configured;
}

/** Persist the setup configuration, preserving every other key in config.json. */
export function saveSetupConfig(cfg: SetupConfig): void {
  const raw = readRawConfig();
  const now = new Date().toISOString();
  const setupBlock: SetupConfig = { ...cfg, configured: true, updatedAt: now };
  if (!setupBlock.createdAt) setupBlock.createdAt = now;
  raw.setup = setupBlock;
  mkdirSync(dataDir(), { recursive: true });
  writeFileSync(configFilePath(), JSON.stringify(raw, null, 2) + '\n', { mode: 0o600 });
}

/** Create the initial in-memory wizard state (step 0). Defaults to creating a
 *  new VTN (vtn_host) — joining an existing VTN is a stub. */
export function createSetupState(): SetupState {
  return { mode: 'vtn_host', currentStep: 0, completed: false };
}

/** Build a SetupConfig from a completed wizard state. */
export function buildSetupConfig(state: SetupState): SetupConfig {
  if (!state.mode || !state.adminVtaUuid) {
    throw new Error('Setup incomplete: mode and admin VTA are required');
  }
  const now = new Date().toISOString();
  return {
    version: 1,
    configured: true,
    mode: state.mode,
    adminVtaUuid: state.adminVtaUuid,
    adminVtaDid: state.adminVtaDid ?? null,
    namespace: state.namespace ?? null,
    vtnUuid: state.vtnUuid ?? null,
    vtnDid: state.vtnDid ?? null,
    network: state.network ?? { ...DEFAULT_NETWORK },
    createdAt: now,
    updatedAt: now,
  };
}
