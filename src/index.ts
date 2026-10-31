// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Entry point: boots the YugabyteDB DataSource (running migrations), the
 * libp2p node, this server's own VTA identity, the TSP inbound-message
 * bridge, connects to the bootstrap server for peer discovery, and finally
 * starts the Fastify HTTP API.
 *
 * Requires YugabyteDB (YB_HOST) — serializable transaction isolation is
 * required for trust task data (name registration, VTC governance, VRC
 * issuance). For local dev:  docker compose up
 */

import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';

import { loadConfig } from './config.js';
import { isConfigured, loadSetupConfig } from './setup/setup-state.js';
import { YugabyteDataSource } from './db/yugabyte-data-source.js';
import { runDataSourceMigrations } from '@p2p-trust-stack/core/db/migrate-via-datasource.js';
import {
  resolveSeedPassphrase,
  readPersistedSeed,
  writeSeedValue,
  SEED_PASSPHRASE_ENV,
} from '@p2p-trust-stack/core/crypto/seed-at-rest.js';
import { didToUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import { startLibp2pNode } from './node/libp2p-node.js';
import { ensureServerVta } from './node/vta.js';
import { startTspBridge } from './node/tsp-bridge.js';
import { buildServer } from './server.js';
import { buildResolverApp } from './resolver-app.js';
import { onShutdownRequested } from './services/shutdown.js';
import { bootstrapTxCoordinator } from './tx/bootstrap.js';
import { createServerTspRequestFn } from './tx/tsp-request.js';
import type { ServerTspRequestAdapter } from './tx/tsp-request.js';
import { TspParticipantTransport } from '@p2p-trust-stack/core/tx/tsp-participant-transport.js';
import type { ConnectivityCheckFn } from '@p2p-trust-stack/core/tx/tsp-participant-transport.js';
import { ExchangeEngine } from '@p2p-trust-stack/core/exchange/engine.js';
import { AgentDeliveryQueue, resolveMemberUuidForPeerId } from './services/agent-delivery-queue.js';
import { ConnectivitySupervisor } from './services/connectivity-supervisor.js';
import { getNamespaceConfig } from './services/namespace-service.js';
import { setExchangeEngine } from './services/exchange-runtime.js';
import { setServerNodeInfo, setServerNodeDid } from './services/server-node-info.js';
import { setOobiSignerFromKey } from '@p2p-trust-stack/core/relationship/oobi-signer.js';
import { setLocalOperationSigner } from '@p2p-trust-stack/core/tx/operation-proof.js';
import { setBootstrapClient } from './services/bootstrap-info.js';
import { GovernanceGuard } from '@p2p-trust-stack/core/services/governance-guard.js';
import { createPolicyEngine } from '@p2p-trust-stack/core/services/policy-engine-config.js';
import { CeremonyCoordinator } from '@p2p-trust-stack/core/tx/index.js';

import { BootstrapClient } from '@p2p-trust-stack/core/transport/bootstrap-client.js';
import {
  loadBootstrapClientEnv,
  buildBootstrapUrls,
  type BootstrapClientEnv,
} from '@p2p-trust-stack/core/config/bootstrap-env.js';
import { applyLoggingEnv } from '@p2p-trust-stack/core/config/logging-env.js';
import { buildDialableMultiaddrs } from '@p2p-trust-stack/core/platform/network-detect.js';

import { cesrEncode, CESR_CODES } from '@p2p-trust-stack/core/crypto/cesr.js';
import { decryptSecretKey } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
import { buildDidPeer4Document } from '@p2p-trust-stack/core/did/create.js';
import * as keysRepo from '@p2p-trust-stack/core/db/repositories/keys-repo.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import type { DidDocument } from '@p2p-trust-stack/core/did/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = join(__dirname, 'db', 'migrations');

/**
 * Decrypt a `keys` row's secret half and pair it with the row's stored public
 * half.
 *
 * Returns `undefined` (naming the key type) when the row has no encrypted
 * secret: such a row is still usable as a PUBLIC key, just not for signing or
 * decrypting — so a partially provisioned identity degrades instead of failing.
 */
async function tryLoadSecretKeyPair(
  row: keysRepo.KeyRow,
  passphrase: string,
): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array } | undefined> {
  if (!row.encryptedSecretKey || !row.salt || !row.nonce || !row.authTag) {
    console.warn(
      `[utility-server] key row ${row.keyType} carries no encrypted secret — ` +
      `usable as a public key only; this key cannot sign or decrypt`,
    );
    return undefined;
  }
  const secretKey = await decryptSecretKey({
    ciphertext: new Uint8Array(row.encryptedSecretKey),
    salt: new Uint8Array(row.salt),
    nonce: new Uint8Array(row.nonce),
    authTag: new Uint8Array(row.authTag),
  }, passphrase);
  return { publicKey: new Uint8Array(row.publicKey), secretKey };
}

/**
 * Resolve this server's bootstrap **client** config.
 *
 * Precedence: the setup wizard's persisted values → this component's `.env` →
 * nothing. The wizard's network step pre-fills both fields from `.env` and lets
 * the operator replace them, so a host running several utility servers can point
 * each one at a different bootstrap server without editing files.
 *
 * Returns `null` rather than throwing when neither source yields a usable pair:
 * an unconfigured (or .env-less) server must still boot so the first-launch
 * setup wizard is reachable. `null` means LAN-only mode.
 *
 * This server is a CLIENT — it holds no seed, only the address and the peer ID to
 * expect (`loadBootstrapClientEnv` refuses a client file that still carries one).
 */
function resolveBootstrapClientEnv(network: {
  bootstrapHost: string;
  bootstrapPeerId: string;
}): BootstrapClientEnv | null {
  let env: BootstrapClientEnv | null = null;
  try {
    env = loadBootstrapClientEnv({ path: join(__dirname, '..', '.env') });
  } catch (err) {
    console.warn(
      `[utility-server] Bootstrap .env unavailable (${(err as Error).message}) — ` +
      'falling back to the setup configuration, or LAN-only mode.',
    );
  }

  // A wizard value wins; an EMPTY wizard value means "accept the .env default".
  const host = network.bootstrapHost.trim() || env?.host || '';
  const peerId = network.bootstrapPeerId.trim() || env?.peerId || '';
  if (!host || !peerId) return null;

  return {
    version: 1,
    host,
    peerId,
    tcpPort: env?.tcpPort ?? 4001,
    wsPort: env?.wsPort ?? 4002,
    enableRelay: env?.enableRelay ?? true,
  };
}

async function main(): Promise<void> {
  // Verbosity comes from this component's `.env` — the same file the bootstrap
  // block lives in, and the reason the npm script needs no `P2PTS_LOG_LEVEL=info`
  // prefix (which PowerShell and cmd cannot parse). Cannot throw: a missing or
  // malformed `.env` leaves logging at the environment/default level.
  applyLoggingEnv({ path: join(__dirname, '..', '.env') });

  const config = loadConfig();

  // First-launch detection: an unconfigured instance boots the full node but
  // exposes only the setup wizard (+ auth), not the normal dashboard.
  const setupCfg = loadSetupConfig();
  const setupMode = !isConfigured();
  const httpPort = setupMode ? config.port : setupCfg.network.httpPort;
  const libp2pPort = setupMode ? config.libp2pPort : setupCfg.network.libp2pPort;
  // The advertised host comes from the setup config — there is no OS env override.
  const advertisedHost = setupMode ? undefined : setupCfg.network.advertisedHost;

  // ── YugabyteDB DataSource (required) ─────────────────────────────────

  console.log(`[utility-server] connecting to YugabyteDB at ${config.ybHost}:${config.ybPort}/${config.ybDatabase}`);
  const ds = new YugabyteDataSource({
    host: config.ybHost,
    port: config.ybPort,
    database: config.ybDatabase,
    user: config.ybUser,
    password: config.ybPassword,
    poolMin: config.ybPoolMin,
    poolMax: config.ybPoolMax,
  });

  const applied = await runDataSourceMigrations(ds, MIGRATIONS_DIR);
  if (applied.length > 0) {
    console.log(`[utility-server] applied ${applied.length} migration(s): ${applied.join(', ')}`);
  }

  // ── libp2p node ──────────────────────────────────────────────────────

  const dataDir = join(__dirname, '..', 'data');
  const configPath = join(dataDir, 'config.json');

  // Load or generate the persisted identity seeds. Three independent seeds:
  //   - libp2p.seedHex      → libp2p node Peer ID
  //   - identity.didSeedHex → did:scid:vh identity (chain) key
  //   - identity.tspVidSeedHex → PERMANENT TSP VID key (decoupled from the did log)
  // Each is sourced from config.json (the per-instance store), NOT from OS
  // environment variables; a future hardware-keychain provider can replace
  // these (see ServerKeyProvider).
  let seed: string | undefined;
  let didSeedHex: string | undefined;
  let tspVidSeedHex: string | undefined;

  let persistedConfig: Record<string, unknown> = {};
  try {
    persistedConfig = JSON.parse(await readFile(configPath, 'utf8')) as Record<string, unknown>;
  } catch { /* no persisted config yet */ }

  // F-022: the seeds below ARE the node's identity, and they used to sit in
  // config.json as plain hex. With TSP_SEED_PASSPHRASE set they are written as
  // AES-256-GCM blobs; existing plaintext files still load unchanged (and are
  // upgraded on the next write), so no deployment is forced to migrate.
  const seedPassphrase = resolveSeedPassphrase();
  const legacySeedFields: string[] = [];

  const loadSeed = async (raw: unknown, label: string): Promise<string | undefined> => {
    const loaded = await readPersistedSeed(raw, seedPassphrase, label);
    if (!loaded) return undefined;
    if (loaded.legacyPlaintext) legacySeedFields.push(label);
    return loaded.hex;
  };

  if (!seed) {
    const persisted = await loadSeed((persistedConfig as any)?.libp2p?.seedHex, 'libp2p.seedHex');
    if (persisted) {
      seed = persisted;
      console.log(`[utility-server] Loaded persisted libp2p seed from ${configPath}.`);
    }
  }

  if (!didSeedHex) {
    const persisted = await loadSeed((persistedConfig as any)?.identity?.didSeedHex, 'identity.didSeedHex');
    if (persisted) {
      didSeedHex = persisted;
      console.log(`[utility-server] Loaded persisted identity didSeedHex from ${configPath}.`);
    }
  }

  if (!tspVidSeedHex) {
    const persisted = await loadSeed((persistedConfig as any)?.identity?.tspVidSeedHex, 'identity.tspVidSeedHex');
    if (persisted) {
      tspVidSeedHex = persisted;
      console.log(`[utility-server] Loaded persisted identity tspVidSeedHex from ${configPath}.`);
    }
  }

  if (legacySeedFields.length > 0) {
    console.warn(
      `[utility-server] ${legacySeedFields.join(', ')} ${legacySeedFields.length === 1 ? 'is' : 'are'} stored in ` +
      `PLAINTEXT in ${configPath} — anyone who can read that file owns this node's identity. ` +
      `Set ${SEED_PASSPHRASE_ENV} and restart to re-write them encrypted (audit F-022).\n` +
      `  Do NOT delete ${configPath} to clear this warning: it holds the ONLY copy of this node's keys, ` +
      `and losing it permanently changes the Peer ID, the did:scid:vh identity and the TSP VID this node presents ` +
      `(nothing can re-derive them). Setting ${SEED_PASSPHRASE_ENV} is the remedy; deleting is not.`,
    );
  }

  // Track which seeds had to be minted. Any of them means this node now presents a
  // NEW identity — a "stop and check" event, not a routine log line.
  const generatedSeeds: string[] = [];

  if (!seed) {
    seed = randomBytes(32).toString('hex');
    generatedSeeds.push('libp2p.seedHex (Peer ID)');
    console.log(
      `[utility-server] No seed found in env or config.json — generated a new one.\n` +
      `  It will be persisted to ${configPath} so the peer ID is stable across restarts.`,
    );
  }

  if (!didSeedHex) {
    didSeedHex = randomBytes(32).toString('hex');
    generatedSeeds.push('identity.didSeedHex (did:scid:vh identity key)');
    console.log(
      `[utility-server] No identity.didSeedHex found — generated a new one for the did:scid:vh identity key.`,
    );
  }

  if (!tspVidSeedHex) {
    tspVidSeedHex = randomBytes(32).toString('hex');
    generatedSeeds.push('identity.tspVidSeedHex (permanent TSP VID key)');
    console.log(
      `[utility-server] No identity.tspVidSeedHex found — generated a new one for the permanent TSP VID key.`,
    );
  }

  // F-022 follow-up (2026-09-25): the plaintext warning sent an operator to set
  // TSP_SEED_PASSPHRASE — but *deleting* config.json also silences it, and that
  // destroys the only copy of this node's keys. From the log alone both remedies
  // look reasonable, so the consequence has to be stated where the choice is made.
  if (generatedSeeds.length > 0) {
    console.warn(
      `[utility-server] NEW IDENTITY — minted ${generatedSeeds.join(', ')} because nothing was found in ` +
      `${SEED_PASSPHRASE_ENV} or ${configPath}.\n` +
      `  This node now presents a different Peer ID / did:scid:vh identity / TSP VID than it did before; ` +
      `credentials, invites, relationships and agent bindings created under the previous identity will not match it.\n` +
      `  If that is unexpected, STOP and restore ${configPath} from a backup before proceeding.\n` +
      `  Set ${SEED_PASSPHRASE_ENV} to store the new seeds encrypted instead of as plain hex.`,
    );
  }

  const node = await startLibp2pNode({ port: libp2pPort, seed });
  console.log(`[utility-server] libp2p peerId: ${node.peerId.toString()}`);
  setServerNodeInfo(node.peerId.toString(), node.getMultiaddrs().map((a) => a.toString()));

  // Persist the seeds so future boots derive the same Peer ID + identity keys.
  // Also persist the HMAC session secret so sessions survive restarts.
  const hmacSecretBytes = randomBytes(32);
  const newHmacSecretHex = hmacSecretBytes.toString('hex');
  let hmacSecretHex: string = newHmacSecretHex;
  try {
    await mkdir(dataDir, { recursive: true });

    // Preserve existing session secret if present, otherwise persist the new one.
    // Same at-rest treatment as the seeds (F-022): the session HMAC secret
    // authenticates every admin session, so it is exactly as sensitive as a seed —
    // and with a passphrase set it is stored as a blob, which this read must handle
    // or every restart would silently issue a new secret and drop all sessions.
    const persistedSessionSecret = await loadSeed(persistedConfig.sessionSecret, 'sessionSecret');
    if (persistedSessionSecret) {
      hmacSecretHex = persistedSessionSecret;
    }

    const now = new Date().toISOString();
    // F-022: honour the passphrase on WRITE too — this is where a plaintext file
    // becomes encrypted, without an explicit migration step.
    const [seedValue, didSeedValue, tspVidSeedValue, sessionSecretValue] = await Promise.all([
      writeSeedValue(seed, seedPassphrase),
      writeSeedValue(didSeedHex, seedPassphrase),
      writeSeedValue(tspVidSeedHex, seedPassphrase),
      writeSeedValue(hmacSecretHex, seedPassphrase),
    ]);
    await writeFile(
      configPath,
      JSON.stringify({
        version: 1,
        libp2p: { seedHex: seedValue },
        identity: {
          didSeedHex: didSeedValue,
          tspVidSeedHex: tspVidSeedValue,
        },
        sessionSecret: sessionSecretValue,
        ...(persistedConfig && (persistedConfig as any).setup
          ? { setup: (persistedConfig as any).setup }
          : {}),
        config: (persistedConfig as any).config ?? {},
        createdAt: (persistedConfig as any).createdAt ?? now,
        updatedAt: now,
      }, null, 2) + '\n',
      { mode: 0o600 },
    );

    console.log(`[utility-server] session secret ${hmacSecretHex === newHmacSecretHex ? 'generated and persisted' : 'loaded from config'}`);
  } catch (err) {
    console.warn(`[utility-server] Failed to write config.json: ${(err as Error)?.message ?? err}`);
  }

  // ── VTA identity ─────────────────────────────────────────────────────

  const keyStorePath = 'utility-server-keystore.db';
  const vta = await ensureServerVta(ds, node, config.nodeName, node.peerId.toString(), {
    didSeedHex,
    tspVidSeedHex,
  });
  console.log(`[utility-server] server VTA identity: ${vta.realDid}`);
  // Record the server's own DID so invite builders can address a connection OOBI
  // at THIS node (the one the invite's peerId actually reaches) instead of at the
  // community, which cannot answer a dial.
  setServerNodeDid(vta.realDid);
  if (vta.tspVid) {
    console.log(`[utility-server] server TSP VID (permanent, from seed): ${vta.tspVid.slice(0, 12)}...`);
  }

  // ── TSP bridge ───────────────────────────────────────────────────────

  // The server's TSP identity uses the PERMANENT seeded TSP VID key (Slot-A),
  // independent of the did:scid:vh identity key. The presented DID document
  // carries the TSP key at verificationMethod[0] (#key-1, what the handshake
  // verifies) and the did:scid:vh identity key at #key-scid.
  const DEV_PASSPHRASE = process.env.NODE_PASSPHRASE ?? 'dev-only-insecure-passphrase';
  let tspIdentity: Parameters<typeof startTspBridge>[2] | undefined;

  try {
    const keyRows = await keysRepo.findByIdentityUuid(ds, didToUuid(vta.realDid));
    const edKey = keyRows.find((k) => k.keyType === 'ed25519');

    // Slot-A: the TSP VID key is the seeded, permanent one (never rotates with
    // the did log). Fall back to the stored identity key for legacy installs
    // that predate the decoupling config.
    const tspKp = vta.tspSigningKeyPair;
    const tspAgreementKp = vta.tspAgreementKeyPair;
    const tspVid = vta.tspVid;

    if (tspKp && tspAgreementKp && tspVid) {
      // Post-quantum roots of trust (G7e provisioned these alongside the
      // classical keys). Loaded here so the server's RUNTIME identity matches
      // what is persisted: without this the server published no #key-mldsa /
      // #key-kem while `keys` held them, so agents stayed classical and the
      // server could not sign an OOBI introduction with ML-DSA-65.
      //
      // Note the key families: #key-1/#key-2 are the PERMANENT Slot-A TSP keys
      // (from tspVidSeedHex), while the ML-DSA / KEM pairs belong to the
      // did:scid:vh identity. That is the server's existing dual-key design —
      // what matters is that the document publishes exactly the keys this
      // process holds, so a peer sealing to #key-kem can be opened here.
      const mlDsaRow = keyRows.find((k) => k.keyType === 'ml_dsa_65');
      const kemRow = keyRows.find((k) => k.keyType === 'mlkem768_x25519');
      const mlDsa65KeyPair = mlDsaRow?.encryptedSecretKey
        ? await tryLoadSecretKeyPair(mlDsaRow, DEV_PASSPHRASE)
        : undefined;
      const hybridKemKeyPair = kemRow?.encryptedSecretKey
        ? await tryLoadSecretKeyPair(kemRow, DEV_PASSPHRASE)
        : undefined;

      const didDocument: DidDocument = buildDidPeer4Document(
        tspKp.publicKey,
        tspAgreementKp.publicKey,
        {
          peerId: node.peerId.toString(),
          multiaddrs: node.getMultiaddrs().map(a => a.toString()),
        },
        edKey ? new Uint8Array(edKey.publicKey) : undefined, // did:scid:vh identity key → #key-scid
        mlDsa65KeyPair && hybridKemKeyPair
          ? { mlDsa65PublicKey: mlDsa65KeyPair.publicKey, hybridKemPublicKey: hybridKemKeyPair.publicKey }
          : mlDsa65KeyPair
            ? { mlDsa65PublicKey: mlDsa65KeyPair.publicKey }
            : hybridKemKeyPair
              ? { hybridKemPublicKey: hybridKemKeyPair.publicKey }
              : undefined,
      );
      didDocument.id = vta.realDid;

      tspIdentity = {
        realDid: vta.realDid,
        didDocument,
        signingSecretKey: tspKp.secretKey,
        // The X25519 pair (not just the secret) is required to OPEN a classical
        // confidential payload: the HPKE context carries the public half too.
        agreementKeyPair: {
          publicKey: tspAgreementKp.publicKey,
          secretKey: tspAgreementKp.secretKey,
        },
        agreementSecretKey: tspAgreementKp.secretKey,
        mlDsa65KeyPair,
        hybridKemKeyPair,
      };

      if (mlDsa65KeyPair && hybridKemKeyPair) {
        console.log('[utility-server] server TSP identity loaded with ML-DSA-65 + MLKEM768-X25519 (PQ roots of trust published)');
      } else {
        // Mirror the agent's loadIdentity(): a server provisioned before G7e is
        // usable, just classical. Say so once, clearly, rather than failing.
        console.warn(
          `[utility-server] server identity has no post-quantum keys ` +
          `(ml_dsa_65: ${mlDsaRow ? 'row present' : 'missing'}, ` +
          `mlkem768_x25519: ${kemRow ? 'row present' : 'missing'}) — ` +
          `the server will publish no #key-mldsa/#key-kem, so confidential traffic ` +
          `stays classical and its OOBI introductions cannot be ML-DSA-signed. ` +
          `Re-provision the server identity to enable them.`,
        );
      }
      console.log(`[utility-server] server TSP identity loaded (VID: ${vta.realDid.slice(0, 24)}... — permanent seeded key)`);
    } else {
      // Legacy path (no tspVidSeedHex configured): use the stored identity key
      // as the TSP VID (previous behavior).
      const xKey = keyRows.find(k => k.keyType === 'x25519');
      if (edKey && xKey && edKey.encryptedSecretKey && edKey.salt && edKey.nonce && edKey.authTag) {
        const signingSecretKey = await decryptSecretKey({
          ciphertext: new Uint8Array(edKey.encryptedSecretKey),
          salt: new Uint8Array(edKey.salt),
          nonce: new Uint8Array(edKey.nonce),
          authTag: new Uint8Array(edKey.authTag),
        }, DEV_PASSPHRASE);

        const agreementSecretKey = xKey.encryptedSecretKey && xKey.salt && xKey.nonce && xKey.authTag
          ? await decryptSecretKey({
              ciphertext: new Uint8Array(xKey.encryptedSecretKey),
              salt: new Uint8Array(xKey.salt),
              nonce: new Uint8Array(xKey.nonce),
              authTag: new Uint8Array(xKey.authTag),
            }, DEV_PASSPHRASE)
          : new Uint8Array(32);

        const primaryDoc = await didDocumentsRepo.findPrimaryForIdentity(ds, vta.identityUuid);
        const didDocument: DidDocument = primaryDoc?.documentJson
          ? JSON.parse(primaryDoc.documentJson)
          : { id: vta.realDid };

        tspIdentity = {
          realDid: vta.realDid, didDocument, signingSecretKey, agreementSecretKey,
          // The all-zero fallback secret above is a placeholder, not a key: only a
          // real pair can OPEN a classical confidential payload (the HPKE context
          // carries the public half too), so expose the pair only when the row
          // actually held an encrypted secret.
          agreementKeyPair: xKey.encryptedSecretKey
            ? { publicKey: new Uint8Array(xKey.publicKey), secretKey: agreementSecretKey }
            : undefined,
        };
        console.log(`[utility-server] server keys loaded for TSP handshake (VID: ${vta.realDid.slice(0, 24)}...)`);
      } else {
        console.warn('[utility-server] server keys not found or incomplete — TSP handshake disabled');
      }
    }
  } catch (err) {
    console.warn(`[utility-server] failed to load server keys: ${(err as Error)?.message ?? err}`);
    console.warn('[utility-server] TSP handshake disabled — agents will not be able to connect');
  }

  // OOBI introductions this server issues (its own OOBI, and the dialable
  // `connectionOobi` inside a VTC invite) are ML-DSA-65-signed from here on when
  // this identity holds a PQ key. The signer is scoped to THIS identity's DID:
  // an OOBI signature is checked against the key published in the document of
  // the OOBI's own `did`, so signing for anyone else could never verify (the
  // provenance gap that made `maybeSignOobi` authority-aware).
  // Installed once, because the builders (a shared invite builder and a route)
  // are far from the code that loaded the key.
  setOobiSignerFromKey(tspIdentity?.mlDsa65KeyPair?.secretKey, { forDid: vta.realDid });

  // F-010 / R1: install this node's operation-proof signer for outbound cross-node
  // operations. The TSP VID is the identity that appears as the actor, and the
  // Ed25519 signing key is the one whose public half IS that VID — so a peer can
  // verify the proof offline, without resolving anything.
  if (tspIdentity?.signingSecretKey && vta.tspVid) {
    setLocalOperationSigner({
      actorVid: vta.tspVid,
      secretKey: tspIdentity.signingSecretKey,
    });
    console.log(`[utility-server] operation proofs: signing as ${vta.tspVid.slice(0, 12)}…`);
  } else {
    console.log(
      '[utility-server] operation proofs: NOT signing (no TSP VID / signing key) — ' +
      'peers with TSP_OPERATION_PROOF_POLICY=enforce will refuse this node\'s tx_prepare',
    );
  }
  console.log(
    `[utility-server] OOBI introductions: ` +
    (tspIdentity?.mlDsa65KeyPair
      ? `ML-DSA-65 signed, authority ${vta.realDid.slice(0, 24)}…`
      : 'UNSIGNED (no PQ key on this identity)'),
  );

  // ── Transaction Coordinator ───────────────────────────────────────────

  const tx = await bootstrapTxCoordinator(ds, { serverId: 'us-1' });
  console.log('[utility-server] transaction coordinator started');

  // Create the TSP request function for server→agent communication.
  // Uses the server's VID and signing key loaded above for TSP_GEN sealing.
  // The address resolver receives the destination string from TspParticipantTransport.
  // For agent pushes, the pid format is 'peer:{vid}:{peerId}' so the transport
  // can extract the VID for tspSeal() and the peerId for libp2p routing.
  let tspAdapter: ServerTspRequestAdapter | undefined;
  if (tspIdentity) {
    tspAdapter = createServerTspRequestFn(
      node,
      vta.realDid,
      tspIdentity.signingSecretKey,
      (destination) => {
        // destination is the peerId portion extracted by TspParticipantTransport
        return { peerId: destination };
      },
    );
    console.log('[utility-server] TSP request adapter created for agent push');
  }

  // Start the TSP bridge AFTER creating the adapter so we can wire
  // handleInboundResponse for correlationId matching on tx responses.
  // Pass the DEDUPED inbound 2PC entry point (H7) so a replayed tx_* message from the
  // coordinator's recovery re-drive or the outbox's reconnect retry is recognised and
  // dropped instead of being re-applied — the participant operations behind it (mint
  // VRC, store_remote_vrc, exchange:identity) are not idempotent in general.
  await startTspBridge(ds, node, tspIdentity, tspAdapter?.handleInboundResponse, tx.handleInboundTxMessage);
  console.log('[utility-server] TSP bridge started');

  // ── Agent Delivery Queue + ExchangeEngine (server-full) ────────────────
  // The AgentDeliveryQueue is the CRE engine's queue-row fan-out store
  // (pending_agent_deliveries). The engine orchestrates catalog-driven fan-out
  // from route commits; the queue drains the durable rows and delivers them to
  // agents via the transaction coordinator.
  // Requires the TSP adapter and transaction manager to be available.
  let agentDeliveryQueue: AgentDeliveryQueue | undefined;
  if (tspAdapter && tx.manager) {
    const transport = new TspParticipantTransport(tspAdapter.request, {
      isConnected: tspAdapter.isConnected as ConnectivityCheckFn,
    });
    agentDeliveryQueue = new AgentDeliveryQueue(ds, tx.manager, transport, 5_000, tx.txDataSource);
    agentDeliveryQueue.start();
    console.log('[utility-server] AgentDeliveryQueue started');

    // Server-full ExchangeEngine: db (app DB for materializers), watermark
    // (tx-coordinator.db), fanoutStore (the queue). Route handlers fan out via
    // getExchangeEngine().enqueueFanout(...).
    const exchangeEngine = new ExchangeEngine({
      db: ds,
      watermark: tx.txDataSource,
      fanoutStore: agentDeliveryQueue,
    });
    setExchangeEngine(exchangeEngine);
    console.log('[utility-server] ExchangeEngine (server-full) ready');

    // ── Flush on agent reconnect ────────────────────────────────────
    // When an agent's libp2p transport peer comes back online, the queue's
    // pending-send-state entries for that member become VALID. Flush them so the
    // current VTC records are transmitted immediately (recovering 'failed' rows too)
    // instead of waiting on the blind backoff timer or staying dead.
    // The relationship (remote_transport.peerId) may not be established at the
    // exact peer:connect instant, so briefly retry member resolution before giving
    // up — the drain plus the next peer connect will cover it.
    // ── Connectivity events (Phase 8) ────────────────────────────────────
    // Event-fed reachability: mark peers connected/disconnected so the queue's
    // drain can skip provably-offline members with zero work (no in_flight tent,
    // no attempt burn, no materialization). peer:connect also flushes the member.
    node.addEventListener('peer:connect', (evt) => {
      const peerId = (evt.detail as { toString(): string }).toString();
      agentDeliveryQueue!.markPeerConnected(peerId);
      // Touch last_seen_at so the ConnectivitySupervisor treats this agent as
      // recently observed (online); a clean logout or crash then ages out via
      // the stale check instead of being dialled forever.
      ds.run(
        'UPDATE peer_endpoints SET last_seen_at = ? WHERE peer_id = ?',
        Math.floor(Date.now() / 1000),
        peerId,
      ).catch(() => {});
      (async () => {
        let memberUuid: string | null = null;
        for (let attempt = 0; attempt < 8; attempt++) {
          memberUuid = await resolveMemberUuidForPeerId(ds, peerId);
          if (memberUuid) break;
          await new Promise((r) => setTimeout(r, 1000));
        }
        if (!memberUuid) {
          console.log(`[utility-server] agent transport peer connected ${peerId.slice(0, 12)}... no member mapping yet (will retry on next drain/connect)`);
          return;
        }
        console.log(`[utility-server] agent transport peer connected ${peerId.slice(0, 12)}... — flushing queue for ${memberUuid.slice(0, 8)}...`);
        await agentDeliveryQueue!.flushForMember(memberUuid);
      })().catch((err) =>
        console.warn('[utility-server] reconnect flush failed:', (err as Error)?.message ?? err),
      );
    });

    // The agent emits peer:disconnect on teardown/go-dark; the server previously
    // never listened. Removing the peer from the connected set means the 5s drain
    // skips it immediately instead of issueing doomed sends.
    node.addEventListener('peer:disconnect', (evt) => {
      const peerId = (evt.detail as { toString(): string }).toString();
      agentDeliveryQueue!.markPeerDisconnected(peerId);
      console.log(`[utility-server] agent transport peer disconnected ${peerId.slice(0, 12)}... — delivery attempts paused until reconnect`);
    });
  }

  // ── Bootstrap registration ───────────────────────────────────────────
  //
  // Wrapped in a CALLABLE function (rather than a one-shot try/catch) so the
  // connectivity supervisor can retry it. Previously a bootstrap outage that
  // started before this server booted was permanent: registration failed once,
  // logged "continuing in LAN-only mode", and was never attempted again — so
  // the server never appeared in discovery and never held a relay reservation.

  // Resolve the bootstrap/relay identity + address: the setup wizard's persisted
  // override wins, then this component's `.env` (written by
  // `npm run init:bootstrap`), then LAN-only. A missing config is NOT fatal here:
  // the server must still boot so the first-launch setup wizard is reachable.
  // There is no hardcoded address and no `process.env` override — see
  // @p2p-trust-stack/core/config/bootstrap-env.
  const bootstrapEnv = resolveBootstrapClientEnv(setupCfg.network);

  let bootstrapClient: BootstrapClient | null = null;
  if (bootstrapEnv) {
    const { tcpUrl, wsUrl } = buildBootstrapUrls(bootstrapEnv);
    bootstrapClient = new BootstrapClient(tcpUrl, wsUrl);
    console.log(
      `[utility-server] bootstrap target ${bootstrapEnv.host}:${bootstrapEnv.tcpPort} ` +
      `(peer ${bootstrapEnv.peerId.slice(0, 12)}...)`,
    );
  } else {
    console.warn(
      '[utility-server] No bootstrap address + peer ID (neither the setup wizard nor ' +
      '.env supplied a usable pair) — running in LAN-only mode. Run ' +
      '`npm run init:bootstrap` or set them in the setup wizard.',
    );
  }

  if (bootstrapClient) {
    // Surface the bootstrap client's own status transitions in the server log.
    // ensureRelayReservation() swallows the actual reservation-failure reason
    // (deferred/unsupported/error) and only reports a boolean, so without this the
    // only relay-related line that ever reaches the log is the supervisor's generic
    // "relay reservation requested but not yet confirmed". This makes it diagnosable.
    bootstrapClient.onStatusChange((status, info) => {
      const warn = status === 'disconnected' || status === 'relay-degraded';
      const attempts = info.attempts != null ? ` (attempt ${info.attempts})` : '';
      console.log(`[utility-server:bootstrap] ${warn ? 'warn' : 'info'}: ${status}${attempts}: ${info.message}`);
    });
    setBootstrapClient(bootstrapClient, node);
  }

  /**
   * The relay address this server can be reached through, as advertised by the
   * bootstrap server (e.g. `/dns/host/tcp/4001/p2p/<relayPeerId>/p2p-circuit`).
   * Used by the supervisor to dial NAT'd agents back through the relay.
   */
  let bootstrapRelayAddr: string | undefined;

  const registerWithBootstrap = async (): Promise<void> => {
    if (!bootstrapClient) return; // LAN-only mode: no bootstrap configured
    const multiaddrs = node.getMultiaddrs().map((a) => a.toString());
    const dialableAddrs = buildDialableMultiaddrs(multiaddrs, advertisedHost);

    // Send the VID (CESR-encoded Ed25519 public key) so agents can build
    // a valid OOBI for TSP connection establishment. Use the PERMANENT seeded
    // TSP VID key (Slot-A) when available, so a future did:scid:vh log roll
    // on the server does NOT change the VID agents connect to.
    //
    // NAMING (H12): this is a CESR **VID**, not a DID — hence `serverVid`. It
    // lives in the discovery payload's `vid` slot by design (the permanent
    // Slot-A TSP key, so a log roll cannot move the address agents dial), while
    // the server's DID travels separately in the `identity.realDid` argument
    // below. Reading it as a DID and "fixing" it here would put a did:… string
    // into a slot that `decodeOobi` runs through `cesrDecode`.
    let serverVid: string | undefined;
    try {
      serverVid = vta.tspVid;
      if (!serverVid) {
        const keyRows = await keysRepo.findByIdentityUuid(ds, didToUuid(vta.realDid));
        const edKey = keyRows.find((k) => k.keyType === 'ed25519');
        if (edKey?.publicKey) {
          serverVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, new Uint8Array(edKey.publicKey));
        }
      }
    } catch { /* best-effort */ }
    // Announce the server's real DID so agents can build the strict 4-item
    // OOBI (vid, peerId, multiaddrs, did) for TSP connection establishment.
    //
    // Announce the peer DESIGNATION the bootstrap stores and displays:
    //   - `net` — the VTN **key** (namespace) this server serves, e.g. 'p2pts'.
    //     This is the identifier: agents match on it to find the utility server
    //     for the VTN they want, and the bootstrap renders `Utl Server (p2pts)`.
    //   - `vtnName` — the VTN's human-readable name (e.g. 'Trust Stackers'), a
    //     UTILITY-ONLY optional field carried separately so a display name can
    //     never be confused with — or collide against — an agent's user name.
    //   - `agentName` — this server's own node name (`NODE_NAME`), which says
    //     nothing about which network it hosts; the bootstrap shows it only as a
    //     secondary detail now that `net` identifies the row.
    let net: string | undefined;
    let vtnName: string | undefined;
    try {
      const ns = await getNamespaceConfig(ds);
      net = ns?.namespace;
      if (ns?.vtnIdentityUuid) {
        const vtn = await identitiesRepo.findByUuid(ds, ns.vtnIdentityUuid);
        vtnName = vtn?.name ?? undefined;
      }
    } catch { /* best-effort — namespace may not be configured yet */ }

    const result = await bootstrapClient.register(
      node,
      dialableAddrs,
      'utility_server',
      serverVid,
      {
        vtaUuid: didToUuid(vta.realDid),
        realDid: vta.realDid,
        name: config.nodeName,
        subjectKind: 'organization',
      },
      {
        agentName: config.nodeName,
        ...(net ? { net } : {}),
        ...(vtnName ? { vtnName } : {}),
      },
    );
    console.log(
      `[utility-server] bootstrap registration OK — VTN ${net ?? '(unbound)'}` +
      `${vtnName ? ` "${vtnName}"` : ''} — discovered ${result.connectedPeers.length} peer(s)`,
    );

    if (result.relayAddr) {
      bootstrapRelayAddr = result.relayAddr;
    }

    for (const peer of result.connectedPeers) {
      if (peer.multiaddrs.length > 0) {
        try {
          await (node.peerStore as any).patch(peer.peerId, { multiaddrs: peer.multiaddrs });
        } catch { /* ignore */ }
      }
    }

    // Keepalive reuses the registration connection. startKeepalive() is
    // restartable, so a re-registration replaces (never duplicates) the loop.
    bootstrapClient.startKeepalive(node);
  };

  try {
    await registerWithBootstrap();
    console.log('[utility-server] bootstrap keepalive started');
  } catch (err) {
    console.warn(
      `[utility-server] Bootstrap server unavailable (${(err as Error)?.message ?? err}) — ` +
      'the connectivity supervisor will keep retrying in the background.',
    );
  }

  // ── Connectivity supervisor ──────────────────────────────────────────
  //
  // Owns everything the server used to leave to chance: bootstrap registration
  // retries, the circuit-relay reservation (which this server previously never
  // held, making relay reachability impossible for NAT'd agents), and re-dialling
  // members whose connection dropped — the missing half of the stalled-delivery
  // bug, which previously resumed only on an inbound peer:connect.
  const connectivitySupervisor = new ConnectivitySupervisor({
    node,
    register: registerWithBootstrap,
    // The same reservation routine the agent uses. The relay only forwards an
    // inbound HOP CONNECT to a destination that HOLDS a reservation, so without
    // this the server answers NO_RESERVATION for every relayed dial.
    ensureRelayReservation: () => bootstrapClient
      ? bootstrapClient.ensureRelayReservation(node)
      : Promise.resolve(),
    isBootstrapConnected: () => bootstrapClient?.getReconnectState() === 'connected',
    getRelayAddr: () => bootstrapRelayAddr,
    listMemberEndpoints: async () => {
      // `peer_endpoints` is the peerId -> multiaddrs map maintained on every
      // agent connect/reconnect, so it is the right source for "who should we
      // try to reach". The supervisor filters out self and connected peers.
      const rows = await ds.all<{
        peer_id: string;
        multiaddrs: string | null;
        agent_name: string | null;
        last_seen_at: number | null;
      }>(
        `SELECT pe.peer_id AS peer_id, pe.multiaddrs AS multiaddrs, pe.last_seen_at AS last_seen_at, i.name AS agent_name
           FROM peer_endpoints pe
           JOIN identities i ON i.uuid = pe.identity_uuid
          WHERE pe.is_active = 1 AND i.role = 'vta'`,
      );
      return rows.map((row: { peer_id: string; multiaddrs: string | null; agent_name: string | null; last_seen_at: number | null }) => {
        let multiaddrs: string[] = [];
        if (row.multiaddrs) {
          try {
            const parsed = JSON.parse(row.multiaddrs) as unknown;
            if (Array.isArray(parsed)) {
              multiaddrs = parsed.filter((a): a is string => typeof a === 'string');
            }
          } catch {
            // Malformed JSON in an endpoint row must not break the tick.
          }
        }
        return {
          peerId: row.peer_id,
          multiaddrs,
          label: row.agent_name ?? row.peer_id.slice(0, 12),
          lastSeenAt: row.last_seen_at,
        };
      });
    },
    onMemberReconnected: async (peerId: string) => {
      // Resume this member's delivery queue immediately instead of waiting for
      // a blind backoff timer — we re-dialled, so no inbound event will come.
      const memberUuid = await resolveMemberUuidForPeerId(ds, peerId);
      if (!memberUuid || !agentDeliveryQueue) return;
      await agentDeliveryQueue.flushForMember(memberUuid);
    },
    onStatus: (message, level) => {
      const tag = level === 'error' ? 'ERROR' : level === 'warn' ? 'warn' : 'info';
      console.log(`[utility-server:connectivity] ${tag}: ${message}`);
    },
  });
  connectivitySupervisor.start();

  // ── HTTP API ─────────────────────────────────────────────────────────

  const app = buildServer({
    db: ds, node, keyStorePath, hmacSecretHex,
    txDb: tx.txDataSource,
    txManager: tx.manager,
    txCoordinator: tx.coordinator,
    ceremonyCoordinator: new CeremonyCoordinator({
      store: tx.ceremonyStore,
      guard: new GovernanceGuard(ds, createPolicyEngine(config.policyEngine), {
        defaultPolicyKind: config.policyEngine.defaultPolicyKind,
      }),
      manager: tx.manager,
      appDb: ds,
    }),
    tspAdapter,
    setupMode,
    // Operator surface: GET /health/connectivity. The supervisor already owns all
    // of this state; before this it had no production caller at all, so none of it
    // was reachable outside the logs.
    getConnectivityStatus: () => connectivitySupervisor.getStatus(),
  });
  await app.listen({ port: httpPort, host: '0.0.0.0' });
  console.log(`[utility-server] HTTP API listening on http://0.0.0.0:${httpPort}`);

  // ── Public DID resolution surface ────────────────────────────────────────
  // A SEPARATE Fastify instance on its own port: no session auth, no admin
  // routes, no static admin UI. This is the only listener intended to face the
  // public internet (via a router port map or a TLS reverse proxy), so the
  // administrator web interface above stays private.
  let resolverApp: ReturnType<typeof buildResolverApp> | undefined;
  if (config.resolverEnabled && !setupMode) {
    resolverApp = buildResolverApp({ db: ds });
    await resolverApp.listen({ port: config.resolverPort, host: config.resolverHost });
    console.log(
      `[utility-server] DID resolver listening on http://${config.resolverHost}:${config.resolverPort}`,
    );
  } else if (!config.resolverEnabled) {
    console.log('[utility-server] DID resolver disabled (RESOLVER_ENABLED=0)');
  }

  let shuttingDown = false;
  const shutdown = async (reason: 'setup-complete' | 'signal' = 'signal') => {
    if (shuttingDown) return; // guard against a signal racing the setup exit
    shuttingDown = true;

    if (reason === 'setup-complete') {
      console.log('');
      console.log('[utility-server] ══════════════════════════════════════════════════════════');
      console.log('[utility-server] ✅ Setup complete — configuration saved.');
      console.log('[utility-server] Shutting down the setup process now.');
      console.log('[utility-server] Restart the utility server to enter operational mode:');
      console.log('[utility-server]     cd utility-server && npm start');
      console.log('[utility-server] ══════════════════════════════════════════════════════════');
      console.log('');
    } else {
      console.log('\n[utility-server] shutting down...');
    }

    connectivitySupervisor.stop();
    bootstrapClient?.stopKeepalive();
    if (agentDeliveryQueue) agentDeliveryQueue.stop();
    if (tspAdapter) tspAdapter.destroy();
    await tx.shutdown();
    if (resolverApp) await resolverApp.close();
    await app.close();
    await node.stop();
    await ds.close();
    process.exit(0);
  };
  // The setup wizard self-terminates the process after `/setup/confirm` (the listen
  // ports + advertised IP are fixed at boot, so operational mode needs a fresh start).
  onShutdownRequested((reason) => void shutdown(reason));
  process.on('SIGINT', () => void shutdown('signal'));
  process.on('SIGTERM', () => void shutdown('signal'));
}

/**
 * Last-resort process guard — installed BEFORE `main()` runs.
 *
 * A long-running trust node must survive a transient dependency failure. On
 * 2026-10-29 a single YugabyteDB tserver RPC timeout ("XX000 / Timed out waiting
 * kResponseSent, state: kProcessingRequest") reached the TSP bridge's
 * fire-and-forget libp2p message handler, became an unhandled rejection, and —
 * under Node's default `--unhandled-rejections=throw` — terminated the utility
 * server outright. The log ended with the Node version banner and a shell
 * prompt; every agent delivery queued behind it stalled.
 *
 * The ROOT CAUSE is fixed at both ends (Libp2pTransport.dispatchMessage() now
 * contains a rejecting handler, and the TSP bridge's own handler has an error
 * boundary). This handler is the backstop for the class, not the fix: any future
 * unawaited promise anywhere in the process logs instead of killing it.
 *
 * Deliberately ONLY `unhandledRejection`. An `uncaughtException` means a
 * synchronous throw escaped to the top of the stack — the process state is
 * genuinely unknown at that point, and continuing to serve trust data from an
 * unknown state is worse than stopping, so that keeps Node's default
 * (log + exit).
 */
process.on('unhandledRejection', (reason) => {
  const err = reason as { message?: string; stack?: string };
  console.error(
    '[utility-server] unhandled rejection (process kept alive):',
    err?.message ?? reason,
    err?.stack ? `\n${err.stack}` : '',
  );
});

main().catch((err) => {
  console.error('[utility-server] fatal error during startup:', err);
  if ((err as NodeJS.ErrnoException)?.code === 'EADDRINUSE') {
    const port = (err as NodeJS.ErrnoException & { port?: number }).port ?? loadConfig().port;
    console.error(`\n[utility-server] Port ${port} is already in use.`);
  }
  process.exit(1);
});