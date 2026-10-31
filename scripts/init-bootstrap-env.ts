#!/usr/bin/env node

// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * init-bootstrap-env — initialize this utility server's bootstrap/relay
 * **client** configuration.
 *
 * Run from the utility-server repo root: `npm run init:bootstrap`.
 *
 * ## What it does
 *
 * The utility server is a **client** of the bootstrap/relay server: it only has
 * to know WHERE that server is and WHICH peer ID to expect. So a developer
 * supplies the relay's **24-word BIP-39 word sequence** (checksum-validated) and
 * this tool:
 *
 *   1. derives the 32-byte Ed25519 seed from the words,
 *   2. derives the relay's libp2p **peer ID** from that seed,
 *   3. writes this repo's gitignored **`.env`** with the peer ID, host (DNS name
 *      or fixed public IP) and ports — and **never the seed**.
 *
 * The phrase is used only to derive a PUBLIC value (the peer ID) and is then
 * discarded. A seed in a client `.env` is a leaked private key with no client
 * use, and `loadBootstrapClientEnv` refuses to start if it finds one — so
 * re-running this tool over an older `.env` STRIPS a stale `BOOTSTRAP_SEED_HEX`
 * rather than leaving it behind.
 *
 * The `.env` is the single source of truth this server reads through
 * `@p2p-trust-stack/core/config/bootstrap-env.js` — there are no hardcoded
 * addresses and no OS environment-variable overrides.
 *
 * ## Examples
 *
 *   # Use the relay's phrase kept OUTSIDE this repo (never lands in shell history)
 *   npm run init:bootstrap -- --words-file ~/data/phrase.txt --host mediator.example.com
 *
 *   # Or pass the phrase inline
 *   npm run init:bootstrap -- --words "<24 words>" --host 203.0.113.5
 *
 * The shared Trust Stackers development relay's phrase is documented in README.md.
 * That relay is deliberately public and **NOT SECURE** — see the security note there.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { basename, dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { keys } from '@libp2p/crypto';
import { peerIdFromPrivateKey } from '@libp2p/peer-id';

import { mnemonicToSeed } from '@p2p-trust-stack/core/crypto/seed-phrase.js';
import { buildBootstrapUrls } from '@p2p-trust-stack/core/config/bootstrap-env.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
/** This repo's root — the script lives in `<root>/scripts/`. */
const REPO_ROOT = resolve(__dirname, '..');
/** The single `.env` this repo reads (bootstrap/relay block). */
const ENV_PATH = resolve(REPO_ROOT, '.env');
/** The only component this repo configures (kept for `--component` back-compat). */
const COMPONENT = 'utility-server';

interface Args {
  words?: string;
  wordsFile?: string;
  generate: boolean;
  host?: string;
  tcpPort: number;
  wsPort: number;
  enableRelay: boolean;
  out?: string;
  component: string;
  all: boolean;
  dryRun: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    generate: false,
    tcpPort: 4001,
    wsPort: 4002,
    enableRelay: true,
    component: COMPONENT,
    all: false,
    dryRun: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === '--words' && argv[i + 1] !== undefined) args.words = next();
    else if (a === '--words-file' && argv[i + 1] !== undefined) args.wordsFile = next();
    else if (a === '--generate') args.generate = true;
    else if (a === '--host' && argv[i + 1] !== undefined) args.host = next();
    else if (a === '--tcp-port' && argv[i + 1] !== undefined) args.tcpPort = parseInt(next(), 10);
    else if (a === '--ws-port' && argv[i + 1] !== undefined) args.wsPort = parseInt(next(), 10);
    else if (a === '--no-relay') args.enableRelay = false;
    else if (a === '--out' && argv[i + 1] !== undefined) args.out = next();
    else if (a === '--component' && argv[i + 1] !== undefined) args.component = next();
    else if (a === '--all') args.all = true;
    else if (a === '--dry-run') args.dryRun = true;
    else if (a === '--help' || a === '-h') args.help = true;
  }
  return args;
}

function printHelp(): void {
  console.log(`
init-bootstrap-env — set this utility server's bootstrap/relay CLIENT config.

Usage:
  npm run init:bootstrap -- [options]

Identity — the RELAY's phrase (pick ONE):
  --words "<24 words>"      The relay's BIP-39 word sequence.
  --words-file <path>       Read it from a file (avoids shell history). Keep the
                            file OUTSIDE this repo, e.g. ~/data/phrase.txt.

  The phrase is used ONLY to derive the relay's public peer ID. It is never
  written to ./.env, and a stale BOOTSTRAP_SEED_HEX in an existing .env is
  REMOVED. Only a bootstrap server needs the seed itself: this component is a
  client, and a client that carries a seed is refused at startup.

Address:
  --host <dns-or-ip>        DNS name OR fixed public IP (required).
  --tcp-port <n>            TCP port (default 4001).
  --ws-port <n>             WebSocket port (default 4002).
  --no-relay                Mark the relay as unavailable.

Output:
  --out <path>              Write to this file (default ./.env).
  --dry-run                 Print what would be written; touch nothing.
  --help                    Show this help.

Writes this repo's gitignored ./.env, read back through
@p2p-trust-stack/core/config/bootstrap-env.js — no hardcoded address, no OS env override.

(--component utility-server and --all are still accepted for backwards
compatibility; this repo has a single component.)

--generate is NOT available here. Minting a new relay identity belongs to the
bootstrap server — in the 'bootstrap' repo, npm run init-bootstrap -- --generate.
`);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Update `KEY=value` lines in existing `.env` text, preserving everything else. */
function upsertEnvKeys(existing: string, updates: Record<string, string>): string {
  const remaining = new Map(Object.entries(updates));
  const outLines: string[] = [];
  for (const line of existing.split(/\r?\n/)) {
    const m = /^\s*([A-Za-z0-9_]+)\s*=/.exec(line);
    if (m && remaining.has(m[1])) {
      outLines.push(`${m[1]}=${remaining.get(m[1])}`);
      remaining.delete(m[1]);
    } else {
      outLines.push(line);
    }
  }
  if (remaining.size > 0) {
    // Drop trailing blank lines, then append the new keys under a heading.
    while (outLines.length > 0 && outLines[outLines.length - 1].trim() === '') outLines.pop();
    if (outLines.length > 0) outLines.push('');
    outLines.push('# ── Bootstrap / relay server (written by `npm run init:bootstrap`) ──');
    for (const [k, v] of remaining) outLines.push(`${k}=${v}`);
  }
  return outLines.join('\n').replace(/\n*$/, '\n');
}

/**
 * Drop `KEY=value` lines (and any comment line immediately above them that
 * mentions the key) from existing `.env` text.
 *
 * Used to strip a stale `BOOTSTRAP_SEED_HEX` from this CLIENT `.env`. A seed in a
 * client file is a leaked private key, so it is removed rather than left behind
 * for the next reader to copy — `loadBootstrapClientEnv` refuses to start with it
 * present, so leaving it would be a boot failure waiting to happen.
 */
function removeEnvKeys(existing: string, keys: readonly string[]): string {
  const wanted = new Set(keys);
  const keep: string[] = [];
  for (const line of existing.split(/\r?\n/)) {
    const m = /^\s*([A-Za-z0-9_]+)\s*=/.exec(line);
    if (m && wanted.has(m[1])) {
      // Also drop a comment directly above that names the removed key.
      while (keep.length > 0) {
        const prev = keep[keep.length - 1].trim();
        if (prev.startsWith('#') && keys.some((k) => prev.includes(k))) keep.pop();
        else break;
      }
      continue;
    }
    keep.push(line);
  }
  return keep.join('\n').replace(/\n*$/, '\n');
}

/**
 * Append the logging block to a `.env` that has none.
 *
 * Logging is a different concern from the bootstrap identity, so this is added
 * ONCE, with the keys left EMPTY (the built-in default is `warn`), and never
 * rewritten afterwards — the operator toggles it in place. `upsertEnvKeys` leaves
 * unknown keys alone, so a value set here survives every later run.
 *
 * It exists because verbosity used to live in the component's `package.json` script
 * (`P2PTS_LOG_LEVEL=info node …`) — POSIX-only syntax that PowerShell and cmd cannot
 * parse. A fresh `.env` should therefore already say where the setting belongs.
 */
function withLoggingBlock(text: string): string {
  if (/^\s*P2PTS_LOG_LEVEL\s*=/m.test(text)) return text;

  const lines = text.split('\n');
  while (lines.length > 0 && lines[lines.length - 1].trim() === '') lines.pop();
  if (lines.length > 0) lines.push('');
  lines.push(
    '# ── Logging (optional) ──',
    '# silent | error | warn | info | debug      (default: warn)',
    'P2PTS_LOG_LEVEL=',
    '# 1 turns on the [CEREMONY] OOBI→RFI→RFA trace lines (independent of the level).',
    'CEREMONY_TRACE=',
  );
  return `${lines.join('\n')}\n`;
}

/**
 * True when `git` reports the path as ignored (so it can never be committed).
 *
 * This standalone repo may not be `git init`-ed yet, in which case
 * `git check-ignore` exits 128 ("not a git repository"). Fall back to reading
 * the committed `.gitignore` so the seed still cannot be written to a path that
 * would end up tracked.
 */
function isGitIgnored(filePath: string): boolean {
  try {
    execFileSync('git', ['check-ignore', '-q', filePath], { cwd: REPO_ROOT, stdio: 'ignore' });
    return true;
  } catch (err) {
    const status = (err as { status?: number }).status;
    if (status === 128) return isIgnoredByDotGitignore(filePath);
    return false; // status 1 => git is present and the path is NOT ignored
  }
}

/** Minimal `.gitignore` matcher, used only when the repo has no `.git` yet. */
function isIgnoredByDotGitignore(filePath: string): boolean {
  const ignoreFile = resolve(REPO_ROOT, '.gitignore');
  if (!existsSync(ignoreFile)) return false;
  const rel = relative(REPO_ROOT, filePath);
  const name = basename(rel);
  return readFileSync(ignoreFile, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== '' && !l.startsWith('#') && !l.startsWith('!'))
    .map((p) => p.replace(/^\//, '').replace(/\/$/, ''))
    .some((p) => p === rel || p === name || p === `**/${name}` || p === `*/${name}`);
}

/**
 * Resolve the RELAY's word sequence from the chosen input.
 *
 * There is deliberately no `--generate` branch: minting a new relay identity
 * belongs to the bootstrap server, not to a client (see `main`).
 */
function resolveSeed(args: Args): Uint8Array {
  let words: string | undefined;
  if (args.words) words = args.words;
  else if (args.wordsFile) words = readFileSync(args.wordsFile, 'utf8').trim();
  if (!words) {
    throw new Error(
      'No relay phrase supplied. Pass it with --words or --words-file (see --help).',
    );
  }
  return mnemonicToSeed(words);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }
  if (args.component !== COMPONENT) {
    console.error(
      `init-bootstrap-env: --component '${args.component}' is not valid in this repo.\n` +
      `  This tool only configures the '${COMPONENT}' component (its own ./.env) — drop --component.`,
    );
    process.exit(1);
  }
  if (args.generate) {
    console.error(
      'init-bootstrap-env: --generate is not available here.\n' +
      '  This component is a CLIENT — the phrase identifies the RELAY, it does not\n' +
      "  create an identity. Mint a new relay identity in the 'bootstrap' repo\n" +
      '  (npm run init-bootstrap -- --generate), then pass that phrase here with\n' +
      '  --words / --words-file.',
    );
    process.exit(1);
  }
  if (!args.host) {
    console.error('init-bootstrap-env: --host <dns-or-ip> is required.\n');
    printHelp();
    process.exit(1);
  }

  const seed = resolveSeed(args);
  const priv = await keys.generateKeyPairFromSeed('Ed25519', seed);
  const peerId = (await peerIdFromPrivateKey(priv)).toString();

  // The seed exists ONLY to derive the peer ID — a public value. It is never persisted; see the
  // CLIENT shape below.
  const urls = buildBootstrapUrls({
    host: args.host,
    tcpPort: args.tcpPort,
    wsPort: args.wsPort,
    peerId,
  });

  // CLIENT shape: the peer ID + the address. NEVER BOOTSTRAP_SEED_HEX — a seed in a client .env is
  // a leaked private key with no client use, and `loadBootstrapClientEnv` refuses to boot with one
  // present.
  const updates: Record<string, string> = {
    BOOTSTRAP_PEER_ID: peerId,
    BOOTSTRAP_HOST: args.host,
    BOOTSTRAP_TCP_PORT: String(args.tcpPort),
    BOOTSTRAP_WS_PORT: String(args.wsPort),
    BOOTSTRAP_ENABLE_RELAY: args.enableRelay ? 'true' : 'false',
  };

  const target = args.out ? resolve(args.out) : ENV_PATH;

  console.log('');
  console.log('Bootstrap / relay — client configuration');
  console.log('───────────────────────────────────────');
  console.log(`  Peer ID   : ${peerId}`);
  console.log(`  Host      : ${args.host}   (${args.tcpPort} tcp / ${args.wsPort} ws)`);
  console.log(`  TCP addr  : ${urls.tcpUrl}`);
  console.log(`  WS addr   : ${urls.wsUrl}`);
  console.log(`  Relay     : ${urls.relayAddr}`);
  console.log('');

  const existing = existsSync(target) ? readFileSync(target, 'utf8') : '';
  // Upsert the client keys, STRIP any stale seed, then make sure the logging block exists.
  const next = withLoggingBlock(
    removeEnvKeys(upsertEnvKeys(existing, updates), ['BOOTSTRAP_SEED_HEX']),
  );
  if (args.dryRun) {
    console.log(`[dry-run] would write ${target}:`);
    console.log(next.split('\n').map((l) => `    ${l}`).join('\n'));
    return;
  }
  if (!isGitIgnored(target)) {
    console.error(
      `init-bootstrap-env: refusing to write ${target} — it is NOT gitignored. ` +
      'Add `.env` to .gitignore first so this config can never be committed by accident.',
    );
    process.exit(1);
  }
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, next, { mode: 0o600 });
  console.log(`  ✓ wrote ${target}  (client: peer ID + address only, no seed; chmod 600)`);
  console.log('');
}

main().catch((err) => {
  console.error('init-bootstrap-env:', err instanceof Error ? err.message : err);
  process.exit(1);
});
