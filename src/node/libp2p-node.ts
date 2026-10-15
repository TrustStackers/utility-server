/**
 * Boots a libp2p node for the utility server with transports matching the
 * agent-app: TCP + WebSockets + circuit-relay-v2 (for NAT traversal and
 * relay reservations).  Supports a deterministic peer ID via seeded key.
 *
 * mDNS is intentionally excluded — peer discovery happens exclusively
 * through the bootstrap server (see bootstrap registration in index.ts).
 *
 * circuit-relay-v2 is dynamically imported (like the agent-app's
 * createLibp2pNodeOnPortRange), and `as any` is used on the transport list
 * to avoid a PeerMap type mismatch caused by duplicate
 * @libp2p/peer-collections installs across workspace members.
 */

import { createLibp2p, type Libp2p } from 'libp2p';
import { tcp } from '@libp2p/tcp';
import { webSockets } from '@libp2p/websockets';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { identify } from '@libp2p/identify';
import { keys } from '@libp2p/crypto';

export interface Libp2pNodeOptions {
  /** Bind host (default: 0.0.0.0). */
  host?: string;
  /** TCP listen port. 0 = OS-assigned. */
  port?: number;
  /** Optional hex-encoded 32-byte Ed25519 seed for a deterministic peer ID. */
  seed?: string;
}

/**
 * Create and start a libp2p node for this server.
 *
 * When a `seed` is provided, the server uses a deterministic Ed25519 key
 * pair and therefore a stable peer ID across restarts — required for the
 * bootstrap server to recognise this peer and for agents to persist a
 * relationship to it.
 *
 * The node includes circuit-relay-v2 transport so the server can establish
 * a relay reservation on the bootstrap server and be reachable by agents
 * behind NAT/firewalls via `/p2p-circuit`.
 */
export async function startLibp2pNode(options: Libp2pNodeOptions = {}): Promise<Libp2p> {
  const host = options.host ?? '0.0.0.0';
  const port = options.port ?? 0;

  // Seeded key for deterministic peer ID, or random on every start.
  const privateKey = options.seed
    ? await keys.generateKeyPairFromSeed('Ed25519', hexToBytes(options.seed))
    : undefined;

  // Dynamic import avoids type-level PeerMap mismatch across workspace
  // node_modules (same pattern used in agent-app).
  const { circuitRelayTransport } = await import('@libp2p/circuit-relay-v2');

  // `as any` silences the PeerMap type mismatch — functionally identical
  // to the agent-app's createLibp2pNodeOnPortRange which also uses
  // dynamic import with the same transport list.
  const node = await createLibp2p({
    privateKey,
    addresses: { listen: [`/ip4/${host}/tcp/${port}`] },
    transports: [tcp(), webSockets(), circuitRelayTransport()] as any,
    streamMuxers: [yamux()],
    connectionEncrypters: [noise()],
    connectionManager: {
      // Hardening (B3): bound the connection table and prune stale/half-open
      // connections so server→agent dials don't hit dead cached streams.
      maxConnections: 256,
      maxParallelDials: 64,
      dialTimeout: 10_000,
      addressDialTimeout: 6_000,
    },
    services: {
      identify: identify(),
      ping: (await import('@libp2p/ping')).ping(),
    },
  });

  return node;
}

/** Convert a hex string to a Uint8Array (no dependencies). */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}