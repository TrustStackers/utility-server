// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Server-side TSP request adapter — creates a TspRequestFn for the utility
 * server to initiate transaction-coordinated requests to agents.
 *
 * This mirrors TspClientModule.request() but adapted for the server side:
 *   1. Encodes the message as a ProtocolMessage
 *   2. Wraps it in a TSP_GEN CESR envelope via tspSeal()
 *   3. Sends via the libp2p transport
 *   4. Awaits the correlated response via a pending registry
 *
 * Used by the server→agent transaction coordinator to send tx_prepare/tx_commit
 * to agents (e.g. the utility server's AgentDeliveryQueue for
 * exchange:vtc-membership / exchange:credential pushes).
 */

import { randomUUID } from 'node:crypto';
import type { Libp2p } from 'libp2p';
import { Libp2pTransport } from '@p2p-trust-stack/core/transport/libp2p-transport.js';
import type { TransportAddress } from '@p2p-trust-stack/core/transport/types.js';
import {
  encodeProtocolMessage,
  decodeProtocolMessage,
} from '@p2p-trust-stack/core/tsp-handlers/types.js';
import { tspSeal } from '@p2p-trust-stack/core/tsp/v3/message.js';
import type { TspRequestFn } from '@p2p-trust-stack/core/tx/tsp-participant-transport.js';

interface PendingRequest {
  resolve: (response: { protocol: string; correlationId?: string; payload: unknown }) => void;
  reject: (err: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
}

/**
 * Create a TspRequestFn that sends protocol messages to agents via TSP_GEN
 * and awaits correlated responses.
 *
 * @param node        The running libp2p node
 * @param serverDid   The server's VID (CESR-encoded Ed25519 public key)
 * @param signingSecretKey  The server's Ed25519 signing secret key
 * @param resolveAddress    Function to resolve a destination string to a TransportAddress
 */
export interface ServerTspRequestAdapter {
  request: TspRequestFn;
  /** Check whether the transport has an active libp2p connection to a peerId. */
  isConnected: (pid: string) => boolean;
  /** Handle an inbound TSP_GEN response that may match a pending correlationId. */
  handleInboundResponse: (body: Uint8Array) => boolean;
  /** Clean up all pending requests. */
  destroy: () => void;
}

export function createServerTspRequestFn(
  node: Libp2p,
  serverDid: string,
  signingSecretKey: Uint8Array,
  resolveAddress: (destination: string) => TransportAddress | null,
): ServerTspRequestAdapter {
  const transport = new Libp2pTransport(node);
  const pending = new Map<string, PendingRequest>();

  // Register a handler for inbound TSP_GEN responses that match pending correlationIds.
  // This is wired into the TSP bridge's message handler.
  const handleInboundResponse = (body: Uint8Array): boolean => {
    let msg;
    try {
      msg = decodeProtocolMessage(body);
    } catch {
      return false;
    }
    if (msg.correlationId && pending.has(msg.correlationId)) {
      const entry = pending.get(msg.correlationId)!;
      clearTimeout(entry.timeout);
      pending.delete(msg.correlationId);
      entry.resolve(msg);
      return true;
    }
    return false;
  };

  /** Check whether the libp2p transport has an active connection to a peer.
   *  The `pid` is in the format used by TspParticipantTransport:
   *    - 'peer:{vid}:{peerId}' → extracts peerId for libp2p connectivity check
   *    - 'peer:{vid}'         → uses vid as peerId
   *    - 'server:...'         → always true (local participants)
   */
  const isConnected = (pid: string): boolean => {
    // Extract the peerId from the pid format used by TspParticipantTransport.
    let peerIdForCheck: string;
    if (pid.startsWith('peer:')) {
      const suffix = pid.slice(5); // '{vid}:{peerId}' or '{vid}'
      // The VID is a DID string (contains ':'), so the peerId separator is the LAST ':'.
      const colonIdx = suffix.lastIndexOf(':');
      peerIdForCheck = colonIdx > 0 ? suffix.slice(colonIdx + 1) : suffix;
    } else if (pid.startsWith('server:')) {
      return true; // local participant — always "connected"
    } else {
      peerIdForCheck = pid;
    }
    return transport.isConnected(peerIdForCheck);
  };

  const requestFn: TspRequestFn = async (destination, protocol, payload, timeoutMs = 30_000) => {
    // destination may be compound: '{vid}:{peerId}' or just '{vid}'
    // Extract the VID for tspSeal() and the peerId for transport routing.
    // NOTE: a v3 VID is a DID string (contains ':'), so the peerId separator is
    // the LAST ':' (libp2p PeerIDs are base58 and never contain ':').
    let vidReceiver: string;
    let peerIdForRouting: string;

    const colonIdx = destination.lastIndexOf(':');
    if (colonIdx > 0 && colonIdx < destination.length - 1) {
      // Compound format: '{vid}:{peerId}'
      vidReceiver = destination.slice(0, colonIdx);
      peerIdForRouting = destination.slice(colonIdx + 1);
    } else {
      // Simple format: just the VID (or peerId)
      vidReceiver = destination;
      peerIdForRouting = destination;
    }

    const addr = resolveAddress(peerIdForRouting);
    if (!addr) {
      throw new Error(`Cannot resolve address for destination: ${peerIdForRouting}`);
    }

    const correlationId = randomUUID();
    const msg = { protocol, correlationId, payload };
    const body = encodeProtocolMessage(msg);

    // Wrap in TSP_GEN CESR envelope using the VID as vidReceiver
    const sealed = tspSeal({
      vidSender: serverDid,
      vidReceiver,
      payload: { type: 'TSP_GEN', body },
      signingSecretKey,
    });

    const promise = new Promise<{ protocol: string; correlationId?: string; payload: unknown }>((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(correlationId);
        // No response within the window. A half-open/black-holed connection
        // accepts the write silently, so this is the only signal that the frame
        // never reached the agent — drop the cached connection so the retry
        // re-dials instead of timing out the same way again.
        void transport.invalidatePeer?.(
          peerIdForRouting,
          'request timed out — reuse of a silent connection avoided',
        );
        reject(new Error(`TSP request '${protocol}' timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      pending.set(correlationId, { resolve, reject, timeout: timer });
    });

    try {
      await transport.send(sealed, addr);
    } catch (sendErr) {
      const entry = pending.get(correlationId);
      if (entry) {
        clearTimeout(entry.timeout);
        pending.delete(correlationId);
      }
      throw sendErr;
    }

    // Attach a catch handler to prevent unhandled rejections from crashing the process.
    // The caller (RemoteParticipant) will catch the error via its own try/catch.
    promise.catch(() => { /* caught by caller */ });

    return promise;
  };

  return { request: requestFn, isConnected, handleInboundResponse, destroy: () => {
    for (const [, entry] of pending) {
      clearTimeout(entry.timeout);
      entry.reject(new Error('server TSP request adapter shutting down'));
    }
    pending.clear();
  }};
}
