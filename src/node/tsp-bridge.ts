// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Bridges the live libp2p/TSP transport into the database.
 *
 * Registers an inbound-message handler on the Libp2pTransport that:
 * 1. Detects TSP_RFI/TSP_RFA handshake messages (CESR-encoded) and
 *    processes them — establishing bidirectional relationships with agents.
 * 2. Routes transaction coordinator messages (tx_prepare, tx_commit, etc.)
 *    through the TransactionCoordinator's handleInboundTxMessage.
 * 3. Falls back to inserting unrecognized messages into the `messages`
 *    table for plain chat/relationship traffic.
 *
 * ## Relationship handshake (TSP_RFI / TSP_RFA)
 *
 * The utility server runs a persistent relationship handler on its TSP
 * transport so agents can establish a bidirectional relationship via the
 * standard RFI/RFA handshake.  Without this, the agent's
 * `TspBridge.connect()` call (which sends an RFI and waits for an RFA)
 * times out after 30 seconds — and name registration, identity push,
 * recovery, and all other TSP protocol operations are unreachable.
 *
 * The handshake is implemented directly against the DataSource (async)
 * rather than through the shared `RelationshipManager` (which is
 * synchronous SQLite-only).  The logic mirrors `RelationshipManager`'s
 * `processRfi()` / `processRfa()` but uses `DsRelationshipStore` and
 * `DsIdentityResolver` for YugabyteDB persistence.
 *
 * ## Protocol routing
 *
 * All protocol operations (identity_push, name_register, name_resolve,
 * identity_lookup) are now handled by
 * TransactionCoordinator Participants registered in the server's
 * bootstrap.  The TSP bridge routes tx_* messages to the coordinator
 * and stores unrecognized messages as raw chat traffic.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { Libp2p } from 'libp2p';
import { Libp2pTransport } from '@p2p-trust-stack/core/transport/libp2p-transport.js';
import type { TransportAddress } from '@p2p-trust-stack/core/transport/types.js';
import * as messagesRepo from '@p2p-trust-stack/core/db/repositories/messages-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import {
  decodeProtocolMessage,
  encodeProtocolMessage,
} from '@p2p-trust-stack/core/tsp-handlers/types.js';

import {
  DsIdentityResolver,
  DsRelationshipStore,
} from './relationship-store-ds.js';

import { isTxProtocol } from '@p2p-trust-stack/core/tx/wire-protocol.js';
import type { TxWireMessage } from '@p2p-trust-stack/core/tx/wire-protocol.js';
import { proofRefusalResponse } from '@p2p-trust-stack/core/tx/operation-proof.js';
import { resolveOperationVid } from '@p2p-trust-stack/core/services/vta.js';
import { shouldStoreUnrecognisedProtocol, describeUnrecognisedProtocolRefusal } from './protocol-rejection.js';
import type { DedupedTxInboundResult } from '@p2p-trust-stack/core/tx/tsp-participant-transport.js';

/**
 * The inbound 2PC entry point this bridge routes to (H7 / decision D-4a).
 *
 * Deliberately **structural, and required to be the DEDUPED one**: the bridge only
 * needs this single function, and typing the parameter as the deduped wrapper (rather
 * than a bare `TransactionCoordinator`) is what makes the H7 protection impossible to
 * wire around by accident — passing `coordinator` here is no longer assignable.
 *
 * A `parse`-time guarantee, not a convention: `BootstrapResult.handleInboundTxMessage`
 * is the only thing in the tree with this signature.
 */
export type InboundTxRouter = (msg: TxWireMessage) => Promise<DedupedTxInboundResult>;

import {
  tspSeal,
  tspOpen,
  peekEnvelope,
  computeSaidDigest,
} from '@p2p-trust-stack/core/tsp/v3/message.js';
import { extractEd25519PublicKey, buildCleanPeer4FromDocument } from '@p2p-trust-stack/core/relationship/key-extract.js';
import { verifyRfiDigest, verifyRfaDigests, verifySenderDocumentBinding } from '@p2p-trust-stack/core/relationship/handshake-verify.js';
import { openConfidentialBody } from '@p2p-trust-stack/core/relationship/confidential-open.js';
import type { DidDocument } from '@p2p-trust-stack/core/did/types.js';
import type { TspRfiPayload, TspRfaPayload, Vid } from '@p2p-trust-stack/core/tsp/v3/types.js';

// ---------------------------------------------------------------------------
// Server VTA identity (set by startTspBridge)
// ---------------------------------------------------------------------------

interface ServerIdentity {
  realDid: string;
  // NOTE: there is deliberately no `vid` field. Both boot paths used to set
  // `vid: vta.realDid`, i.e. a `vid`-named field holding a DID — the exact
  // inversion the G7g audit was about ("no *vid* name fed by a DID source") —
  // and it was a duplicate of `realDid`. The TSP VID slot on the wire carries
  // this DID (both runtimes build `vidSender` from the identity DID), so the
  // slot is filled from `realDid` at the two call sites instead.
  didDocument: DidDocument;
  signingSecretKey: Uint8Array;
  /**
   * The X25519 pair, not just the secret: opening a classical confidential
   * payload needs the public half too (the HPKE context carries it).
   */
  agreementKeyPair?: { publicKey: Uint8Array; secretKey: Uint8Array };
  /** Kept for existing callers; mirrors agreementKeyPair.secretKey. */
  agreementSecretKey: Uint8Array;
  /**
   * Post-quantum roots of trust, when the server identity was provisioned with
   * them (G7e). Undefined on an identity that predates PQ provisioning — the
   * DID document then publishes no #key-mldsa/#key-kem and traffic to this
   * server stays classical.
   */
  mlDsa65KeyPair?: { publicKey: Uint8Array; secretKey: Uint8Array };
  hybridKemKeyPair?: { publicKey: Uint8Array; secretKey: Uint8Array };
}

let serverIdentity: ServerIdentity | null = null;

// ---------------------------------------------------------------------------
// Build RFA (mirrors RelationshipManager.buildRfa)
// ---------------------------------------------------------------------------

function buildRfa(params: {
  localDid: Vid;
  remoteDid: Vid;
  localDidDocument: DidDocument;
  rfiDigest: Uint8Array;
  signingSecretKey: Uint8Array;
}): { sealed: Uint8Array; replyDigest: Uint8Array } {
  const { localDid, remoteDid, localDidDocument, rfiDigest, signingSecretKey } = params;

  // Self-addressing digest (spec 7.2.1): derived over the envelope + payload.
  const replyDigest = computeSaidDigest('RFA', localDid, remoteDid, { requestDigest: rfiDigest });

  const sealed = tspSeal({
    vidSender: localDid,
    vidReceiver: remoteDid,
    payload: {
      type: 'TSP_RFA',
      digest: rfiDigest,
      didDocument: localDidDocument,
    },
    signingSecretKey,
  });

  return { sealed, replyDigest };
}

// ---------------------------------------------------------------------------
// Decline a message we refused (TSP XRFD)
// ---------------------------------------------------------------------------

/**
 * Send an `XRFD` decline carrying the digest of the message being declined.
 *
 * Without it, a refused invite produced NO wire signal: the agent's request
 * simply timed out after 30 s with no indication that it had been rejected. The
 * reason stays in this server's log; the digest lets the agent correlate the
 * decline with the exact invite it sent.
 *
 * Best-effort — a send failure must not break the inbound-message handler.
 */
async function sendRfd(
  transport: Libp2pTransport,
  toAddr: TransportAddress,
  remoteDid: Vid,
  declinedDigest: Uint8Array | undefined,
): Promise<void> {
  if (!serverIdentity || !declinedDigest) return;
  try {
    const sealed = tspSeal({
      vidSender: serverIdentity.realDid,
      vidReceiver: remoteDid,
      payload: { type: 'TSP_RFD', digest: declinedDigest },
      signingSecretKey: serverIdentity.signingSecretKey,
    });
    await transport.send(sealed, toAddr);
    console.log(
      `[tsp-bridge] → XRFD sent to ${remoteDid.slice(0, 24)}... ` +
      `(declined=${Buffer.from(declinedDigest.subarray(0, 8)).toString('hex')})`,
    );
  } catch (err) {
    console.warn('[tsp-bridge] failed to send XRFD:', (err as Error)?.message ?? err);
  }
}

// ---------------------------------------------------------------------------
// Process TSP_RFI — handle an inbound relationship request from an agent
// ---------------------------------------------------------------------------

async function processRfi(
  db: DataSource,
  transport: Libp2pTransport,
  payload: TspRfiPayload,
  fromAddr: TransportAddress,
  senderDidDocument: DidDocument,
  /** Sender VID from the signature-verified envelope (the digest covers this). */
  senderVid: Vid,
  /** Receiver VID from the signature-verified envelope (the addressee check). */
  receiverVid: Vid | null,
): Promise<void> {
  if (!serverIdentity) {
    console.warn('[tsp-bridge] processRfi: server identity not loaded — cannot respond');
    return;
  }

  const resolver = new DsIdentityResolver(db);
  const store = new DsRelationshipStore(db, resolver);

  // The DID document's `id` is the agent's authoritative DID (the v3 VID is the
  // DID string). Derive the method from it rather than hardcoding did:peer:4,
  // which no longer matches did:scid:vh agents and would leave the identity as
  // an endpoint-less "TSP-bridge fake" stub that collides with the real VTA.
  const realDid = senderDidDocument.id!;
  const realMethod = realDid.startsWith('did:scid:vh:') ? 'did:scid:vh' : 'did:peer:4';

  console.log(`[tsp-bridge] ← TSP_RFI from ${realDid.slice(0, 24)}...`);

  // Verify the invite's self-addressing digest (spec 7.2.1) with the SAME shared
  // helper the agent uses. These two responders had diverged — this side verified
  // NOTHING, so a mis-addressed or tampered invite was accepted and answered,
  // establishing a relationship the spec says must be refused. A failure is loud:
  // it is declined with an XRFD so the agent fails fast with a correlation handle
  // instead of timing out after 30 s.
  const rfiCheck = verifyRfiDigest({
    vidSender: senderVid,
    localDid: serverIdentity.realDid,
    nonce: payload.nonce,
    digest: payload.digest,
    receiverVid,
  });
  if (!rfiCheck.ok) {
    console.error(
      `[tsp-bridge] REJECT ${rfiCheck.reason} (${rfiCheck.detail}) ` +
      `from=${realDid.slice(0, 24)}... → declining with XRFD`,
    );
    await sendRfd(transport, fromAddr, realDid, payload.digest);
    return;
  }

  // Ensure the remote identity exists in the database (idempotent), and record
  // the agent's live libp2p endpoint so `hasAnyEndpoint` sees it as a real VTA.
  await resolver.resolveRemoteIdentity({
    did: realDid,
    method: realMethod,
    didDocumentJson: JSON.stringify(buildCleanPeer4FromDocument(senderDidDocument)),
    isPrimary: false,
    recordedByNode: 'tsp-bridge',
    peerId: fromAddr.peerId,
  });

  // Upsert the inbound relationship record
  await store.upsertInbound({
    localDid: serverIdentity.realDid,
    localMethod: 'did:scid:vh',
    remoteDid: realDid,
    remoteMethod: realMethod,
    didDocument: senderDidDocument,
    remoteTransport: fromAddr,
    rfiDigest: payload.digest!,
  });

  // Build and send TSP_RFA response
  const { sealed, replyDigest } = buildRfa({
    localDid: serverIdentity.realDid,
    remoteDid: realDid,
    localDidDocument: serverIdentity.didDocument,
    rfiDigest: payload.digest!,
    signingSecretKey: serverIdentity.signingSecretKey,
  });

  await transport.send(sealed, fromAddr);
  console.log(`[tsp-bridge] → TSP_RFA sent to ${realDid.slice(0, 24)}...`);

  // Store the RFA reply digest
  await store.setRfaReplyDigest(serverIdentity.realDid, realDid, replyDigest);

  // Confirm bidirectional
  await store.confirmBidirectional({
    localDid: serverIdentity.realDid,
    remoteDid: realDid,
    remoteTransport: fromAddr,
    rfaReplyDigest: replyDigest,
  });

  console.log(`[tsp-bridge] ✓ bidirectional relationship established with ${realDid.slice(0, 24)}...`);
}

// ---------------------------------------------------------------------------
// Process TSP_RFA — handle an inbound relationship acceptance
// ---------------------------------------------------------------------------

async function processRfa(
  db: DataSource,
  payload: TspRfaPayload,
  fromAddr: TransportAddress,
  senderDidDocument: DidDocument,
  /** Sender VID from the signature-verified envelope (the digest covers this). */
  senderVid: Vid,
  /** Receiver VID from the signature-verified envelope (the addressee check). */
  receiverVid: Vid | null,
): Promise<void> {
  if (!serverIdentity) return;

  const resolver = new DsIdentityResolver(db);
  const store = new DsRelationshipStore(db, resolver);

  const realDid = senderDidDocument.id!;

  console.log(`[tsp-bridge] ← TSP_RFA from ${realDid.slice(0, 24)}...`);

  // Verify the accept's Reply_Digest (spec 7.2.1) — the same shared helper the
  // agent uses. The server never initiates, so there is no outbound RFI digest to
  // compare `digest` against; the Reply_Digest and the addressee are both
  // checkable from the accept alone.
  const rfaCheck = verifyRfaDigests({
    vidSender: senderVid,
    localDid: serverIdentity.realDid,
    digest: payload.digest,
    replyDigest: payload.replyDigest,
    receiverVid,
  });
  if (!rfaCheck.ok) {
    console.error(
      `[tsp-bridge] REJECT ${rfaCheck.reason} (${rfaCheck.detail}) ` +
      `from=${realDid.slice(0, 24)}... — accept ignored, relationship NOT confirmed`,
    );
    return;
  }

  // Store the responder's DID document and its live endpoint.
  await store.storeRemoteDidDocument(serverIdentity.realDid, realDid, senderDidDocument);
  if (fromAddr?.peerId) {
    await resolver.resolveRemoteIdentity({
      did: realDid,
      method: realDid.startsWith('did:scid:vh:') ? 'did:scid:vh' : 'did:peer:4',
      didDocumentJson: JSON.stringify(buildCleanPeer4FromDocument(senderDidDocument)),
      isPrimary: false,
      recordedByNode: 'tsp-bridge',
      peerId: fromAddr.peerId,
    });
  }

  // Confirm bidirectional
  await store.confirmBidirectional({
    localDid: serverIdentity.realDid,
    remoteDid: realDid,
    remoteTransport: fromAddr,
    rfaReplyDigest: payload.replyDigest!,
  });

  console.log(`[tsp-bridge] ✓ bidirectional relationship confirmed with ${realDid.slice(0, 24)}...`);
}

// ---------------------------------------------------------------------------
// Send a TSP_GEN response back to the agent
// ---------------------------------------------------------------------------

async function sendTspGenResponse(
  transport: Libp2pTransport,
  fromAddr: TransportAddress,
  remoteDid: Vid,
  responseMsg: { protocol: string; correlationId?: string; payload: unknown },
): Promise<void> {
  if (!serverIdentity) {
    console.warn('[tsp-bridge] sendTspGenResponse: no serverIdentity, dropping response');
    return;
  }

  console.log(`[tsp-bridge] → sending TSP_GEN response: ${responseMsg.protocol} to ${remoteDid.slice(0, 12)}... at peerId=${fromAddr.peerId.slice(0, 12)}...`);
  const responseBytes = encodeProtocolMessage(responseMsg);
  const sealed = tspSeal({
    vidSender: serverIdentity.realDid,
    vidReceiver: remoteDid,
    payload: { type: 'TSP_GEN', body: responseBytes },
    signingSecretKey: serverIdentity.signingSecretKey,
  });

  console.log(`[tsp-bridge] → sealed response: sealedBytes=${sealed.length}`);
  await transport.send(sealed, fromAddr);
  console.log(`[tsp-bridge] ✓ TSP_GEN response sent: ${responseMsg.protocol}`);
}

// ---------------------------------------------------------------------------
// Route a protocol message through the transaction coordinator
// ---------------------------------------------------------------------------

async function routeProtocolMessage(
  db: DataSource,
  transport: Libp2pTransport,
  fromAddr: TransportAddress,
  body: Uint8Array,
  remoteDid: Vid,
  inboundTx?: InboundTxRouter,
): Promise<void> {
  const fromDoc = await didDocumentsRepo.findByPeerId(db, fromAddr.peerId);

  let protocolMsg;
  try { protocolMsg = decodeProtocolMessage(body); }
  catch { /* Not a protocol message */ }

  if (protocolMsg && protocolMsg.protocol) {
    console.log(`[tsp-bridge] routeProtocolMessage: protocol=${protocolMsg.protocol} correlationId=${protocolMsg.correlationId?.slice(0, 8) ?? 'none'}`);

    // ── Transaction coordinator routing ──────────────────────────────
    // Route tx_prepare / tx_commit / tx_abort / tx_inquiry / tx_query
    // messages to the server's transaction coordinator, which dispatches
    // to the registered participants (identity_push, name_register,
    // name_resolve, identity_lookup, exchange:*).
    if (inboundTx && isTxProtocol(protocolMsg.protocol)) {
      try {
        const txMsg = protocolMsg.payload as TxWireMessage;

        // F-010 / R1: authority from a SIGNED operation document rather than from the
        // transport that carried it. `remoteDid` is the envelope sender here, so the
        // proof's actor must be that sender.
        //
        // BEFORE dedup, deliberately: a refused prepare must not consume its
        // (txId, messageId) key, or a corrected retry would be swallowed as a replay.
        // F-010 / R1: bind the proof's actor to the SENDER's published operation key. The
        // actor is a CESR VID — an agent's is the CESR encoding of its live Ed25519 keystore
        // key (`meta.vid`), which this node holds as the identity's current key. Passing
        // `remoteDid` compared a CESR key against a DID, which can never match: every prepare
        // was reported `invalid` (observed 2026-09-25) and `enforce` would have refused all
        // cross-node work. An unknown key yields `undefined`, and the binding is then
        // honestly `indeterminate` rather than a false substitution.
        const senderVid = await resolveOperationVid(db, fromDoc?.uuid);
        const refusal = proofRefusalResponse(txMsg, { senderVid });
        if (refusal) {
          await sendTspGenResponse(transport, fromAddr, remoteDid, {
            protocol: refusal.kind,
            correlationId: protocolMsg.correlationId,
            payload: refusal,
          });
          return;
        }

        // H7: deduped entry point — a replayed tx_* message is recognised and dropped
        // WITHOUT re-invoking the coordinator, and must NOT fall through to the
        // "unrecognized protocol message" branch below (a replay is not unrecognised).
        const { duplicate, response } = await inboundTx(txMsg);
        if (duplicate) {
          console.log(`[tsp-bridge] duplicate ${protocolMsg.protocol} suppressed (not re-applied)`);
          return;
        }
        if (response) {
          await sendTspGenResponse(transport, fromAddr, remoteDid, {
            protocol: response.kind,
            correlationId: protocolMsg.correlationId,
            payload: response,
          });
          return;
        }
      } catch (err) {
        // A RECOGNISED tx message must NOT fall through to the F-029 "unrecognised
        // protocol" branch below. Falling through printed
        //   REJECTED unrecognised protocol message "tx_prepare" … (F-029 / Y5-reject)
        // for messages this bridge had just recognised and (usually) already delivered —
        // the failures seen in the field were `Cannot write to a stream that is closed` and
        // `connect ECONNREFUSED` while sending the RESPONSE, so the message was mislabelled
        // as foreign traffic. The same principle is already stated below for the duplicate
        // case ("a replay is not unrecognised"); it applies to the error case too.
        console.error(`[tsp-bridge] tx message handler error:`, (err as Error)?.message);
        return;
      }
    }

    // ── Unrecognised protocol message — REFUSED, not stored (F-029 / ruling Y5-reject) ──
    //
    // This used to be `messagesRepo.create({ type: `tsp-${protocolMsg.protocol}` })`. That
    // table is what the chat UI reads, so an unrecognised protocol message became
    // indistinguishable from real traffic — an unsolicited write into a peer's history.
    // The stack now says no to what it cannot interpret; `shouldStoreUnrecognisedProtocol()`
    // carries the policy, and the `tsp-raw` branch below is untouched because a plain
    // message between peers IS chat traffic.
    if (shouldStoreUnrecognisedProtocol(protocolMsg.protocol)) {
      await messagesRepo.create(db, {
        fromDidDocumentUuid: fromDoc?.uuid ?? null,
        toDidDocumentUuid: null,
        type: `tsp-${protocolMsg.protocol}`,
        payload: new Uint8Array(body),
      });
      return;
    }
    console.warn(
      describeUnrecognisedProtocolRefusal(protocolMsg.protocol, {
        fromDidDocumentUuid: fromDoc?.uuid ?? null,
        bodyLength: body.length,
      }),
    );
    return;
  } else {
    // ── Raw message — store for later inspection ─────────────────────
    await messagesRepo.create(db, {
      fromDidDocumentUuid: fromDoc?.uuid ?? null,
      toDidDocumentUuid: null,
      type: 'tsp-raw',
      payload: new Uint8Array(body),
    });
  }
}

// ---------------------------------------------------------------------------
// Start the TSP bridge
// ---------------------------------------------------------------------------

/**
 * Start the TSP transport on the given libp2p node and wire inbound
 * messages into the transaction coordinator.
 *
 * @param db       YugabyteDB DataSource
 * @param node     Running libp2p node
 * @param identity Server VTA identity (keys, DID, DID document)
 * @param onInboundResponse Optional callback for matching inbound TSP_GEN
 *   responses to pending correlationIds (e.g. ServerTspRequestAdapter).
 *   When provided, it is called BEFORE the coordinator.  If it returns
 *   `true`, the message was consumed and no further routing occurs.
 * @param inboundTx The DEDUPED inbound 2PC entry point for routing
 *   tx_* messages to registered participants.
 */
export async function startTspBridge(
  db: DataSource,
  node: Libp2p,
  /**
   * Server VTA identity. Typed as `ServerIdentity` (not duplicated inline) so the
   * module-level identity and this parameter cannot drift apart — the previous
   * inline copy is why adding the PQ pairs required a change in two places.
   */
  identity?: ServerIdentity,
  onInboundResponse?: (body: Uint8Array) => boolean,
  inboundTx?: InboundTxRouter,
): Promise<Libp2pTransport> {
  // Store the server identity for RFI/RFA processing
  if (identity) {
    serverIdentity = identity;
    console.log(`[tsp-bridge] server identity loaded: ${identity.realDid.slice(0, 30)}...`);
  } else {
    console.warn('[tsp-bridge] no server identity provided — RFI/RFA handshake disabled');
  }

  const transport = new Libp2pTransport(node);

  transport.onMessage(async (message: Uint8Array, fromAddr: TransportAddress) => {
    console.log(`[tsp-bridge] ← inbound message peerId=${fromAddr.peerId.slice(0, 12)}... msgLen=${message.length}`);
    // ── Step 1: Try to detect TSP handshake messages (RFI/RFA) ──────────
    if (serverIdentity) {
      try {
        const peek = peekEnvelope(message);
        console.log(`[tsp-bridge] peekEnvelope: type=${peek.payloadType} vidSender=${peek.vidSender.slice(0, 12)}...`);

        // Record the sender's live libp2p endpoint on EVERY inbound message.
        // The RFI/RFA handshake records it too, but TSP_GEN from an
        // already-established relationship needs it as well — otherwise the
        // sender's identity stays endpoint-less and createVtc rejects it as a
        // "TSP-bridge fake". Idempotent (upsertPeerEndpoint is guarded).
        //
        // `createIfMissing: false`: `peek.vidSender` comes from peekEnvelope(),
        // which only PARSES the envelope — the signature is verified later, and
        // for TSP_GEN it may never be verified at all. Materializing an identity
        // from that value let any sender mint an orphan identity row keyed by
        // whatever it put in the VID field. An unknown sender is skipped here;
        // the handshake (which verifies first, then passes the document's id)
        // still creates first-contact identities.
        if (fromAddr?.peerId) {
          try {
            const resolver = new DsIdentityResolver(db);
            const resolved = await resolver.resolveRemoteIdentity({
              did: peek.vidSender,
              method: peek.vidSender.startsWith('did:scid:vh:') ? 'did:scid:vh' : 'did:peer:4',
              isPrimary: false,
              recordedByNode: 'tsp-bridge',
              peerId: fromAddr.peerId,
              createIfMissing: false,
            });
            if (resolved) {
              console.log(`[tsp-bridge] recorded endpoint ${fromAddr.peerId.slice(0, 12)}… → ${peek.vidSender.slice(0, 24)}…`);
            } else {
              console.log(
                `[tsp-bridge] sender ${peek.vidSender.slice(0, 24)}… is not a known identity — ` +
                `not recording an endpoint for an unverified VID`,
              );
            }
          } catch (err) {
            console.warn('[tsp-bridge] failed to record sender endpoint:', (err as Error)?.message ?? err);
          }
        }

        if (peek.payloadType === 'TSP_RFI' && peek.didDocument) {
          let senderPublicKey: Uint8Array;
          try {
            senderPublicKey = extractEd25519PublicKey(peek.didDocument);
          } catch {
            console.warn('[tsp-bridge] TSP_RFI: cannot extract Ed25519 key from DID document');
            return;
          }

          let envelope: ReturnType<typeof tspOpen>;
          try {
            envelope = tspOpen({ message, senderPublicKey });
          } catch (err) {
            console.warn('[tsp-bridge] TSP_RFI: tspOpen failed:', (err as Error)?.message ?? err);
            return;
          }

          // The inline document is where the sender's signing key came from; the
          // envelope's sender VID is what the relationship is recorded against.
          // They must name the same identity — see verifySenderDocumentBinding().
          const rfiBinding = verifySenderDocumentBinding({
            vidSender: envelope.vidSender,
            document: peek.didDocument,
          });
          if (!rfiBinding.ok) {
            const declinedDigest = envelope.payload.type === 'TSP_RFI'
              ? envelope.payload.digest
              : undefined;
            console.error(
              `[tsp-bridge] TSP_RFI: REJECT ${rfiBinding.reason} (${rfiBinding.detail}) ` +
              `→ declining with XRFD`,
            );
            await sendRfd(transport, fromAddr, envelope.vidSender, declinedDigest);
            return;
          }

          await processRfi(
            db, transport,
            envelope.payload as TspRfiPayload,
            fromAddr,
            peek.didDocument,
            envelope.vidSender,
            envelope.vidReceiver,
          );
          return;
        }

        if (peek.payloadType === 'TSP_RFA' && peek.didDocument) {
          let senderPublicKey: Uint8Array;
          try {
            senderPublicKey = extractEd25519PublicKey(peek.didDocument);
          } catch {
            console.warn('[tsp-bridge] TSP_RFA: cannot extract Ed25519 key from DID document');
            return;
          }

          let envelope: ReturnType<typeof tspOpen>;
          try {
            envelope = tspOpen({ message, senderPublicKey });
          } catch (err) {
            console.warn('[tsp-bridge] TSP_RFA: tspOpen failed:', (err as Error)?.message ?? err);
            return;
          }

          // Same binding requirement as the RFI path (see above).
          const rfaBinding = verifySenderDocumentBinding({
            vidSender: envelope.vidSender,
            document: peek.didDocument,
          });
          if (!rfaBinding.ok) {
            console.error(
              `[tsp-bridge] TSP_RFA: REJECT ${rfaBinding.reason} (${rfaBinding.detail}) ` +
              `— accept ignored, relationship NOT confirmed`,
            );
            return;
          }

          await processRfa(
            db,
            envelope.payload as TspRfaPayload,
            fromAddr,
            peek.didDocument,
            envelope.vidSender,
            envelope.vidReceiver,
          );
          return;
        }

        // ── TSP_GEN / TSP_GEN_CONFIDENTIAL: protocol messages ──────────
        if (peek.payloadType === 'TSP_GEN' || peek.payloadType === 'TSP_GEN_CONFIDENTIAL') {
          // Look up the sender's Ed25519 public key from the relationship store
          const resolver = new DsIdentityResolver(db);
          const store = new DsRelationshipStore(db, resolver);
          const relRecord = await store.get(serverIdentity.realDid, peek.vidSender);
          if (!relRecord || !relRecord.remoteEd25519Key) {
            console.warn(`[tsp-bridge] TSP_GEN from ${peek.vidSender.slice(0, 12)}...: no relationship or missing Ed25519 key — dropping`);
            return;
          }

          // ── Recover the INNER BODY, per payload type ──────────────────
          //
          // A confidential payload is NOT a payload with a `body`: it is a single
          // HPKE-Base cipher (enc || ciphertext), so reading `.body` off it yields
          // undefined and the server would route nothing while looking successful.
          // It has to be opened with the same rule the agent uses — see
          // openConfidentialBody() — which is why the server needs an X25519 pair
          // and, when it publishes #key-kem, its MLKEM768-X25519 pair.
          let innerBody: Uint8Array | undefined;
          if (peek.payloadType === 'TSP_GEN_CONFIDENTIAL') {
            const opened = await openConfidentialBody({
              message,
              senderPublicKey: relRecord.remoteEd25519Key,
              vidSender: peek.vidSender,
              vidReceiver: serverIdentity.realDid,
              agreementKeyPair: serverIdentity.agreementKeyPair,
              hybridKemKeyPair: serverIdentity.hybridKemKeyPair,
              expectHybrid: !!relRecord.remoteHybridKemKey,
            });
            if (!opened) {
              console.warn(
                `[tsp-bridge] TSP_GEN_CONFIDENTIAL from ${peek.vidSender.slice(0, 12)}...: could not open ` +
                `with either KEM (peer publishes #key-kem: ${!!relRecord.remoteHybridKemKey}; ` +
                `this server holds #key-kem: ${!!serverIdentity.hybridKemKeyPair}) — dropping`,
              );
              return;
            }
            innerBody = opened.plaintext;
            console.log(`[tsp-bridge] ← TSP_GEN_CONFIDENTIAL from ${peek.vidSender.slice(0, 12)}... opened with the ${opened.used} KEM bodyLen=${innerBody.length}`);
          } else {
            let envelope: ReturnType<typeof tspOpen>;
            try {
              envelope = tspOpen({ message, senderPublicKey: relRecord.remoteEd25519Key });
            } catch (err) {
              console.warn(
                '[tsp-bridge] TSP_GEN: tspOpen failed:',
                (err as Error)?.message ?? err,
                `storedEd25519=${Buffer.from(relRecord.remoteEd25519Key).toString('hex')}`,
                `vidSender=${peek.vidSender}`,
              );
              return;
            }
            innerBody = (envelope.payload as { type: string; body: Uint8Array }).body;
            console.log(`[tsp-bridge] ← TSP_GEN from ${peek.vidSender.slice(0, 12)}... bodyLen=${innerBody.length}`);
          }

          if (!innerBody || innerBody.length === 0) {
            console.warn(`[tsp-bridge] TSP_GEN from ${peek.vidSender.slice(0, 12)}...: empty body — dropping`);
            return;
          }

          // ── Check for pending correlationId match FIRST ───────────────
          if (onInboundResponse?.(innerBody)) {
            console.log(`[tsp-bridge] ← TSP_GEN response matched pending correlationId — consumed by adapter`);
            return;
          }

          // Route the inner body through the transaction coordinator
          await routeProtocolMessage(db, transport, fromAddr, innerBody, peek.vidSender, inboundTx);
          return;
        }
      } catch (err) {
        console.log(`[tsp-bridge] peekEnvelope failed (not CESR?): ${(err as Error)?.message ?? err}`);
        // Not a CESR TSP message — fall through
      }
    }

    // ── Step 2: Try JSON protocol messages (non-CESR, direct JSON) ─────
    await routeProtocolMessage(db, transport, fromAddr, message, '' as Vid, inboundTx);
  });

  await transport.start();
  return transport;
}