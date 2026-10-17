// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Server node transport info — a tiny module-level holder so participants
 * (which don't receive the live libp2p node) can build OOBIs that point at
 * this server's own peerId + multiaddrs.
 *
 * Set once at startup in index.ts (where the node is available); read by the
 * VTC participant's `vtc_invite` query op.
 */

export interface ServerNodeInfo {
  peerId: string;
  multiaddrs: string[];
  /**
   * The server's own real DID (the identity agents address their invites to).
   *
   * Needed to build a *dialable* invite/connection OOBI: the invite's peerId
   * reaches this node, so the OOBI's `did` must be THIS identity, not the
   * community's (a community is an identities row here, not a libp2p node).
   * Populated once the server VTA identity is resolved at startup; null before
   * that (or if the VTA load failed), in which case invite builders fall back to
   * the legacy behaviour with a warning.
   */
  did: string | null;
}

let info: ServerNodeInfo | null = null;

export function setServerNodeInfo(peerId: string, multiaddrs: string[]): void {
  info = { peerId, multiaddrs, did: info?.did ?? null };
}

/** Record the server's own real DID (see {@link ServerNodeInfo.did}). */
export function setServerNodeDid(realDid: string): void {
  if (!info) {
    info = { peerId: '', multiaddrs: [], did: realDid };
    return;
  }
  info = { ...info, did: realDid };
}

export function getServerNodeInfo(): ServerNodeInfo | null {
  return info;
}
