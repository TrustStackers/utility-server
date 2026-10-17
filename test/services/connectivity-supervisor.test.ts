// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Tests: ConnectivitySupervisor — utility-server-side recovery policy.
 *
 * The supervisor exists because the server used to (a) register with the
 * bootstrap server exactly once and never retry, (b) hold no circuit-relay
 * reservation at all, and (c) resume a member's paused delivery queue only when
 * that member happened to reconnect inbound. A relay-session expiry therefore
 * left members unreachable by the server indefinitely.
 *
 * These tests drive `runTick()` with injected fakes — no libp2p, no timers, no
 * database — and assert the three stages and their backoff behaviour.
 */
import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import type { Libp2p } from 'libp2p';

import {
  ConnectivitySupervisor,
  extractPeerId,
  isDialablePeerId,
  type ConnectivitySupervisorDeps,
  type MemberEndpoint,
} from '../../src/services/connectivity-supervisor.js';

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

/** Node fake: connection table, dial recorder, reservation store. */
function makeNode(opts: {
  peerId?: string;
  connected?: string[];
  reservedPeers?: string[];
  dialImpl?: (addr: string) => Promise<unknown>;
  /** Addresses the fake peer store holds for ANY peer id it is asked about. */
  peerStoreAddrs?: string[];
}) {
  const connected = new Set(opts.connected ?? []);
  const reserved = new Set(opts.reservedPeers ?? []);
  const dialed: string[] = [];
  /**
   * How each dial target was SHAPED: 'multiaddr' for a parsed Multiaddr object,
   * otherwise the JS `typeof`. libp2p's `dial()` only accepts a Multiaddr —
   * a string throws `multiaddrs[0].getComponents is not a function` — so the
   * shape is asserted, not just the address.
   */
  const dialTypes: string[] = [];

  /** A real Multiaddr has `getComponents`; a plain string does not. */
  const asString = (addr: unknown): string =>
    typeof addr === 'string' ? addr : String(addr);
  const shapeOf = (addr: unknown): string =>
    addr != null && typeof (addr as { getComponents?: unknown }).getComponents === 'function'
      ? 'multiaddr'
      : typeof addr;

  const node = {
    peerId: { toString: () => opts.peerId ?? '12D3KooWSELF' },
    getConnections: (peerId: unknown) =>
      connected.has(String(peerId)) ? [{ status: 'open' }] : [],
    dial: async (addr: unknown) => {
      dialed.push(asString(addr));
      dialTypes.push(shapeOf(addr));
      if (opts.dialImpl) return opts.dialImpl(asString(addr));
      throw new Error(`dial refused: ${asString(addr)}`);
    },
    // Deliberately answers the same list for every peer id: the supervisor only
    // asks about the member it is re-dialling. Shape matches libp2p's
    // `peerStore.get(peerId)` → `{ addresses: [{ multiaddr }] }`.
    peerStore: opts.peerStoreAddrs
      ? {
          get: async () => ({
            addresses: opts.peerStoreAddrs!.map((a) => ({
              multiaddr: { toString: () => a },
            })),
          }),
        }
      : undefined,
    components: {
      transportManager: {
        getTransports: () => [
          {
            reservationStore: {
              hasReservation: (peerId: { toString(): string }) =>
                reserved.has(peerId.toString()),
            },
          },
        ],
      },
    },
  };

  return {
    node: node as unknown as Libp2p,
    dialed,
    dialTypes,
    reserved,
    markConnected: (peerId: string) => connected.add(peerId),
  };
}

/** Build supervisor deps with sane defaults, overridable per test. */
function makeDeps(overrides: Partial<ConnectivitySupervisorDeps> = {}) {
  const events: string[] = [];
  let bootstrapConnected = true;
  let registerCalls = 0;
  let ensureCalls = 0;
  let members: MemberEndpoint[] = [];

  const base: ConnectivitySupervisorDeps = {
    node: makeNode({}).node,
    register: async () => {
      registerCalls++;
      bootstrapConnected = true;
    },
    ensureRelayReservation: async () => {
      ensureCalls++;
    },
    isBootstrapConnected: () => bootstrapConnected,
    listMemberEndpoints: async () => members,
    getRelayAddr: () => '/dns/relay.test/tcp/4001/p2p/12D3KooWRELAY/p2p-circuit',
    onMemberReconnected: async (peerId) => {
      events.push(`reconnected:${peerId}`);
    },
    onStatus: (message) => {
      events.push(message);
    },
    tickMs: 60_000,
    registerBackoffMinMs: 0,
    memberBackoffMinMs: 0,
  };

  const merged: ConnectivitySupervisorDeps = { ...base, ...overrides };
  return {
    deps: merged,
    events,
    setBootstrapConnected: (v: boolean) => {
      bootstrapConnected = v;
    },
    setMembers: (m: MemberEndpoint[]) => {
      members = m;
    },
    getRegisterCalls: () => registerCalls,
    getEnsureCalls: () => ensureCalls,
  };
}

// ---------------------------------------------------------------------------
// Stage 1: bootstrap registration
// ---------------------------------------------------------------------------

describe('ConnectivitySupervisor: bootstrap registration', () => {
  let h: ReturnType<typeof makeDeps>;

  beforeEach(() => {
    h = makeDeps();
  });

  it('does not register while bootstrap is already connected', async () => {
    const sup = new ConnectivitySupervisor(h.deps);
    await sup.runTick();
    assert.equal(h.getRegisterCalls(), 0);
  });

  it('re-registers when the bootstrap connection is down', async () => {
    h.setBootstrapConnected(false);
    const sup = new ConnectivitySupervisor(h.deps);
    await sup.runTick();
    assert.equal(h.getRegisterCalls(), 1);
    assert.ok(h.events.some((e) => /registration \(re\)established/.test(e)));
  });

  it('retries forever, backing off between attempts (no terminal give-up)', async () => {
    let failures = 0;
    h = makeDeps({
      isBootstrapConnected: () => false,
      register: async () => {
        failures++;
        throw new Error('bootstrap unreachable');
      },
    });
    const sup = new ConnectivitySupervisor(h.deps);

    // With a 0ms first backoff the second tick retries immediately; the point
    // is that it NEVER stops trying (the old code called register() once).
    await sup.runTick();
    await sup.runTick();
    await sup.runTick();
    assert.equal(failures, 3);
    assert.ok(h.events.some((e) => /registration failed \(attempt 1\)/.test(e)));
  });

  it('stops retrying once a later attempt succeeds', async () => {
    let attempt = 0;
    let connected = false;
    h = makeDeps({
      isBootstrapConnected: () => connected,
      register: async () => {
        attempt++;
        if (attempt < 2) throw new Error('still down');
        connected = true;
      },
    });
    const sup = new ConnectivitySupervisor(h.deps);
    await sup.runTick(); // fails
    await sup.runTick(); // succeeds
    await sup.runTick(); // no-op
    assert.equal(attempt, 2);
  });
});

// ---------------------------------------------------------------------------
// Stage 2: circuit-relay reservation
// ---------------------------------------------------------------------------

describe('ConnectivitySupervisor: relay reservation', () => {
  it('re-applies the reservation when the relay has none for us', async () => {
    const fake = makeNode({ reservedPeers: [] });
    const h = makeDeps({ node: fake.node });
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();
    assert.equal(h.getEnsureCalls(), 1);
  });

  it('does not re-apply a reservation we already hold', async () => {
    // This matters: TransportManager.listen() has no address dedupe, so calling
    // it repeatedly leaks a listener object each time.
    const fake = makeNode({ reservedPeers: ['12D3KooWRELAY'] });
    const h = makeDeps({ node: fake.node });
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();
    assert.equal(h.getEnsureCalls(), 0);
  });

  it('skips the reservation when no relay is advertised', async () => {
    const fake = makeNode({ reservedPeers: [] });
    const h = makeDeps({ node: fake.node, getRelayAddr: () => undefined });
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();
    assert.equal(h.getEnsureCalls(), 0);
  });

  it('waits for bootstrap before attempting a reservation', async () => {
    const fake = makeNode({ reservedPeers: [] });
    const h = makeDeps({
      node: fake.node,
      isBootstrapConnected: () => false,
      register: async () => {
        throw new Error('down');
      },
    });
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();
    assert.equal(h.getEnsureCalls(), 0);
  });

  it('spaces reservation retries out instead of re-listening every tick', async () => {
    // `TransportManager.listen()` has no address-level dedupe, so an
    // unconfirmable reservation used to create a fresh listener (and log the
    // same un-actionable line) on every 15 s tick, forever.
    const fake = makeNode({ reservedPeers: [] });
    const h = makeDeps({ node: fake.node, relayBackoffMinMs: 60_000 });
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();
    assert.equal(h.getEnsureCalls(), 1, 'the first tick must still attempt immediately');

    await sup.runTick();
    await sup.runTick();
    assert.equal(h.getEnsureCalls(), 1, 'later ticks must respect the backoff');
    assert.ok(sup.getStatus().relay.nextAttemptInMs > 0);
  });

  it('warns once with the reason, then reports the streak at info', async () => {
    const fake = makeNode({ reservedPeers: [] });
    const h = makeDeps({ node: fake.node, relayBackoffMinMs: 0 });
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick(); // attempt fails
    await sup.runTick(); // attempt fails again

    const warnings = h.events.filter((e) => /requested but not yet confirmed/.test(e));
    assert.equal(warnings.length, 1, 'the warning must not repeat every tick');
    assert.match(
      warnings[0]!,
      /reason not reported by the bootstrap client/,
      'a swallowed reason must be named as such rather than implied',
    );
    assert.ok(
      h.events.some((e) => /still unconfirmed after 2 attempt\(s\)/.test(e)),
      `expected a streak report, got: ${JSON.stringify(h.events)}`,
    );
    assert.equal(sup.getStatus().relay.consecutiveFailures, 2);
  });

  it('re-attempts at once after a success (the failure streak is reset)', async () => {
    const fake = makeNode({ reservedPeers: [] });
    const h = makeDeps({ node: fake.node, relayBackoffMinMs: 600_000 });
    // Grant the reservation on the first attempt only, so the second loss has
    // to be re-attempted rather than waiting out a 10-minute backoff.
    let grants = 0;
    h.deps.ensureRelayReservation = async () => {
      grants++;
      if (grants === 1) fake.reserved.add('12D3KooWRELAY');
    };
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();
    assert.equal(grants, 1);
    assert.ok(h.events.some((e) => /relay reservation \(re\)established/.test(e)));

    fake.reserved.delete('12D3KooWRELAY'); // the reservation is lost again
    await sup.runTick();
    assert.equal(grants, 2, 'a lost reservation must be re-attempted immediately');
  });
});


// ---------------------------------------------------------------------------
// Stage 3: member reconnects
// ---------------------------------------------------------------------------

describe('ConnectivitySupervisor: member reconnects', () => {
  const member: MemberEndpoint = {
    peerId: '12D3KooWAGENT',
    multiaddrs: ['/ip4/192.168.1.9/tcp/24001', '/dns/relay.test/tcp/4001/p2p/12D3KooWRELAY/p2p-circuit'],
    label: 'alice',
  };

  /**
   * A syntactically REAL peer id (base58btc ed25519 multihash). Required by the
   * peer-store tests: the store is keyed by a parsed PeerId, so the synthetic
   * short ids used elsewhere in this file cannot be looked up in it.
   */
  const REAL_PEER_ID = '12D3KooWDWknVaqQesqsHf24nEeHjCe2wWNhMVxwmPHyNArKBegp';

  it('re-dials a member whose connection is down and resumes its queue', async () => {
    const fake = makeNode({
      reservedPeers: ['12D3KooWRELAY'],
      dialImpl: async () => ({ status: 'open' }),
    });
    const h = makeDeps({ node: fake.node });
    h.setMembers([member]);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();

    // Direct address first; the relay address is not needed once direct works.
    assert.deepEqual(fake.dialed, ['/ip4/192.168.1.9/tcp/24001']);
    assert.deepEqual(
      h.events.filter((e) => e.startsWith('reconnected:')),
      ['reconnected:12D3KooWAGENT'],
    );
  });

  it('falls back to the relay address when direct dialling fails', async () => {
    const fake = makeNode({
      reservedPeers: ['12D3KooWRELAY'],
      dialImpl: async (addr: string) => {
        if (addr.includes('/p2p-circuit')) return { status: 'open' };
        throw new Error('direct refused');
      },
    });
    const h = makeDeps({ node: fake.node });
    h.setMembers([member]);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();

    assert.equal(fake.dialed.length, 2);
    assert.equal(
      fake.dialed[1],
      '/dns/relay.test/tcp/4001/p2p/12D3KooWRELAY/p2p-circuit/p2p/12D3KooWAGENT',
    );
    assert.deepEqual(
      h.events.filter((e) => e.startsWith('reconnected:')),
      ['reconnected:12D3KooWAGENT'],
    );
  });

  it('dials a peer-store address when the member row carries no direct address', async () => {
    // The regression this guards: `peer_endpoints.multiaddrs` was written as
    // NULL by the identity push, so the ONLY candidate was the relay and every
    // tick logged `all 1 address(es) failed` even when a direct path was known
    // to libp2p. The peer store's addresses must be considered too.
    //
    // A REAL peer id (base58btc ed25519 multihash) is used here: the peer store
    // is keyed by a parsed PeerId, so the synthetic short ids the other tests
    // use cannot be looked up (and correctly yield no candidates).
    const fake = makeNode({
      reservedPeers: ['12D3KooWRELAY'],
      peerStoreAddrs: ['/ip4/192.168.1.9/tcp/24001'],
      dialImpl: async () => ({ status: 'open' }),
    });
    const h = makeDeps({ node: fake.node });
    h.setMembers([{ peerId: REAL_PEER_ID, multiaddrs: [], label: 'alice' }]);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();

    assert.deepEqual(fake.dialed, ['/ip4/192.168.1.9/tcp/24001']);
    assert.deepEqual(
      h.events.filter((e) => e.startsWith('reconnected:')),
      [`reconnected:${REAL_PEER_ID}`],
    );
  });

  it('caps how many peer-store candidates one tick will dial', async () => {
    const many = Array.from({ length: 9 }, (_, i) => `/ip4/10.0.0.${i + 1}/tcp/24001`);
    const fake = makeNode({
      reservedPeers: ['12D3KooWRELAY'],
      peerStoreAddrs: many,
    });
    const h = makeDeps({ node: fake.node });
    h.setMembers([{ peerId: REAL_PEER_ID, multiaddrs: [], label: 'alice' }]);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();

    // Each candidate carries its own DIAL_TIMEOUT_MS, so a large address book
    // must not be walked in full on one tick: the 9 peer-store addresses are
    // capped at 4, plus the single relay candidate.
    assert.equal(fake.dialed.length, 5, 'expected the peer-store candidate cap (+ relay)');
    assert.ok(
      !fake.dialed.some((a) => a.startsWith('/ip4/10.0.0.5')),
      'addresses past the cap must not be dialled',
    );
  });

  it('does not duplicate an address present in both the row and the peer store', async () => {
    const fake = makeNode({
      reservedPeers: ['12D3KooWRELAY'],
      peerStoreAddrs: ['/ip4/192.168.1.9/tcp/24001'],
      dialImpl: async () => ({ status: 'open' }),
    });
    const h = makeDeps({ node: fake.node });
    h.setMembers([{ peerId: REAL_PEER_ID, multiaddrs: ['/ip4/192.168.1.9/tcp/24001'], label: 'alice' }]);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();

    assert.deepEqual(fake.dialed, ['/ip4/192.168.1.9/tcp/24001']);
  });

  it('leaves already-connected members alone', async () => {
    const fake = makeNode({
      connected: ['12D3KooWAGENT'],
      reservedPeers: ['12D3KooWRELAY'],
    });
    const h = makeDeps({ node: fake.node });
    h.setMembers([member]);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();
    assert.deepEqual(fake.dialed, []);
  });

  it('never dials itself', async () => {
    const fake = makeNode({ peerId: '12D3KooWSELF', reservedPeers: ['12D3KooWRELAY'] });
    const h = makeDeps({ node: fake.node });
    h.setMembers([{ peerId: '12D3KooWSELF', multiaddrs: ['/ip4/127.0.0.1/tcp/24001'] }]);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();
    assert.deepEqual(fake.dialed, []);
  });

  it('never dials a placeholder peer ID (the setup-flow `bootstrap-<hex>` endpoint)', async () => {
    // The VTC setup flow writes an ACTIVE endpoint whose peer_id is
    // `bootstrap-${16 random bytes as hex}` for a founder VTA whose agent has
    // not run yet. It is not a libp2p peer ID, so every dial fails — but before
    // this guard the supervisor retried it forever (reaching the 120s backoff
    // cap) and logged a warning on every retry.
    const fake = makeNode({
      reservedPeers: ['12D3KooWRELAY'],
      dialImpl: async () => ({ status: 'open' }),
    });
    const h = makeDeps({ node: fake.node, memberBackoffMinMs: 60_000 });
    h.setMembers([
      {
        peerId: 'bootstrap-6105b830373d15a11db1ef8a3594c441',
        multiaddrs: [],
        label: 'shannon',
      },
    ]);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();
    await sup.runTick(); // and it stays silent on later ticks too

    assert.deepEqual(fake.dialed, [], 'a non-peer ID must never be dialled');
    assert.ok(
      !h.events.some((e) => /reconnect to agent bootstrap-/.test(e)),
      'the placeholder must not produce a reconnect warning',
    );
    // It is not a "stuck member" either: skipping happens BEFORE bookkeeping, so
    // the operator status surface stays clean.
    assert.equal(sup.getStatus().membersInBackoff, 0);
    assert.equal(sup.getStatus().members.length, 0);
  });

  it('still dials a real peer ID alongside a skipped placeholder', async () => {
    const fake = makeNode({
      reservedPeers: ['12D3KooWRELAY'],
      dialImpl: async () => ({ status: 'open' }),
    });
    const h = makeDeps({ node: fake.node });
    h.setMembers([
      { peerId: 'bootstrap-6105b830373d15a11db1ef8a3594c441', multiaddrs: [] },
      { peerId: '12D3KooWAGENT', multiaddrs: ['/ip4/192.168.1.9/tcp/24001'] },
    ]);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();

    assert.deepEqual(fake.dialed, ['/ip4/192.168.1.9/tcp/24001']);
    assert.deepEqual(
      h.events.filter((e) => e.startsWith('reconnected:')),
      ['reconnected:12D3KooWAGENT'],
    );
  });

  it('hands libp2p a Multiaddr, never a bare string', async () => {
    // Regression. `node.dial()` runs its target through libp2p's
    // `getPeerAddress()`, which does `multiaddrs[0].getComponents()`. A plain
    // string has no `getComponents`, so the call threw
    // `TypeError: multiaddrs[0].getComponents is not a function` BEFORE any
    // connection was attempted: every candidate "failed", the tick logged
    // `reconnect to agent … failed (all N address(es) failed)`, and the server
    // never re-dialled a member it had lost — which is exactly the field log
    // this guards (`reconnected to agent …` had never once been printed).
    const fake = makeNode({ reservedPeers: ['12D3KooWRELAY'] });
    const h = makeDeps({ node: fake.node });
    h.setMembers([member]);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();

    assert.equal(fake.dialed[0], '/ip4/192.168.1.9/tcp/24001');
    assert.ok(
      fake.dialTypes.every((t) => t === 'multiaddr'),
      `libp2p dial() requires a parsed Multiaddr, got shapes: ${JSON.stringify(fake.dialTypes)}`,
    );
  });

  it('names the real reason a member could not be reached', async () => {
    // The bare `catch {}` in the candidate loop reported only
    // "all 1 address(es) failed", discarding the one detail that identified the
    // bug above.
    const fake = makeNode({
      reservedPeers: ['12D3KooWRELAY'],
      dialImpl: async () => {
        throw new TypeError('multiaddrs[0].getComponents is not a function');
      },
    });
    const h = makeDeps({ node: fake.node });
    h.setMembers([{ peerId: '12D3KooWAGENT', multiaddrs: ['/ip4/192.168.1.9/tcp/24001'] }]);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();

    assert.ok(
      h.events.some((e) => /all \d+ address\(es\) failed: .*getComponents/.test(e)),
      `expected the failure reason in the log, got: ${JSON.stringify(h.events)}`,
    );
  });
});


describe('ConnectivitySupervisor: backoff + resilience', () => {
  const member: MemberEndpoint = {
    peerId: '12D3KooWAGENT',
    multiaddrs: ['/ip4/192.168.1.9/tcp/24001'],
  };

  it('backs off a member after a failed attempt instead of retrying every tick', async () => {
    const fake = makeNode({ reservedPeers: ['12D3KooWRELAY'] }); // every dial throws
    const h = makeDeps({ node: fake.node, memberBackoffMinMs: 60_000 });
    h.setMembers([member]);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();
    const afterFirst = fake.dialed.length;
    await sup.runTick(); // inside the backoff window — must not dial again

    assert.ok(afterFirst > 0);
    assert.equal(fake.dialed.length, afterFirst);
    assert.equal(sup.getStatus().membersInBackoff, 1);
  });

  it('counts "no dialable addresses" as a failed attempt', async () => {
    const fake = makeNode({ reservedPeers: ['12D3KooWRELAY'] });
    const h = makeDeps({ node: fake.node, getRelayAddr: () => undefined });
    h.setMembers([{ peerId: '12D3KooWAGENT', multiaddrs: [] }]);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();
    assert.deepEqual(fake.dialed, []);
    assert.equal(sup.getStatus().membersInBackoff, 1);
  });

  it('survives a member-endpoint query failure', async () => {
    const h = makeDeps({
      listMemberEndpoints: async () => {
        throw new Error('db down');
      },
    });
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick(); // must not throw
    assert.ok(h.events.some((e) => /could not list member endpoints/.test(e)));
  });

  it('survives a throwing status sink', async () => {
    const h = makeDeps({
      onStatus: () => {
        throw new Error('sink exploded');
      },
    });
    h.setBootstrapConnected(false);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick(); // must not throw
    assert.equal(h.getRegisterCalls(), 1);
  });
});

// ---------------------------------------------------------------------------
// Stale-member ageing (last_seen_at)
// ---------------------------------------------------------------------------

describe('ConnectivitySupervisor: stale-member ageing', () => {
  const member: MemberEndpoint = {
    peerId: '12D3KooWAGENT',
    multiaddrs: ['/ip4/192.168.1.9/tcp/24001'],
    label: 'alice',
  };

  it('does not dial a member whose last_seen_at has aged out (clean logout / crash)', async () => {
    const fake = makeNode({ reservedPeers: ['12D3KooWRELAY'], dialImpl: async () => ({ status: 'open' }) });
    const h = makeDeps({ node: fake.node });
    const staleSeconds = Math.floor(Date.now() / 1000) - 2 * 60 * 60;
    h.setMembers([{ ...member, lastSeenAt: staleSeconds }]);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();

    assert.deepEqual(fake.dialed, [], 'an aged-out member must not be dialled');
  });

  it('still dials a member with a recent last_seen_at', async () => {
    const fake = makeNode({ reservedPeers: ['12D3KooWRELAY'], dialImpl: async () => ({ status: 'open' }) });
    const h = makeDeps({ node: fake.node });
    const freshSeconds = Math.floor(Date.now() / 1000) - 60;
    h.setMembers([{ ...member, lastSeenAt: freshSeconds }]);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();

    assert.deepEqual(fake.dialed, ['/ip4/192.168.1.9/tcp/24001']);
  });

  it('treats a missing last_seen_at as "seen now" (legacy row)', async () => {
    const fake = makeNode({ reservedPeers: ['12D3KooWRELAY'], dialImpl: async () => ({ status: 'open' }) });
    const h = makeDeps({ node: fake.node });
    h.setMembers([member]); // no lastSeenAt
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();

    assert.deepEqual(fake.dialed, ['/ip4/192.168.1.9/tcp/24001']);
  });
});

// ---------------------------------------------------------------------------
// Lifecycle + helpers
// ---------------------------------------------------------------------------

describe('ConnectivitySupervisor: lifecycle', () => {
  it('start() is idempotent and stop() halts ticks', async () => {
    const h = makeDeps();
    const sup = new ConnectivitySupervisor(h.deps);

    sup.start();
    sup.start(); // second call must not create a second interval
    assert.equal(sup.getStatus().running, true);

    sup.stop();
    assert.equal(sup.getStatus().running, false);

    // A tick after stop() is a no-op.
    h.setBootstrapConnected(false);
    await sup.runTick();
    assert.equal(h.getRegisterCalls(), 0);
  });
});

describe('ConnectivitySupervisor: operator status (H14)', () => {
  it('reports WHICH member is stuck, why, and when the next attempt is', async () => {
    const fake = makeNode({ reservedPeers: ['12D3KooWRELAY'] });
    // Default relay (advertised, and reserved on) — so this test also proves the
    // reservation is actually COMPUTED, not just reported as unknown. A 5s member
    // backoff (the shared default is 0 for deterministic tests) makes `inBackoff`
    // observable rather than instantaneously false.
    const h = makeDeps({ node: fake.node, memberBackoffMinMs: 5_000 });
    h.setMembers([
      { peerId: '12D3KooWSTUCK', multiaddrs: [], label: 'stuck-agent' },
      { peerId: '12D3KooWUP', multiaddrs: [], label: 'happy-agent' },
    ]);
    fake.markConnected('12D3KooWUP');
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();
    const status = sup.getStatus();

    // Bootstrap registration state (consecutive failures / next attempt) is
    // reported separately from the connection flag.
    assert.equal(typeof status.bootstrap.consecutiveFailures, 'number');
    assert.equal(typeof status.bootstrap.nextAttemptInMs, 'number');

    // Relay: whether the reservation is HELD is the question whose absence caused
    // the outage class, and it is now answerable from the status rather than logs.
    // (It must be COMPUTED — passing no relay peer id to readRelayHealth() reports
    // `false` unconditionally, which is a lie of omission this test catches.)
    assert.equal(status.relay.reservationHeld, true);
    assert.equal(
      status.relay.advertisedAddr,
      '/dns/relay.test/tcp/4001/p2p/12D3KooWRELAY/p2p-circuit',
      'the advertised relay address must be reported',
    );

    // Per-member detail — the reason the aggregate count was insufficient.
    const byLabel = new Map(status.members.map((m) => [m.label, m]));
    const stuck = byLabel.get('stuck-agent');
    assert.ok(stuck, 'the unreachable member must be listed');
    assert.equal(stuck!.inBackoff, true);
    assert.ok(stuck!.nextAttemptInMs >= 0);
    assert.equal(stuck!.consecutiveFailures, 1);
    assert.equal(stuck!.lastResult?.ok, false);
    // The verbatim failure reason, not a generic "failed" — this is what makes the
    // status surface diagnosable. (The relayed dial was attempted and refused.)
    assert.match(stuck!.lastResult!.detail, /1 address\(es\) failed/);

    const happy = byLabel.get('happy-agent');
    assert.ok(happy, 'the connected member must be listed too');
    assert.equal(happy!.inBackoff, false);
    assert.equal(happy!.lastResult?.ok, true);
    assert.equal(happy!.lastResult?.detail, 'connected');

    // The old aggregate count is preserved for existing consumers.
    assert.equal(status.membersInBackoff, 1);
  });

  it('names a successful dial in the per-member result', async () => {
    const fake = makeNode({
      reservedPeers: ['12D3KooWRELAY'],
      dialImpl: async () => ({ ok: true }),
    });
    const h = makeDeps({ node: fake.node });
    h.setMembers([{ peerId: '12D3KooWAGENT', multiaddrs: ['/ip4/127.0.0.1/tcp/1'], label: 'agent-a' }]);
    const sup = new ConnectivitySupervisor(h.deps);

    await sup.runTick();
    const member = sup.getStatus().members.find((m) => m.label === 'agent-a');
    assert.equal(member?.lastResult?.ok, true);
    assert.equal(member?.lastResult?.detail, 'dialled direct');
    assert.equal(member?.inBackoff, false);
  });
});

describe('extractPeerId', () => {
  it('reads the last /p2p/ component', () => {
    assert.equal(
      extractPeerId('/dns/relay.test/tcp/4001/p2p/12D3KooWRELAY/p2p-circuit'),
      '12D3KooWRELAY',
    );
    assert.equal(extractPeerId('/ip4/1.2.3.4/tcp/4001/p2p/12D3KooWX'), '12D3KooWX');
  });

  it('returns undefined when there is no peer ID', () => {
    assert.equal(extractPeerId('/ip4/1.2.3.4/tcp/4001'), undefined);
  });
});

describe('isDialablePeerId', () => {
  it('accepts real libp2p peer ID shapes', () => {
    assert.equal(isDialablePeerId('12D3KooWDWknVaqQesqsHf24nEeHjCe2wWNhMVxwmPHyNArKBegp'), true);
    assert.equal(isDialablePeerId('12D3KooWEhn9pF83fwGCazsoqjM13KRsZLadicXFgLxLui4m4Trn'), true);
    assert.equal(isDialablePeerId('QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG'), true);
  });

  it('rejects the setup-flow placeholder and other non-base58 strings', () => {
    assert.equal(isDialablePeerId('bootstrap-6105b830373d15a11db1ef8a3594c441'), false);
    assert.equal(isDialablePeerId(''), false);
    // base58btc excludes 0, O, I and l — any of them proves it is not a peer ID.
    assert.equal(isDialablePeerId('agent-0Ol'), false);
    assert.equal(isDialablePeerId('12D3KooW AGENT'), false);
  });
});

