/**
 * ConnectivitySupervisor — utility-server-side owner of network recovery.
 *
 * WHY THIS EXISTS
 * ---------------
 * The utility server is a PASSIVE listener: agents dial it. Nothing on this
 * side ever re-dialled an agent, and bootstrap registration was a one-shot at
 * boot. That is fine until connectivity is lost — and a circuit-relay session
 * expiring is exactly such a loss:
 *
 *   1. The relay enforces a per-relayed-connection duration/byte grant
 *      (`relayMaxDuration` / `relayMaxData`, bootstrap/server/bootstrap-server.ts).
 *      When it runs out, the relay aborts the HOP/STOP streams and BOTH ends
 *      see `peer:disconnect`.
 *   2. This server reacted by marking the member unreachable and PAUSING that
 *      member's delivery queue (`AgentDeliveryQueue.markPeerDisconnected`).
 *   3. The only thing that could resume it was an inbound `peer:connect` from
 *      the agent — which never came if the agent's own recovery did not fire.
 *      The member's queue then stalled indefinitely.
 *   4. Worse, this server held NO circuit-relay reservation (it never listened
 *      on `/p2p-circuit`), so an agent behind NAT could not dial it through the
 *      relay at all — the relay answered NO_RESERVATION for every HOP aimed
 *      here. Any relay-based recovery was impossible by construction.
 *
 * This supervisor fixes all of it:
 *   - retries bootstrap registration with backoff until it succeeds (a
 *     bootstrap outage at boot is no longer permanent)
 *   - re-applies the circuit-relay reservation when it is lost, so agents can
 *     reach this server via relay
 *   - re-dials every known member whose transport connection is down and
 *     resumes that member's delivery queue, instead of waiting for an inbound
 *     connect that may never arrive
 *
 * Dependencies are injected as plain functions so the policy is testable
 * without booting libp2p.
 */

import type { Libp2p } from 'libp2p';
import { peerIdFromString } from '@libp2p/peer-id';
import { multiaddr } from '@multiformats/multiaddr';
import {
  hasRelayReservation as nodeHasRelayReservation,
  readRelayHealth,
  relayHealthLabel,
} from '@p2p-trust-stack/core/transport/relay-health.js';

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/** Supervisor tick cadence. */
const DEFAULT_TICK_MS = 15_000;

/** Per-address dial timeout. */
const DIAL_TIMEOUT_MS = 10_000;

/** Backoff bounds for re-dialling an individual member. */
const MEMBER_BACKOFF_MIN_MS = 5_000;
const MEMBER_BACKOFF_MAX_MS = 120_000;

/**
 * How long (ms) a member may go without an observed connection before it is
 * treated as "stale" (clean logout or crash) and skipped rather than dialled
 * forever. The recency signal is peer_endpoints.last_seen_at, touched on
 * `peer:connect` and on every live-endpoint write. An idle-but-online agent
 * stays connected (fresh last_seen_at); a transient drop is still inside this
 * window; a long-gone agent ages out.
 */
const MEMBER_STALE_AFTER_MS = 15 * 60_000;

/**
 * Max peer-store addresses considered per member, per tick.
 *
 * Each candidate is dialled with its own DIAL_TIMEOUT_MS, so an address book
 * holding many dead entries must not stretch a tick (or the 15s cadence) out.
 */
const MAX_PEERSTORE_CANDIDATES = 4;

/** Bootstrap registration backoff bounds (registration is the co-ordination plane). */
const REGISTER_BACKOFF_MIN_MS = 5_000;
const REGISTER_BACKOFF_MAX_MS = 60_000;

/**
 * Backoff bounds for the circuit-relay reservation attempt.
 *
 * WHY A BACKOFF AT ALL: `ensureRelayReservation()` ends in
 * `transportManager.listen('<relay>/p2p-circuit')`, and `TransportManager.listen()`
 * has NO address-level dedupe — every call creates a fresh listener object. A
 * reservation that cannot be confirmed (the relay has not advertised the hop
 * codec, or a failed attempt has blacklisted the relay for this process) was
 * therefore re-attempted on EVERY 15 s tick, leaking a listener each time and
 * printing the same un-actionable line forever. The first attempt is still made
 * immediately; only the retries are spaced out.
 */
const RELAY_BACKOFF_MIN_MS = 30_000;
const RELAY_BACKOFF_MAX_MS = 240_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A member endpoint worth (re-)dialling. */
export interface MemberEndpoint {
  /** The agent's libp2p peer ID. */
  peerId: string;
  /** Known multiaddrs for that peer (direct and/or relay). */
  multiaddrs: string[];
  /** Optional human label for logs (agent name / member uuid prefix). */
  label?: string;
  /** Epoch-seconds of last observed connectivity (peer_endpoints.last_seen_at). */
  lastSeenAt?: number | null;
}

/** The last outcome this supervisor observed for one member. */
export interface MemberLastResult {
  /** True when the member is reachable (connected, or just dialled successfully). */
  ok: boolean;
  /** Epoch ms of the observation. */
  at: number;
  /** Why — 'connected', 'dialled direct', 'dialled via relay', or a failure reason. */
  detail: string;
}

/** One member's connectivity state, as reported to an operator. */
export interface MemberStatus {
  peerId: string;
  label: string;
  /** True while this member is being skipped until `nextAttemptInMs` elapses. */
  inBackoff: boolean;
  /** Milliseconds until the next dial attempt (0 = due now). */
  nextAttemptInMs: number;
  consecutiveFailures: number;
  /** Last observed outcome, or `null` if this member has not been acted on yet. */
  lastResult: MemberLastResult | null;
}

/**
 * Operator-facing connectivity snapshot.
 *
 * Deliberately covers what an operator needs during an outage that the previous
 * four-field summary could not answer: WHICH member is stuck, why, and when the
 * next attempt is; whether the relay reservation (the thing whose absence caused
 * the outage class) is actually held; and whether bootstrap registration is
 * failing, with its next attempt.
 */
export interface SupervisorStatus {
  running: boolean;
  bootstrapConnected: boolean;
  relayLabel: string;
  /** Aggregate count retained for the existing summary consumers. */
  membersInBackoff: number;
  /** Bootstrap REGISTRATION state (distinct from the connection state above). */
  bootstrap: {
    /** Consecutive failed registrations. */
    consecutiveFailures: number;
    /** Milliseconds until the next registration attempt (0 = due now). */
    nextAttemptInMs: number;
  };
  relay: {
    /** A relayed inbound HOP can only arrive when we HOLD a reservation. */
    reservationHeld: boolean;
    /** The relay prefix we advertise for inbound, or null when none is set. */
    advertisedAddr: string | null;
    /** Consecutive failed reservation attempts (0 = held, or never attempted). */
    consecutiveFailures: number;
    /** Milliseconds until the next reservation attempt (0 = due now). */
    nextAttemptInMs: number;
  };
  /**
   * Members this supervisor has OBSERVED (from its own tick's endpoint list).
   * A member that has never appeared in that list is absent by definition.
   */
  members: MemberStatus[];
}

/** Injected behaviour — see the module header for why each is needed. */
export interface ConnectivitySupervisorDeps {
  node: Libp2p;
  /**
   * Register (or re-register) with the bootstrap server. MUST be idempotent —
   * it is called repeatedly until it stops throwing.
   */
  register: () => Promise<void>;
  /**
   * Apply the circuit-relay reservation (`listen('<relay>/p2p-circuit')`).
   * Idempotent; safe to call on every tick.
   */
  ensureRelayReservation: () => Promise<void>;
  /** Bootstrap reachability, per the bootstrap client's own state machine. */
  isBootstrapConnected: () => boolean;
  /** Member endpoints to consider re-dialling. */
  listMemberEndpoints: () => Promise<MemberEndpoint[]>;
  /**
   * The relay's dialable address prefix, ending in `/p2p-circuit` (e.g.
   * `/dns/host/tcp/4001/p2p/<relayPeerId>/p2p-circuit`). Used to build the
   * relayed dial address for members that cannot be reached directly.
   */
  getRelayAddr: () => string | undefined;
  /**
   * Called after a member's transport connection is re-established — this is
   * where the delivery queue is flushed so queued records go out immediately
   * rather than waiting for a blind backoff timer.
   */
  onMemberReconnected?: (peerId: string) => void | Promise<void>;
  /** Status sink for the operator (TUI / HTTP status / console). */
  onStatus?: (message: string, level: 'info' | 'warn' | 'error') => void;
  /** Override the tick cadence (tests). */
  tickMs?: number;
  /**
   * Override the first bootstrap-registration backoff (tests / fast dev retry).
   * Still doubles up to REGISTER_BACKOFF_MAX_MS.
   */
  registerBackoffMinMs?: number;
  /** Override the first per-member re-dial backoff (tests). */
  memberBackoffMinMs?: number;
  /** Override the first relay-reservation backoff (tests). */
  relayBackoffMinMs?: number;
}

// ---------------------------------------------------------------------------
// ConnectivitySupervisor
// ---------------------------------------------------------------------------

export class ConnectivitySupervisor {
  private readonly deps: ConnectivitySupervisorDeps;
  private timer?: ReturnType<typeof setInterval>;
  private tickInFlight = false;
  private stopped = false;

  /** Consecutive failed bootstrap registrations (for capped backoff). */
  private registerFailures = 0;
  /** Earliest next registration attempt. */
  private nextRegisterAt = 0;

  /** Per-member re-dial backoff: peerId -> earliest next attempt. */
  private readonly memberNextAttempt = new Map<string, number>();
  private readonly memberFailures = new Map<string, number>();
  /**
   * Last observed outcome per member, for the operator status surface.
   *
   * Tracked because the log line is the only other record, and "which member is
   * stuck, and why" is precisely what an operator needs during an outage — the
   * pre-existing `membersInBackoff` COUNT could not answer it.
   */
  private readonly memberLastResult = new Map<string, MemberLastResult>();
  /** Human labels seen for members (from the endpoint list), for status output. */
  private readonly memberLabels = new Map<string, string>();

  /** Consecutive failed circuit-relay reservation attempts (for capped backoff). */
  private relayFailures = 0;
  /** Earliest next reservation attempt. */
  private relayNextAttemptAt = 0;
  /** Whether the current reservation-failure streak has already been warned about. */
  private relayWarnedThisStreak = false;

  constructor(deps: ConnectivitySupervisorDeps) {
    this.deps = deps;
  }

  /** Start the periodic tick. */
  start(): void {
    if (this.timer) return;
    this.stopped = false;
    this.timer = setInterval(() => {
      void this.runTick();
    }, this.deps.tickMs ?? DEFAULT_TICK_MS);
    if (typeof this.timer.unref === 'function') {
      this.timer.unref();
    }
    this.emit('connectivity supervisor started', 'info');
  }

  /** Stop the periodic tick. Safe to call repeatedly. */
  stop(): void {
    this.stopped = true;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  /**
   * Run one supervisor pass. Public so tests (and an operator action) can drive
   * it deterministically instead of waiting for a timer.
   *
   * ORDER: bootstrap registration first (it is the co-ordination plane — without
   * it no member address can be refreshed), then the relay reservation (without
   * it no agent behind NAT can reach us at all), then member re-dials.
   *
   * Each stage is independently guarded: one failing must not skip the others.
   */
  async runTick(): Promise<void> {
    if (this.tickInFlight || this.stopped) return;
    this.tickInFlight = true;
    try {
      await this.stageBootstrapRegistration();
      await this.stageRelayReservation();
      await this.stageMemberReconnects();
    } catch (err) {
      // Belt-and-braces: stages swallow their own errors, so reaching here means
      // something unexpected (a bug or a shutdown race). Never rethrow — the
      // next tick retries.
      this.emit(`supervisor tick failed: ${(err as Error)?.message ?? err}`, 'error');
    } finally {
      this.tickInFlight = false;
    }
  }

  /** Live snapshot for status surfaces. */
  getStatus(): SupervisorStatus {
    const relayAddr = this.deps.getRelayAddr() ?? null;
    // The relay peer id MUST be passed: `readRelayHealth(node)` without it reports
    // `hasReservation: false` unconditionally, because a reservation is per-relay.
    // Omitting it (as this call did) made the status structurally blind to the very
    // condition — "do we hold a reservation?" — whose absence caused the outage
    // class this supervisor exists for.
    const relayPeerId = relayAddr ? extractPeerId(relayAddr) : undefined;
    const health = readRelayHealth(this.deps.node, relayPeerId);
    const now = Date.now();
    return {
      running: !!this.timer,
      bootstrapConnected: this.deps.isBootstrapConnected(),
      relayLabel: relayHealthLabel(health),
      membersInBackoff: this.memberNextAttempt.size,
      bootstrap: {
        consecutiveFailures: this.registerFailures,
        nextAttemptInMs: Math.max(0, this.nextRegisterAt - now),
      },
      relay: {
        reservationHeld: health.hasReservation,
        advertisedAddr: relayAddr,
        consecutiveFailures: this.relayFailures,
        nextAttemptInMs: Math.max(0, this.relayNextAttemptAt - now),
      },
      members: this.memberStatuses(now),
    };
  }

  /**
   * Per-member status rows, keyed by every peerId this supervisor has observed.
   *
   * Derived from the in-memory tracking maps rather than the endpoint list, so the
   * snapshot stays SYNCHRONOUS (safe from a route without touching the database)
   * and still answers the outage question — which member, why, and when is the
   * next attempt.
   */
  private memberStatuses(now: number): MemberStatus[] {
    const peerIds = new Set<string>([
      ...this.memberLastResult.keys(),
      ...this.memberNextAttempt.keys(),
      ...this.memberFailures.keys(),
    ]);

    return [...peerIds].map((peerId) => {
      const nextAttemptAt = this.memberNextAttempt.get(peerId) ?? 0;
      return {
        peerId,
        label: this.memberLabels.get(peerId) ?? peerId.slice(0, 12),
        inBackoff: now < nextAttemptAt,
        nextAttemptInMs: Math.max(0, nextAttemptAt - now),
        consecutiveFailures: this.memberFailures.get(peerId) ?? 0,
        lastResult: this.memberLastResult.get(peerId) ?? null,
      };
    }).sort((a, b) => a.label.localeCompare(b.label));
  }

  // -------------------------------------------------------------------------
  // Stage 1 — bootstrap registration
  // -------------------------------------------------------------------------

  /**
   * Register with the bootstrap server, retrying with capped exponential
   * backoff until it succeeds.
   *
   * A bootstrap outage that starts BEFORE this server boots used to be
   * permanent: registration ran once inside a try/catch, the failure was logged
   * as "continuing in LAN-only mode", and nothing ever retried — so the server
   * never appeared in discovery and never obtained a relay reservation.
   */
  private async stageBootstrapRegistration(): Promise<void> {
    if (this.deps.isBootstrapConnected()) {
      this.registerFailures = 0;
      this.nextRegisterAt = 0;
      return;
    }

    const now = Date.now();
    if (now < this.nextRegisterAt) return; // still backing off

    try {
      await this.deps.register();
      this.registerFailures = 0;
      this.nextRegisterAt = 0;
      this.emit('bootstrap registration (re)established', 'info');
    } catch (err) {
      this.registerFailures++;
      const delay = Math.min(
        (this.deps.registerBackoffMinMs ?? REGISTER_BACKOFF_MIN_MS) *
          Math.pow(2, this.registerFailures - 1),
        REGISTER_BACKOFF_MAX_MS,
      );
      this.nextRegisterAt = now + delay;
      this.emit(
        `bootstrap registration failed (attempt ${this.registerFailures}) — retrying in ${Math.round(delay / 1000)}s: ` +
          `${(err as Error)?.message ?? err}`,
        'warn',
      );
    }
  }

  // -------------------------------------------------------------------------
  // Stage 2 — circuit-relay reservation
  // -------------------------------------------------------------------------

  /**
   * Re-assert the circuit-relay reservation when it is missing.
   *
   * Without a reservation the relay rejects every inbound HOP CONNECT aimed at
   * this server with NO_RESERVATION, so agents behind NAT cannot reach it at
   * all. The reservation is DELETED by @libp2p/circuit-relay-v2 whenever the
   * connection to the relay closes, and the library does not re-listen on its
   * own — so this has to be owned explicitly.
   */
  private async stageRelayReservation(): Promise<void> {
    const relayAddr = this.deps.getRelayAddr();
    if (!relayAddr) return; // relay not advertised / not enabled
    if (!this.deps.isBootstrapConnected()) return; // need the relay connection first

    // Resolve the relay's peer ID the same way the agent-side client does.
    const relayPeerId = extractPeerId(relayAddr);
    if (!relayPeerId) return;

    if (nodeHasRelayReservation(this.deps.node, relayPeerId)) {
      // Held — clear any failure streak so a later loss is retried immediately.
      this.relayFailures = 0;
      this.relayNextAttemptAt = 0;
      this.relayWarnedThisStreak = false;
      return;
    }

    const now = Date.now();
    if (now < this.relayNextAttemptAt) return; // still backing off this attempt

    try {
      await this.deps.ensureRelayReservation();

      if (nodeHasRelayReservation(this.deps.node, relayPeerId)) {
        this.relayFailures = 0;
        this.relayNextAttemptAt = 0;
        this.relayWarnedThisStreak = false;
        this.emit(
          'relay reservation (re)established — agents can now reach this server via relay',
          'info',
        );
        return;
      }

      // `ensureRelayReservation()` resolved but the reservation is still absent.
      // That is NOT a no-op: the bootstrap client DEFERS the attempt when the
      // relay has not (yet) advertised the circuit-relay hop codec, and a
      // failed attempt can leave @libp2p/circuit-relay-v2 with the relay
      // blacklisted for the whole process. Either way the caller learns
      // nothing, so record the failure and back off.
      this.backoffRelay(now);
    } catch (err) {
      this.backoffRelay(now, (err as Error)?.message ?? String(err));
    }
  }

  /**
   * Record a failed reservation attempt, space the next one out, and report it.
   *
   * The first failure of a streak is a WARNING that names the reason (or, when
   * `ensureRelayReservation()` swallowed it, says so explicitly) — an operator
   * needs to know that agents on another network cannot reach this server. The
   * remaining failures are INFO, because repeating a warning every tick is how
   * the previous single `info` line became background noise nobody read.
   */
  private backoffRelay(now: number, reason?: string): void {
    this.relayFailures++;
    const delay = Math.min(
      (this.deps.relayBackoffMinMs ?? RELAY_BACKOFF_MIN_MS) * Math.pow(2, this.relayFailures - 1),
      RELAY_BACKOFF_MAX_MS,
    );
    this.relayNextAttemptAt = now + delay;

    const detail = reason ? ` (${reason})` : ' (reason not reported by the bootstrap client)';
    if (!this.relayWarnedThisStreak) {
      this.relayWarnedThisStreak = true;
      this.emit(
        `relay reservation requested but not yet confirmed${detail} — agents on another network ` +
          `cannot reach this server via relay until it succeeds. Retrying in ${Math.round(delay / 1000)}s.`,
        'warn',
      );
      return;
    }
    this.emit(
      `relay reservation still unconfirmed after ${this.relayFailures} attempt(s)${detail} — ` +
        `next attempt in ${Math.round(delay / 1000)}s.`,
      'info',
    );
  }


  // -------------------------------------------------------------------------
  // Stage 3 — member reconnects
  // -------------------------------------------------------------------------

  /**
   * Re-dial members whose transport connection is down.
   *
   * This is the fix for the stalled-delivery symptom: the server used to pause
   * a member's queue on `peer:disconnect` and resume it ONLY on an inbound
   * `peer:connect`. If the agent's own recovery did not fire (or the agent was
   * unreachable inbound), that member's queued records never went out. Dialling
   * from this side removes the dependency on the agent's behaviour.
   */
  private async stageMemberReconnects(): Promise<void> {
    // Deliberately NOT gated on bootstrap reachability: cached member addresses
    // are often still usable, and a stale address beats no attempt at all.
    if (this.stopped) return;

    const endpoints = await this.deps.listMemberEndpoints().catch((err) => {
      this.emit(`could not list member endpoints: ${(err as Error)?.message ?? err}`, 'warn');
      return [] as MemberEndpoint[];
    });

    const now = Date.now();
    for (const endpoint of endpoints) {
      if (this.stopped) return;
      if (!endpoint.peerId || endpoint.peerId === this.selfPeerId()) continue;
      // A peer ID that is not a libp2p peer ID can never be dialled — skip it
      // BEFORE any bookkeeping, so it never enters the backoff maps, the status
      // surface, or the logs. See isDialablePeerId() for the case that made this
      // necessary (the `bootstrap-<hex>` endpoint placeholder written by the VTC
      // setup flow, which produced one permanent
      // "reconnect to agent bootstrap-61... failed" warning every 120s).
      if (!isDialablePeerId(endpoint.peerId)) continue;
      if (endpoint.label) this.memberLabels.set(endpoint.peerId, endpoint.label);

      if (this.isStale(endpoint.lastSeenAt, now)) {
        // Clean logout or crash (no observation for > MEMBER_STALE_AFTER_MS).
        // Stop re-dialling until an inbound peer:connect refreshes last_seen_at.
        this.memberNextAttempt.delete(endpoint.peerId);
        this.memberFailures.delete(endpoint.peerId);
        this.memberLastResult.set(endpoint.peerId, { ok: false, at: now, detail: 'stale (not seen recently)' });
        continue;
      }

      if (this.isPeerConnected(endpoint.peerId)) {
        // Connected — clear backoff so a later drop is retried promptly.
        this.memberNextAttempt.delete(endpoint.peerId);
        this.memberFailures.delete(endpoint.peerId);
        this.memberLastResult.set(endpoint.peerId, { ok: true, at: now, detail: 'connected' });
        continue;
      }

      const nextAttempt = this.memberNextAttempt.get(endpoint.peerId) ?? 0;
      if (now < nextAttempt) continue; // backing off this member

      await this.dialMember(endpoint);
    }
  }

  /** The local peer ID, so we never attempt to dial ourselves. */
  private selfPeerId(): string {
    try {
      return (this.deps.node as { peerId?: { toString(): string } }).peerId?.toString() ?? '';
    } catch {
      return '';
    }
  }

  /**
   * Whether a member has aged out: its `last_seen_at` (epoch-seconds) is older
   * than {@link MEMBER_STALE_AFTER_MS}. `null`/`undefined` (e.g. a legacy row
   * written before this column existed) is treated as "seen now" so we never
   * skip a member we cannot date.
   */
  private isStale(lastSeenAt: number | null | undefined, now: number): boolean {
    if (lastSeenAt == null) return false;
    return now - lastSeenAt * 1000 > MEMBER_STALE_AFTER_MS;
  }

  /** Is the local node currently connected to `peerId`? */
  private isPeerConnected(peerId: string): boolean {
    try {
      const connections =
        (this.deps.node as { getConnections?: (p: unknown) => unknown[] }).getConnections?.(
          peerId,
        ) ?? [];
      return connections.some((c) => {
        const status = (c as { status?: string }).status;
        return status === 'open' || status === 'closing';
      });
    } catch {
      return false;
    }
  }


  /**
   * Try to (re-)connect to one member: direct addresses first, then through the
   * bootstrap server's circuit relay.
   *
   * Each address is attempted individually so one stale address cannot fail the
   * whole attempt — after an agent's relay session expires its cached DIRECT
   * addresses are often still valid while the relayed path is dead, and after a
   * NAT/IP change the reverse holds.
   */
  private async dialMember(endpoint: MemberEndpoint): Promise<void> {
    const label = endpoint.label ?? endpoint.peerId.slice(0, 12);
    const dialer = this.deps.node as unknown as {
      dial?: (addr: string | unknown, opts?: unknown) => Promise<unknown>;
    };

    const direct = endpoint.multiaddrs.filter((a) => !a.includes('/p2p-circuit'));
    const relayed = this.buildRelayAddr(endpoint.peerId);
    // Addresses libp2p ITSELF already knows for this member are an ADDITIONAL
    // candidate source. `peer_endpoints.multiaddrs` comes from the agent's
    // identity_push and can be absent (a push from an older agent, or a row
    // written before the addresses were carried) or stale (re-bound port, new
    // network), while the peer store is what this node has actually observed.
    // Without it such a member had exactly ONE candidate — the relay — and every
    // tick failed as `reconnect to agent … failed (all 1 address(es) failed)`
    // even though a direct path was known.
    const known = await this.knownAddrsFor(endpoint.peerId);
    const candidates = [...new Set([...direct, ...known, ...(relayed ? [relayed] : [])])];

    if (candidates.length === 0) {
      this.backoffMember(endpoint.peerId, 'no dialable addresses');
      return;
    }

    // The LAST candidate failure, so the operator sees WHY rather than only
    // "all N address(es) failed". The bare `catch {}` this replaces discarded
    // the one piece of information that would have identified the bug below.
    let lastError: unknown;

    for (const addr of candidates) {
      if (this.stopped) return;
      try {
        // MUST be a Multiaddr object, NOT the string. libp2p's dial() runs the
        // target through `getPeerAddress()`, which does
        // `multiaddrs[0].getComponents()` — a plain string has no
        // `getComponents`, so it threw
        // `TypeError: multiaddrs[0].getComponents is not a function` BEFORE any
        // connection was attempted. Every candidate failed that way, so every
        // member was reported unreachable forever
        // (`reconnect to agent … failed (all N address(es) failed)`), and the
        // server never re-dialled an agent it had lost.
        await dialer.dial?.(multiaddr(addr), { signal: AbortSignal.timeout(DIAL_TIMEOUT_MS) });

        // Connected. Clear backoff and let the caller resume delivery.
        this.memberNextAttempt.delete(endpoint.peerId);
        this.memberFailures.delete(endpoint.peerId);
        this.memberLastResult.set(endpoint.peerId, {
          ok: true,
          at: Date.now(),
          detail: addr.includes('/p2p-circuit') ? 'dialled via relay' : 'dialled direct',
        });
        this.emit(
          `reconnected to agent ${label} (${addr.includes('/p2p-circuit') ? 'via relay' : 'direct'})`,
          'info',
        );

        try {
          await this.deps.onMemberReconnected?.(endpoint.peerId);
        } catch (err) {
          this.emit(
            `post-reconnect hook failed for ${label}: ${(err as Error)?.message ?? err}`,
            'warn',
          );
        }
        return;
      } catch (err) {
        // Try the next candidate address, remembering why this one failed.
        lastError = err;
      }
    }

    const reason = lastError
      ? `all ${candidates.length} address(es) failed: ${(lastError as Error)?.message ?? lastError}`
      : `all ${candidates.length} address(es) failed`;
    this.backoffMember(endpoint.peerId, reason);
  }

  /**
   * Addresses the local node's peer store holds for `peerId`; `[]` when there is
   * no peer store, the peer is unknown, or the id cannot be parsed.
   *
   * Capped because each candidate is dialled with its own DIAL_TIMEOUT_MS, so an
   * address book full of dead entries must not stretch a tick indefinitely.
   */
  private async knownAddrsFor(peerId: string): Promise<string[]> {
    try {
      const store = (
        this.deps.node as unknown as {
          peerStore?: {
            get?: (p: unknown) => Promise<
              { addresses?: Array<{ multiaddr?: { toString(): string } }> } | undefined
            >;
          };
        }
      ).peerStore;
      if (!store?.get) return [];
      const entry = await store.get(peerIdFromString(peerId));
      const addrs = (entry?.addresses ?? [])
        .map((a) => a.multiaddr?.toString())
        .filter((a): a is string => typeof a === 'string' && a.length > 0);
      return addrs.slice(0, MAX_PEERSTORE_CANDIDATES);
    } catch {
      // Not a parseable peer ID, or no peer store on this node — no extra hints.
      return [];
    }
  }

  /**
   * Build the dial address for a member through the bootstrap server's relay.
   *
   * Shape: `<relay-multiaddr-ending-in-/p2p-circuit>/p2p/{memberPeerId}`.
   * `getRelayAddr()` is contractually `<relay>/p2p-circuit` (e.g.
   * `/dns/host/tcp/4001/p2p/<relayPeerId>/p2p-circuit`), so the member's peer ID
   * is appended directly — the same shape the agent-side connectivity module
   * builds. The fallback branch handles a legacy/malformed address that ends in
   * a peer ID instead of `/p2p-circuit`.
   */
  private buildRelayAddr(memberPeerId: string): string | undefined {
    const relayAddr = this.deps.getRelayAddr();
    if (!relayAddr) return undefined;
    if (relayAddr.endsWith('/p2p-circuit')) {
      return `${relayAddr}/p2p/${memberPeerId}`;
    }
    return `${relayAddr.replace(/\/p2p\/[^/]+$/, '')}/p2p-circuit/p2p/${memberPeerId}`;
  }

  /** Record a failed attempt and set the next allowed attempt time. */
  private backoffMember(peerId: string, reason: string): void {
    const failures = (this.memberFailures.get(peerId) ?? 0) + 1;
    this.memberFailures.set(peerId, failures);
    const delay = Math.min(
      (this.deps.memberBackoffMinMs ?? MEMBER_BACKOFF_MIN_MS) * Math.pow(2, failures - 1),
      MEMBER_BACKOFF_MAX_MS,
    );
    this.memberNextAttempt.set(peerId, Date.now() + delay);
    // Record WHY, so the operator status surface can name the stall instead of
    // reporting an anonymous backoff count.
    this.memberLastResult.set(peerId, { ok: false, at: Date.now(), detail: reason });
    this.emit(
      `reconnect to agent ${peerId.slice(0, 12)}... failed (${reason}) — retrying in ${Math.round(delay / 1000)}s`,
      'warn',
    );
  }

  /** Route a status line to the injected sink (never throws). */
  private emit(message: string, level: 'info' | 'warn' | 'error'): void {
    try {
      this.deps.onStatus?.(message, level);
    } catch {
      // A failing status sink must never break recovery.
    }
  }
}

/**
 * Extract the LAST `/p2p/<id>` component from a multiaddr string, tolerating a
 * trailing `/p2p-circuit`. Returns undefined when the address has no peer ID.
 */
export function extractPeerId(addrStr: string): string | undefined {
  const match = /\/p2p\/([^/]+)(?:\/p2p-circuit)?$/.exec(addrStr);
  return match?.[1];
}

/**
 * Could `peerId` ever be a libp2p peer ID?
 *
 * libp2p peer IDs are **base58btc multihash strings** (e.g.
 * `12D3KooWDWknVaqQesqsHf24nEeHjCe2wWNhMVxwmPHyNArKBegp`), so anything outside
 * the base58btc alphabet — `0`, `O`, `I`, `l`, `-`, `_`, `.`, hex digits 0/O —
 * is provably not one, and dialling it can only ever fail.
 *
 * WHY THIS EXISTS: the VTC setup flow (`createFounderVta` in
 * setup/setup-service.ts) records an ACTIVE endpoint for a freshly minted VTA
 * whose peer ID is a placeholder — `bootstrap-${randomBytes(16).toString('hex')}`
 * — because the operator's agent has not run yet and the founder must still
 * pass the "real VTA" endpoint check. Until that agent's identity_push retires
 * the placeholder, the endpoint list contains a member that is not a peer at
 * all: the supervisor dutifully built `<relay>/p2p-circuit/p2p/bootstrap-<hex>`,
 * failed every time (invalid peer ID), and logged
 * `reconnect to agent bootstrap-61... failed (all 1 address(es) failed)` every
 * 120s for the lifetime of the process — while the /health/connectivity status
 * listed it as a permanently stuck member.
 *
 * The length is deliberately NOT asserted: peer IDs are ≥ 46 characters in
 * practice, but a length bound would reject the short synthetic IDs the
 * supervisor's own tests use without adding any discrimination this alphabet
 * check does not already provide.
 */
export function isDialablePeerId(peerId: string): boolean {
  return typeof peerId === 'string' && /^[1-9A-HJ-NP-Za-km-z]+$/.test(peerId);
}

