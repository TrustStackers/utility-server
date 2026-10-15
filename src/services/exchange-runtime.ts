/**
 * Exchange runtime holder — the single server-side ExchangeEngine instance,
 * set once at startup (index.ts) and imported by route handlers that trigger
 * queue-row fan-out (`engine.enqueueFanout`).
 *
 * Keeping it module-level (rather than threading deps through every route
 * registration) matches the utility-server's existing pattern and avoids
 * changing route signatures for a single shared dependency.
 */
import type { ExchangeEngine } from '@p2p-trust-stack/core/exchange/engine.js';
import type { RecordSetName } from '@p2p-trust-stack/core/exchange/types.js';

let engine: ExchangeEngine | null = null;

export function setExchangeEngine(e: ExchangeEngine): void {
  engine = e;
}

export function getExchangeEngine(): ExchangeEngine {
  if (!engine) throw new Error('ExchangeEngine not initialized (utility server)');
  return engine;
}

export function hasExchangeEngine(): boolean {
  return engine !== null;
}

/**
 * Fire-and-forget queue-row fan-out through the server engine.
 *
 * Used by participants that run inside the 2PC coordinator (vtc-create /
 * ceremony) where the engine may not be wired in unit-test/standalone contexts —
 * in that case the fan-out is skipped with a warning (same degraded behavior as
 * the TSP adapter being absent: no delivery queue means nothing can enqueue).
 */
export async function tryEnqueueFanout(
  name: RecordSetName,
  ref: Record<string, unknown>,
): Promise<{ queued: number; targets: string[] } | null> {
  if (!engine) {
    console.warn(`[exchange-runtime] fan-out '${name}' skipped — ExchangeEngine not wired`);
    return null;
  }
  return engine.enqueueFanout(name, ref);
}