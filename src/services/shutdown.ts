/**
 * shutdown — a tiny process-lifecycle signal.
 *
 * The setup wizard (`/setup/confirm`) has to terminate the process it runs in:
 * the HTTP listen port, the libp2p port, and the advertised IP are all fixed at
 * boot (`index.ts`), so entering operational mode after first-launch config
 * requires a fresh start. `setup-routes.ts` cannot reach the teardown closure in
 * `index.ts` directly, so it asks through this module and `index.ts` registers
 * the real handler at startup.
 *
 * When nothing is registered (unit tests, scripts) `requestShutdown` is a no-op,
 * so importing the setup routes never terminates a test runner.
 */

export type ShutdownReason = 'setup-complete' | 'signal';

type ShutdownHandler = (reason: ShutdownReason) => void;

let handler: ShutdownHandler | undefined;

/** Register the process teardown. Called once from `index.ts`. */
export function onShutdownRequested(cb: ShutdownHandler): void {
  handler = cb;
}

/**
 * Ask the process to shut down gracefully.
 *
 * Call this only AFTER the current HTTP response has been flushed (attach it to
 * the response `finish` event) so the client receives its reply before the
 * socket closes.
 */
export function requestShutdown(reason: ShutdownReason): void {
  handler?.(reason);
}
