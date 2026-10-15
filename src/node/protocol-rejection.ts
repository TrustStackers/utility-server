/**
 * F-029 — what to do with a protocol message this node does not recognise.
 *
 * ## The finding
 *
 * *"An unrecognised protocol message is stored as raw chat traffic."* `routeProtocolMessage`
 * fell through to `messagesRepo.create({ type: 'tsp-<protocol>' })` — the same table the
 * chat UI reads. Two consequences, both bad:
 *
 *   1. **Unsolicited content became indistinguishable from real traffic.** A peer (or
 *      anything that can reach the transport) could write into a transcript by sending a
 *      protocol string the stack did not recognise; nothing marked it as foreign.
 *   2. **The stack silently absorbed what it could not interpret.** An unrecognised
 *      protocol is a statement about the *sender*, and refusing it is the honest answer.
 *
 * ## The ruling
 *
 * **Y5-reject (2026-09-24):** refuse it — report and store nothing.
 *
 * ## What this deliberately does NOT change
 *
 * The `tsp-raw` branch in the same function handles bodies that are not protocol messages
 * at all. Those are ordinary peer-to-peer traffic and keep being stored: a plain message
 * between peers IS chat. Only the *unrecognised protocol* case is refused, and the
 * predicate below exists so that distinction is explicit at the call site rather than an
 * omission a reader has to infer.
 */

/**
 * Should an unrecognised protocol message be stored?
 *
 * Always `false` under ruling Y5-reject. It is a named seam rather than an inline
 * `false` for two reasons: the call site then reads as a decision, and a test can pin
 * the policy so a future edit cannot quietly restore the write.
 */
export function shouldStoreUnrecognisedProtocol(protocol: string): boolean {
  // Parameter kept for the signature's sake: the policy is about the CLASS of message,
  // not about which unknown protocol it happens to be.
  void protocol;
  return false;
}

/**
 * The refusal line. Kept beside the predicate so the wording and the policy cannot drift.
 */
export function describeUnrecognisedProtocolRefusal(
  protocol: string,
  opts: { fromDidDocumentUuid?: string | null; bodyLength?: number } = {},
): string {
  const from = opts.fromDidDocumentUuid ? `doc=${opts.fromDidDocumentUuid.slice(0, 8)}…` : 'doc=unknown';
  const len = opts.bodyLength === undefined ? '' : ` len=${opts.bodyLength}`;
  return (
    `[tsp-bridge] REJECTED unrecognised protocol message "${protocol}" (${from}${len}) — ` +
    'not stored (F-029 / Y5-reject: unsolicited protocol traffic must not enter the message store)'
  );
}
