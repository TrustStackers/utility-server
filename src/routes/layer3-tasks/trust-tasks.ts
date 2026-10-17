// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Layer 3 — Trust Tasks: `POST /trust-tasks` (the document-level bridge, P5.5).
 *
 * This is the ONE endpoint that speaks the Trust Task envelope: an inbound document
 * carrying `{id, type, threadId, issuer, recipient, issuedAt, payload, proof}` is parsed,
 * its `proof` checked for transport attribution, its `type` routed to a policy
 * operation, and the reply wrapped back into an envelope.
 *
 * It REUSES the P4 policy logic (`gatePolicy`, `createPolicyEngine`'s validate/evaluate,
 * the governance repo) rather than reimplementing it — the bridge only adds framing.
 * Our `type` identifiers are `task:p2pts:…` (see `src/services/trust-tasks/type-uris.ts`).
 *
 * ## The correctness rule (docs/08 §7)
 *
 * A document carrying a `proof` whose issuer is NOT authenticated by this transport is
 * INDETERMINATE — we refuse it (401 `proof/unattributable`) rather than act as its
 * content asks. This is the transport-edge realization of "indeterminate, not allow":
 * a proof proves *who asked*, never *that they may*, and without a transport binding we
 * cannot even attribute it. We do NOT verify the proof's cryptosuite here (crypto stays
 * in `GovernanceGuard`) — we only require that the `issuer` matches the session's
 * authenticated identity.
 *
 * ## Envelope → operation mapping
 *
 * The `recipient` is the community DID (`task:p2pts:policy:*` always names a community to
 * act on); the `issuer` is the actor DID; the `payload` carries the operation body:
 *
 *   evaluate — payload `{ action, kind?, subjectDid?, facts? }`  → `gatePolicy` (real facts)
 *   test     — payload `{ policy, query, data? }`                 → engine dry-run on supplied input
 *   validate — payload `{ policy }`                               → engine.validatePolicy
 *   upsert   — payload `{ policy }`                               → validate + persist + fan-out
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import {
  listCeremonyThreads,
  getCeremonyThread,
} from '@p2p-trust-stack/core/services/trust-tasks/ceremony-log.js';
import { POLICY_ACTIONS } from '@p2p-trust-stack/core/services/policy-engine.js';
import type { PolicyQuery } from '@p2p-trust-stack/core/services/policy-engine.js';
import {
  parseTrustTask,
  buildResponse,
  buildError,
  isIndeterminateForProof,
  typeUriToOperation,
} from '@p2p-trust-stack/core/services/trust-tasks/index.js';
import type {
  TrustTaskDocument,
  TrustTaskError,
  PolicyDocumentOperation,
} from '@p2p-trust-stack/core/services/trust-tasks/index.js';
import { gatePolicy } from '@p2p-trust-stack/core/services/policy-gate.js';
import { validateSession } from '../../session.js';

/** An operational refusal that becomes a `buildError` response. */
class TaskFailure extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, message: string, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

function payloadOf(doc: TrustTaskDocument): Record<string, unknown> {
  return (typeof doc.payload === 'object' && doc.payload !== null
    ? doc.payload
    : {}) as Record<string, unknown>;
}

/** Resolve the community named by the envelope's `recipient` DID. */
async function resolveCommunityByDid(
  db: DataSource,
  did: string | undefined,
): Promise<{ uuid: string; did: string; role: string }> {
  if (!did || typeof did !== 'string' || did.length === 0) {
    throw new TaskFailure('malformedRequest', 'recipient (community DID) is required', 400);
  }
  const identity = await identitiesRepo.findByRealDid(db, did);
  if (!identity || !identity.did) {
    throw new TaskFailure('communityNotFound', `community ${did} not found`, 404);
  }
  return { uuid: identity.uuid, did: identity.did, role: identity.role };
}

/** Is `issuer` the same identity the session authenticated? */
async function issuerAuthenticated(
  db: DataSource,
  doc: TrustTaskDocument,
  cookie: string | undefined,
  secret: Buffer,
): Promise<boolean> {
  if (!doc.issuer || typeof doc.issuer !== 'string') return false;
  const session = validateSession(cookie, secret);
  if (!session) return false;
  const identity = await identitiesRepo.findByUuid(db, session.identityUuid);
  return identity?.did === doc.issuer;
}

async function evaluateTask(db: DataSource, doc: TrustTaskDocument): Promise<unknown> {
  const community = await resolveCommunityByDid(db, doc.recipient);
  const p = payloadOf(doc);
  const action = p.action;
  if (typeof action !== 'string' || !action) {
    throw new TaskFailure('policy/invalid', 'payload.action is required', 400);
  }
  if (!(POLICY_ACTIONS as readonly string[]).includes(action)) {
    throw new TaskFailure('policy/invalid', `unknown action '${action}'`, 400);
  }
  const params: Record<string, unknown> = {};
  if (p.kind !== undefined) params.kind = p.kind;
  if (p.subjectDid !== undefined) params.subjectDid = p.subjectDid;
  const query: PolicyQuery = {
    action: action as PolicyQuery['action'],
    communityDid: community.did,
    actorDid: typeof doc.issuer === 'string' && doc.issuer ? doc.issuer : community.did,
    params,
  };
  const facts = (p.facts && typeof p.facts === 'object')
    ? p.facts as Record<string, unknown>
    : undefined;
  const result = await gatePolicy(db, query, facts);
  return { communityUuid: community.uuid, communityDid: community.did, query, result };
}

/**
 * Dispatch a policy trust-task operation. Only the read-only `evaluate` remains — the
 * document-writing ops (`upsert`/`test`/`validate`) were the utility server's developer
 * policy API and are removed. Governance changes flow through the governance-change
 * ceremony (Phase B), never a direct document write.
 */
async function dispatch(db: DataSource, op: PolicyDocumentOperation, doc: TrustTaskDocument): Promise<unknown> {
  if (op === 'evaluate') return evaluateTask(db, doc);
  throw new TaskFailure('endpointNotFound', `unsupported operation '${op}'`, 404);
}

function sendError(
  reply: FastifyReply,
  doc: TrustTaskDocument | undefined,
  status: number,
  error: TrustTaskError,
) {
  return reply.code(status).send(buildError(doc, error));
}

export function registerTrustTaskRoutes(app: FastifyInstance, db: DataSource): void {
  app.post(
    '/trust-tasks',
    async (req: FastifyRequest<{ Body: unknown }>, reply: FastifyReply) => {
      // 1. Parse the envelope.
      const parsed = parseTrustTask(req.body);
      if (!parsed.ok) {
        return sendError(reply, undefined, 400, { code: parsed.code, message: parsed.message });
      }
      const doc = parsed.document;

      // 2. A response document is not a request.
      if (doc.type.endsWith('#response')) {
        return sendError(reply, doc, 400, { code: 'malformedRequest', message: 'a #response document is not a request' });
      }

      // 3. Transport attribution of the issuer.
      const hmacSecret = (app as unknown as { hmacSecret?: Buffer }).hmacSecret;
      const authenticated = hmacSecret
        ? await issuerAuthenticated(db, doc, req.headers.cookie, hmacSecret)
        : false;

      // 4. proof → indeterminate (never silently allow).
      if (isIndeterminateForProof(doc, authenticated)) {
        return sendError(reply, doc, 401, {
          code: 'proof/unattributable',
          message: 'document carries a proof, but its issuer is not authenticated over this transport',
        });
      }

      // 5. Route by type.
      const op = typeUriToOperation(doc.type);
      if (!op) {
        return sendError(reply, doc, 404, { code: 'endpointNotFound', message: `unknown task type '${doc.type}'` });
      }

      // 6. Dispatch, and wrap the reply.
      try {
        const result = await dispatch(db, op, doc);
        return reply.send(buildResponse(doc, result));
      } catch (err) {
        if (err instanceof TaskFailure) {
          return sendError(reply, doc, err.status, { code: err.code, message: err.message });
        }
        throw err;
      }
    },
  );

  // ── GET /trust-tasks/threads — the ceremony task-log index ────────────────
  // One entry per ceremony RUN, newest first. Registered before the `:threadId`
  // route in intent — Fastify resolves the static segment first, so `threads` is
  // never read as a thread id.
  app.get('/trust-tasks/threads', async () => ({ threads: await listCeremonyThreads(db) }));

  // ── GET /trust-tasks/:threadId — read a ceremony's task record ────────────
  // The queryable half of the audit trail: given a ceremony `threadId`
  // (= the ceremonyId), return every recorded task document in record order.
  app.get(
    '/trust-tasks/:threadId',
    async (req: FastifyRequest<{ Params: { threadId: string } }>) => ({
      threadId: req.params.threadId,
      tasks: await getCeremonyThread(db, req.params.threadId),
    }),
  );
}
