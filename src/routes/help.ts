/**
 * /help route — a lightweight, self-describing API index.
 *
 * Introspects every route Fastify has registered (via `app.printRoutes()`
 * in JSON form) and returns them grouped by trust-stack layer, each
 * annotated with a short human-readable description where one is known.
 * Registered *last* in server.ts so it sees every other route group's
 * routes, including the layer 3-5 stubs.
 *
 * This is the HTTP-reachable equivalent of a CLI `--help`: once the server
 * is running, `curl http://localhost:8787/help` (or open it in a browser)
 * lists every available endpoint without needing to read the source.
 *
 * See also: `npm run routes`, a standalone script (src/scripts/list-routes.ts)
 * that prints the same information to the console without booting the
 * database/libp2p/HTTP listener at all.
 */

import type { FastifyInstance } from 'fastify';

/**
 * Known route descriptions, keyed by `"METHOD /path"` (Fastify's own path
 * syntax, e.g. `/identities/:id`). Routes not found here still show up in
 * the listing, just without a description.
 */
const ROUTE_DESCRIPTIONS: Record<string, string> = {
  'GET /health': 'Liveness check — returns { status, service, time }.',
  'GET /help': 'This route — lists every registered API endpoint.',

  // Layer 1 — Infrastructure
  'POST /identities': 'Create a new identity (VTA/VTC/VTN).',
  'GET /identities': 'List identities, optionally filtered by ?role= and/or ?custody=.',
  'GET /identities/:id': 'Fetch a single identity by numeric id.',
  'GET /identities/by-did/:did': 'Fetch a single identity by its DID.',

  'POST /did-documents': 'Create a new did_document row for an identity.',
  'GET /did-documents/:id': 'Fetch a single did_document by numeric id.',
  'GET /did-documents/by-did/:did': 'Fetch a single did_document by its DID.',
  'GET /identities/:identityId/did-documents': 'List all did_documents for an identity.',
  'PATCH /did-documents/:id/primary': 'Mark a did_document as the primary one for its identity.',
  'PATCH /did-documents/:id/status': 'Set a did_document status (active/deactivated/superseded).',

  'POST /did-documents/:id/rotation-log': 'Append a signed key-rotation entry for a did_document.',
  'GET /did-documents/:id/rotation-log': 'List the full rotation log for a did_document.',
  'GET /did-documents/:id/rotation-log/latest': 'Fetch the most recent rotation-log entry.',
  'POST /rotation-log/:id/witness-attestations': 'Add a witness signature attesting to a rotation entry.',
  'GET /rotation-log/:id/witness-attestations': 'List witness attestations for a rotation entry.',

  // Layer 2 — Trust Spanning
  'POST /relationships/oobi': 'Generate an OOBI (VID + peerId + multiaddrs) for a local identity.',
  'POST /relationships': 'Establish a relationship from a received OOBI (sends RFI via the live libp2p node).',
  'GET /relationships': 'List relationships for a local identity (?identityId=).',
  'GET /relationships/:id': 'Fetch a single relationship by numeric id.',
  'POST /messages/send': 'Send a TSP message to a related peer over the live libp2p node.',
  'GET /messages': 'List messages, optionally filtered by ?didDocumentId=&unread=true.',
  'PATCH /messages/:id/read': 'Mark a message as read.',

  // Layer 3 — Trust Tasks
  'POST /credentials': 'Issue a credential (VMC/VEC/VRC/custom_endorsement/delegation); optional profileId attaches a profile\'s R-Card snapshot into the claim.',

  'GET /credentials': 'List credentials, optionally filtered by ?subjectId=&issuerId=&vcType=.',
  'GET /credentials/:id': 'Fetch a single credential.',
  'POST /credentials/:id/signatures': 'Add a signature to a pending-signatures credential; flips to issued at threshold.',
  'GET /credentials/:id/signatures': 'List the collected signatures for a credential.',
  'POST /credentials/:id/verify':
    'Verify a credential. `valid` is true only when the signature threshold is met; `indeterminate: true` with `signatureCounts` reports that the threshold was missed WITHOUT any signature being provably invalid (no locally-known key for a signer) — that is not the same as an invalid signature.',
  'POST /credentials/:id/revoke': 'Revoke a credential (flips a status_list bit).',
  'POST /status-lists': 'Provision a status list ahead of time for a community.',
  'GET /status-lists/:id': 'Fetch a Bitstring Status List (public bitstring for external verifiers).',
  'GET /status-lists/:id/flips': 'List the raw flip history (audit log) for a status list.',
  'POST /nonces/challenge': 'Request a fresh replay-protection nonce for an identity.',
  'POST /nonces/:nonce/verify': 'Verify (and consume) a nonce.',
  'POST /auth/challenge': 'Issue a random nonce challenge for a VTA to sign (challenge-response authentication).',
  'POST /auth/verify': 'Verify an Ed25519 signature over a previously-issued nonce against the VTA\'s published key.',
  'POST /trust-tasks': 'Submit a Trust Task envelope ({ id, type, threadId, issuer, recipient, issuedAt, payload, proof }); the task:p2pts:… type routes to evaluate/test/validate/upsert, and the reply is a #response envelope.',

  // Layer 4 — Governance
  'GET /memberships/:id': 'Fetch a single membership by numeric id.',
  'GET /memberships': 'List memberships, optionally filtered by ?memberIdentityId=&communityIdentityId=&status=.',
  'POST /communities/:communityId/memberships': 'Request membership in a community (status=pending).',
  'POST /memberships/:id/approve': 'Approve a pending membership -> active; issues a backing VMC credential.',
  'POST /memberships/:id/personhood-events': 'Record a personhood ceremony event (challenged/asserted/revoked).',
  'GET /memberships/:id/personhood-events': 'List personhood ceremony events for a membership.',
  'GET /personhood-events/:id': 'Fetch a single personhood event by numeric id.',
  'GET /governance/:id': 'Fetch a governance row by its own numeric id.',
  // NB: these keys must match the REGISTERED path EXACTLY — Fastify's `:uuid`, not `:id`
  // — or the description silently never applies. Three entries below (governance ×2 and
  // dashboard) had drifted to `:id` and were returning `description: null`.
  'GET /communities/:uuid/governance': 'Fetch a community\'s governance parameters.',
  'PATCH /communities/:uuid/governance': 'Update (or create) a community\'s governance parameters.',

  'GET /delegations/:id': 'Fetch a single delegation by numeric id.',
  'POST /delegations': 'Create a delegation (operates/owns/represents/employs).',
  'GET /delegations': 'List delegations, optionally filtered by ?principalId=&dependentId=.',
  'POST /delegations/:id/revoke': 'Revoke a delegation.',
  'GET /grants/:id': 'Fetch a single grant by numeric id.',
  'POST /grants': 'Create a grant (usually system-generated on credential/delegation issuance).',
  'GET /grants': 'List grants, optionally filtered by ?granteeId=&scopeId=&permission=.',
  'POST /grants/:id/revoke': 'Revoke a grant.',
  'GET /grants/check': 'Check whether a grantee holds a permission, optionally scoped to a community.',

  // Layer 5 — Trust Applications
  'GET /identities/:id/profile': 'Composed profile: identity + primary DID + memberships + delegations + grants.',
  'GET /communities/:uuid/dashboard': 'Composed dashboard: governance + membership roster (by status) + pending approvals.',
  'GET /graph/edges': 'DTG edge list (credentials + delegations as edges), optionally filtered by ?identityId=.',
  'POST /webhooks/subscriptions': '[stub] Webhook/event subscription endpoints for external Layer 4 apps.',
  'POST /vtas': 'Register a new VTA: generates a did:peer:4 identity + identities/did_documents rows + encrypted keys (passphrase required).',
  'POST /vtcs': 'Create a VTC/VTN: identities + governance (M-of-N threshold + policy bindings) + founding_admin memberships + pre-seeded revocation status_list, in one composed action.',
  'GET /vtcs': 'List all VTC/VTN identities, enriched with governance parameters and active member count.',
  // VTN network rules (Phase B follow-up) — admin-gated; approvals are co-signed from agents.
  'GET /vtns/:uuid/governance': "A VTN's governance rules + pending changes (VTN admins/founding admins only).",
  'POST /vtns/:uuid/governance/propose': 'Propose a VTN governance change (VTN admins only); the required admins co-sign from their agent apps.',
  'GET /dashboard/summary': 'UI dashboard counts: total VTAs/VTCs/VTNs/VRCs/Other Credentials, plus VTA breakdown by subject_kind.',


  // Layer 5 — Profiles (Scenario 3 — Manage Multiple Profiles / R-Cards)
  'POST /identities/:id/profiles': 'Create a display-layer profile (persona) for an identity.',
  'GET /identities/:id/profiles': 'List all profiles for an identity.',
  'GET /profiles/:id': 'Fetch a single profile by numeric id.',
  'PATCH /profiles/:id': 'Update a profile\'s label/purpose/visibility, or set it as default.',
  'DELETE /profiles/:id': 'Remove a profile (blocked if it is the identity\'s last remaining profile).',
  'POST /profiles/:id/claims': 'Add a claim (key/value + visibility/disclosure) to a profile.',
  'GET /profiles/:id/claims': 'List all claims on a profile.',
  'PATCH /profile-claims/:id': 'Update a profile claim\'s value/type/disclosure/order.',
  'DELETE /profile-claims/:id': 'Remove a profile claim.',
  'GET /profiles/:id/card': 'Assemble the shareable R-Card/Agent-Card view of a profile, filtered by claim disclosure rules (?requested= for discretionary claims).',
};

/**
 * Replace every `:param` segment with `:_`, so a description attaches regardless of how
 * the parameter happens to be NAMED.
 *
 * Why this exists: these descriptions were written when ids were integers (`:id`), and
 * the schema moved to UUIDs (`:uuid`). The lookup below is an exact-string match, so
 * `:id` !== `:uuid` — and 41 of 81 descriptions were silently returning
 * `description: null`. Renaming the keys would fix today's drift and leave the next
 * rename to break it again; normalising both sides makes the parameter name irrelevant,
 * which is the property actually wanted: a description describes the ROUTE, not the
 * spelling of its parameters.
 */
export function normalizeRoutePath(path: string): string {
  return path.replace(/:[^/]+/g, ':_');
}

/** The description index, keyed by normalised `METHOD /path`. */
const DESCRIPTION_BY_NORMALIZED_KEY: Record<string, string> = Object.fromEntries(
  Object.entries(ROUTE_DESCRIPTIONS).map(([key, value]) => [normalizeRoutePath(key), value]),
);

interface RouteEntry {
  method: string;
  path: string;
  description: string | null;
}

/**
 * Pull the flat list of registered routes out of Fastify.
 *
 * Fastify's `printRoutes({ commonPrefix: false })` returns a human-oriented
 * tree string by default; passing no args still gives a string, but the
 * find-my-own-my-way-around approach here uses the lower-level
 * `app.routes` iteration available in Fastify v5 via `getRoutes` in some
 * versions — since that's not guaranteed across versions, we fall back to
 * walking `app.printRoutes({ commonPrefix: false })`'s raw route metadata
 * via the documented `onRoute` hook instead, collected as the app is built.
 */
export function collectRoutes(app: FastifyInstance): RouteEntry[] {
  const routes: RouteEntry[] = [];
  for (const entry of (app as unknown as { [key: symbol]: unknown } as any).__routeRegistry ?? []) {
    routes.push(entry);
  }
  return routes.sort((a, b) => (a.path === b.path ? a.method.localeCompare(b.method) : a.path.localeCompare(b.path)));
}

/**
 * Registers an `onRoute` hook (must be called before other route
 * registrations, or at least before app.ready()) that records every route
 * Fastify registers into `app.__routeRegistry`, then exposes GET /help to
 * read that registry back out as JSON.
 */
export function registerHelpRoute(app: FastifyInstance): void {
  const registry: RouteEntry[] = [];
  (app as any).__routeRegistry = registry;

  app.addHook('onRoute' as any, (routeOptions: { method: string | string[]; url: string }) => {
    const methods = Array.isArray(routeOptions.method) ? routeOptions.method : [routeOptions.method];
    for (const method of methods) {
      if (method === 'HEAD' || method === 'OPTIONS') continue; // Fastify auto-adds these; skip noise.
      const key = `${method} ${routeOptions.url}`;
      registry.push({
        method,
        path: routeOptions.url,
        // Normalised lookup: the description attaches whatever the parameters are called.
        description: DESCRIPTION_BY_NORMALIZED_KEY[normalizeRoutePath(key)] ?? null,
      });
    }
  });

  app.get('/help', async () => {
    const routes = collectRoutes(app);
    return {
      service: 'utility-server',
      description: 'P2P Trust Stack utility server API. Layers 1-5 are fully implemented; webhook/event subscriptions remain a registered stub (501 Not Implemented).',
      routeCount: routes.length,
      routes,
    };
  });
}
