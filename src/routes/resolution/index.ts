/**
 * Public DID resolution routes — the entire route table of the resolver
 * listener built by `utility-server/src/resolver-app.ts`.
 *
 * ## Isolation contract
 *
 * This module is deliberately the ONLY thing the resolver app registers besides
 * the error handler. It must never import `plugins/auth.ts` (session gate),
 * `@fastify/static` (admin UI), or any layer 1–5 admin registrar — the resolver
 * is the one surface intended to face the public internet, and the admin
 * surface must stay private. `test/resolution/isolation.test.ts` asserts this
 * by pinning the exact route list.
 *
 * ## Routes
 *
 *   GET /                                  landing page (DID entry form)
 *   GET /1.0/identifiers/:did              W3C DID Resolution (JSON or HTML)
 *   GET /1.0/identifiers/:did/log          the rotation log as JSONL
 *   GET /log/:scid/did.jsonl               same, did:webvh-style URL
 *   GET /health                            liveness
 *   GET /.well-known/did-scid-vh           discovery document
 *
 * ## Representation
 *
 * `/1.0/identifiers/:did` content-negotiates:
 *   - `Accept: text/html` (browsers) → the annotated HTML page.
 *   - `Accept: application/did+json` → the bare DID document.
 *   - anything else                  → the full W3C resolution envelope
 *                                      (`application/did+ld+json`).
 * `?format=json` / `?format=html` override negotiation, so the HTML page can
 * link to its own JSON representation.
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import {
  DidResolutionService,
  type DidResolutionReport,
} from '@p2p-trust-stack/core/did/did-resolution-service.js';
import { rotationLogToJsonl } from '@p2p-trust-stack/core/did/rotation-entry-codec.js';
import { renderLandingPage, renderResolutionPage } from '../../resolver-html.js';

export interface ResolutionRouteDeps {
  db: DataSource;
}

interface IdentifierQuery {
  versionId?: string;
  versionTime?: string;
  src?: string;
  format?: string;
}

/**
 * True when the client's `Accept` header prefers HTML over the DID JSON types.
 *
 * Compares POSITIONS rather than just presence: a browser names `text/html`
 * first (its Accept then ends with a wildcard), while a resolver client that
 * also accepts a wildcard but names `application/did+ld+json` first must keep
 * getting JSON.
 */
export function prefersHtml(accept: string | undefined): boolean {
  if (!accept) return false;
  const html = accept.indexOf('text/html');
  if (html === -1) return false;
  const didPositions = [accept.indexOf('application/did+ld+json'), accept.indexOf('application/did+json')]
    .filter((i) => i !== -1);
  const did = didPositions.length > 0 ? Math.min(...didPositions) : Infinity;
  return html < did;
}

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

export function registerResolutionRoutes(app: FastifyInstance, deps: ResolutionRouteDeps): void {
  const service = new DidResolutionService(deps.db);

  // ── Landing page — a human arriving at the resolver root ────────────────
  app.get('/', async (_req, reply) => {
    return reply.type('text/html; charset=utf-8').send(renderLandingPage());
  });

  // ── Liveness (resolver-scoped, no node data) ────────────────────────────
  app.get('/health', async () => ({
    status: 'ok',
    service: 'did-resolver',
    time: new Date().toISOString(),
  }));

  // ── Discovery document ──────────────────────────────────────────────────
  app.get('/.well-known/did-scid-vh', async () => ({
    method: 'did:scid:vh',
    resolutionEndpoint: '/1.0/identifiers/{did}',
    logEndpoint: '/log/{scid}/did.jsonl',
    representations: ['application/did+ld+json', 'application/did+json', 'text/html'],
    queryParameters: ['versionId', 'versionTime', 'src', 'format'],
  }));

  // ── W3C DID Resolution ──────────────────────────────────────────────────
  app.get(
    '/1.0/identifiers/:did',
    async (req: FastifyRequest<{ Params: { did: string }; Querystring: IdentifierQuery }>, reply: FastifyReply) => {
      const query = req.query ?? {};
      const report = await service.resolve(req.params.did, {
        versionId: query.versionId,
        versionTime: query.versionTime,
        src: query.src,
      });
      return sendReport(req, reply, report, query.format);
    },
  );

  // ── Rotation log as JSONL (machine-verifiable companion to the doc) ─────
  // A third party can replay this themselves rather than trusting our render.
  app.get(
    '/1.0/identifiers/:did/log',
    async (req: FastifyRequest<{ Params: { did: string } }>, reply: FastifyReply) =>
      sendLog(reply, service, req.params.did),
  );

  // did:webvh-style alias: did:scid:vh is always version 1, so the SCID alone
  // identifies the DID.
  app.get(
    '/log/:scid/did.jsonl',
    async (req: FastifyRequest<{ Params: { scid: string } }>, reply: FastifyReply) =>
      sendLog(reply, service, `did:scid:vh:1:${req.params.scid}`),
  );
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

function sendReport(
  req: FastifyRequest,
  reply: FastifyReply,
  report: DidResolutionReport,
  format: string | undefined,
): FastifyReply {
  const error = report.result.didResolutionMetadata.error;
  const wantHtml = format === 'html' || (format !== 'json' && prefersHtml(req.headers.accept));
  const status = error ? 404 : 200;

  reply.header('Access-Control-Allow-Origin', '*');
  reply.header('Cache-Control', error ? 'no-store' : 'public, max-age=300');

  // ETag keyed on the newest rotation version+digest: an unchanged identity
  // re-resolves cheaply, and a rotation invalidates the cache automatically.
  const latest = report.log?.[report.log.length - 1];
  if (latest) {
    const etag = `"v${latest.version}-${hex(latest.digest)}"`;
    reply.header('ETag', etag);
    if (req.headers['if-none-match'] === etag) return reply.code(304).send();
  }

  if (wantHtml) {
    return reply.code(status).type('text/html; charset=utf-8').send(renderResolutionPage(report));
  }

  // `application/did+json` means "the document only"; the LD form and the
  // default both mean "the full resolution envelope".
  const accept = req.headers.accept ?? '';
  const bareDocument = /application\/did\+json/.test(accept) && !/application\/did\+ld\+json/.test(accept);
  reply.type(bareDocument ? 'application/did+json' : 'application/did+ld+json');
  return reply.code(status).send(bareDocument ? report.result.didDocument : report.result);
}

async function sendLog(
  reply: FastifyReply,
  service: DidResolutionService,
  did: string,
): Promise<FastifyReply> {
  reply.header('Access-Control-Allow-Origin', '*');
  const log = await service.resolveLog(did);
  if (!log || log.entries.length === 0) {
    return reply
      .code(404)
      .type('application/json')
      .send({ error: { message: `no rotation log held for ${did}` } });
  }

  const latest = log.entries[log.entries.length - 1];
  reply.header('ETag', `"v${latest.version}-${hex(latest.digest)}"`);
  reply.header('Cache-Control', 'public, max-age=3600');
  return reply.type('application/jsonl; charset=utf-8').send(rotationLogToJsonl(log.entries));
}
