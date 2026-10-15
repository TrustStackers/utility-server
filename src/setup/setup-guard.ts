/**
 * setup-guard — redirects an unconfigured instance to the setup wizard.
 * Mirrors crowdfund's setup-guard; registered as an onRequest hook only when
 * the instance is not yet configured.
 */

import type { FastifyRequest, FastifyReply } from 'fastify';
import { isConfigured } from '../setup/setup-state.js';

const ALLOWED_PREFIXES = [
  '/setup',
  '/auth/',
  '/health',
  '/lib/',
  '/favicon.ico',
  '/ui/setup.html',
];

export async function requireSetup(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  // Only engage in setup mode.
  if (isConfigured()) return;

  const url = (request.url ?? '').split('?')[0];
  if (url === '/' || ALLOWED_PREFIXES.some((p) => url === p || url.startsWith(p))) {
    return;
  }

  if (request.method === 'GET' || request.method === 'HEAD') {
    return reply.redirect('/ui/setup.html');
  }
  return reply.code(503).send({
    error: { message: 'Instance not configured' },
    setupUrl: '/ui/setup.html',
  });
}
