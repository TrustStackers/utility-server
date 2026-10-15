/**
 * Global Fastify error handler.
 *
 * Normalizes thrown errors into a consistent JSON envelope:
 *   { error: { message, code? } }
 * Uses `err.statusCode` when set (e.g. by `fastify-sensible`-style helpers
 * or manually via `reply.code(...)`), otherwise defaults to 500.
 */

import type { FastifyInstance, FastifyError, FastifyRequest, FastifyReply } from 'fastify';

export function registerErrorHandler(app: FastifyInstance): void {
  app.setErrorHandler((err: FastifyError, _req: FastifyRequest, reply: FastifyReply) => {
    const statusCode = err.statusCode ?? 500;

    if (statusCode >= 500) {
      app.log.error(err);
    }

    reply.code(statusCode).send({
      error: {
        message: err.message ?? 'Internal Server Error',
        code: err.code,
      },
    });
  });

  app.setNotFoundHandler((req: FastifyRequest, reply: FastifyReply) => {
    reply.code(404).send({
      error: {
        message: `Route not found: ${req.method} ${req.url}`,
      },
    });
  });
}
