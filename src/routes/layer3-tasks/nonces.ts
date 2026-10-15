/**
 * Layer 3 — Trust Tasks: /nonces routes.
 *
 * VP-style challenge/response support (replay protection).
 *
 * - POST /nonces/challenge      — request a fresh nonce for an identity
 * - POST /nonces/:nonce/verify  — verify (and consume) a nonce
 */

import { randomBytes } from 'node:crypto';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import * as noncesRepo from '@p2p-trust-stack/core/db/repositories/nonces-repo.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';

interface ChallengeBody {
  identityUuid: string;
  purpose?: string;
  expiresInSeconds?: number;
}

interface VerifyBody {
  identityUuid: string;
}

const DEFAULT_EXPIRY_SECONDS = 5 * 60; // 5 minutes

export function registerNonceRoutes(app: FastifyInstance, db: DataSource): void {
  app.post(
    '/nonces/challenge',
    async (req: FastifyRequest<{ Body: ChallengeBody }>, reply: FastifyReply) => {
      const body = req.body;
      if (!body?.identityUuid) {
        return reply.code(400).send({ error: { message: 'identityUuid is required' } });
      }
      if (!await identitiesRepo.findByUuid(db, body.identityUuid)) {
        return reply.code(404).send({ error: { message: `identity ${body.identityUuid} not found` } });
      }

      const nonce = randomBytes(32).toString('base64url');
      const now = Math.floor(Date.now() / 1000);
      const expiresAt = now + (body.expiresInSeconds ?? DEFAULT_EXPIRY_SECONDS);

      const uuid = await noncesRepo.create(db, {
        identityUuid: body.identityUuid,
        nonce,
        purpose: body.purpose,
        expiresAt,
      });

      const row = await noncesRepo.findByIdentityAndNonce(db, body.identityUuid, nonce);
      return reply.code(201).send({ uuid, ...row });
    },
  );

  app.post(
    '/nonces/:nonce/verify',
    async (req: FastifyRequest<{ Params: { nonce: string }; Body: VerifyBody }>, reply: FastifyReply) => {
      const nonce = req.params.nonce;
      const identityUuid = req.body?.identityUuid;
      if (!nonce || !identityUuid) {
        return reply.code(400).send({ error: { message: 'nonce (param) and identityUuid (body) are required' } });
      }

      const row = await noncesRepo.findByIdentityAndNonce(db, identityUuid, nonce);
      if (!row) {
        return reply.code(200).send({ valid: false, reason: 'nonce not found' });
      }

      const now = Math.floor(Date.now() / 1000);
      if (row.expiresAt !== null && row.expiresAt < now) {
        await noncesRepo.consume(db, row.uuid);
        return reply.code(200).send({ valid: false, reason: 'nonce expired' });
      }

      await noncesRepo.consume(db, row.uuid);
      return reply.code(200).send({ valid: true });
    },
  );
}
