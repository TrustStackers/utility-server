// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Layer 2 — Trust Spanning: /messages routes.
 *
 * - POST /messages/send      — send a TSP message over the live libp2p node to a related identity
 * - GET  /messages           — list messages, optionally filtered by ?didDocumentId=&unread=true
 * - PATCH /messages/:id/read — mark a message as read
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { Libp2p } from 'libp2p';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import { Libp2pTransport } from '@p2p-trust-stack/core/transport/libp2p-transport.js';
import type { TransportAddress } from '@p2p-trust-stack/core/transport/types.js';

import * as messagesRepo from '@p2p-trust-stack/core/db/repositories/messages-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as relationshipsRepo from '@p2p-trust-stack/core/db/repositories/relationships-repo.js';

interface SendMessageBody {
  fromDidDocumentUuid: string;
  relationshipUuid: string;
  body: string;
}

interface ListQuery {
  didDocumentUuid?: string;
  unread?: string;
}

export function registerMessageRoutes(
  app: FastifyInstance,
  db: DataSource,
  node: Libp2p,
): void {
  app.post(
    '/messages/send',
    async (req: FastifyRequest<{ Body: SendMessageBody }>, reply: FastifyReply) => {
      const { fromDidDocumentUuid, relationshipUuid, body } = req.body ?? ({} as SendMessageBody);
      if (!fromDidDocumentUuid || !relationshipUuid || !body) {
        return reply
          .code(400)
          .send({ error: { message: 'fromDidDocumentUuid, relationshipUuid, and body are required' } });
      }

      const relationship = await relationshipsRepo.findByUuid(db, relationshipUuid);
      if (!relationship) {
        return reply.code(404).send({ error: { message: `relationship ${relationshipUuid} not found` } });
      }
      if (!relationship.remoteTransport) {
        return reply
          .code(409)
          .send({ error: { message: `relationship ${relationshipUuid} has no known remote transport` } });
      }

      let remoteTransport: TransportAddress;
      try {
        remoteTransport = JSON.parse(relationship.remoteTransport);
      } catch {
        return reply.code(500).send({ error: { message: 'stored remote_transport is not valid JSON' } });
      }

      const transport = new Libp2pTransport(node);
      const payload = new TextEncoder().encode(body);

      try {
        await transport.send(payload, remoteTransport);
      } catch (err) {
        return reply.code(502).send({ error: { message: `failed to send message: ${(err as Error).message}` } });
      }

      const messageUuid = await messagesRepo.create(db, {
        fromDidDocumentUuid,
        toDidDocumentUuid: relationship.remoteDidDocumentUuid ?? null,
        type: 'TSP_GEN',
        decryptedPayload: body,
      });

      const row = await messagesRepo.findByUuid(db, messageUuid);
      return reply.code(201).send(row);
    },
  );

  app.get('/messages', async (req: FastifyRequest<{ Querystring: ListQuery }>, reply: FastifyReply) => {
    const { didDocumentUuid, unread } = req.query;

    if (didDocumentUuid !== undefined) {
      if (!await didDocumentsRepo.findByUuid(db, didDocumentUuid)) {
        return reply.code(404).send({ error: { message: `did_document ${didDocumentUuid} not found` } });
      }
    }

    return messagesRepo.findForDidDocument(db, {
      didDocumentUuid,
      unreadOnly: unread === 'true',
    });
  });

  app.patch(
    '/messages/:uuid/read',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const uuid = req.params.uuid;
      const existing = await messagesRepo.findByUuid(db, uuid);
      if (!existing) {
        return reply.code(404).send({ error: { message: `message ${uuid} not found` } });
      }
      await messagesRepo.markRead(db, uuid);
      return messagesRepo.findByUuid(db, uuid);
    },
  );
}
