/**
 * Layer 3 — Trust Tasks: /credentials routes.
 *
 * - POST /credentials                 — issue a credential (single-signer issues directly,
 *                                        multi-signer creates a pending_signatures row)
 * - GET  /credentials                 — list, filterable by ?subjectId=&issuerId=&vcType=
 * - GET  /credentials/:id             — fetch a single credential
 * - POST /credentials/:id/signatures  — add a co-signer signature; auto-flips status to
 *                                        'issued' at threshold
 * - POST /credentials/:id/verify      — verify a credential against locally-known DIDs/keys
 * - POST /credentials/:id/revoke      — flips a status_list bit + sets status='revoked'
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import * as credentialsRepo from '@p2p-trust-stack/core/db/repositories/credentials-repo.js';
import type { VcType, CredentialStatus } from '@p2p-trust-stack/core/db/repositories/credentials-repo.js';
import * as credentialSignaturesRepo from '@p2p-trust-stack/core/db/repositories/credential-signatures-repo.js';
import * as statusListsRepo from '@p2p-trust-stack/core/db/repositories/status-lists-repo.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as keysRepo from '@p2p-trust-stack/core/db/repositories/keys-repo.js';
import { getProfileCard, ProfileNotFoundError } from '../../services/profiles.js';
import { verifyEd25519 } from '@p2p-trust-stack/core/crypto/primitives.js';

interface CreateCredentialBody {
  vcType: VcType;
  issuerIdentityUuid: string;
  subjectIdentityUuid: string;
  claim?: unknown;
  thresholdRequired?: number;
  validFrom?: number;
  validUntil?: number;
  profileUuid?: string;
  profileCardRequestedKeys?: string[];
}


interface ListQuery {
  subjectUuid?: string;
  issuerUuid?: string;
  vcType?: VcType;
}

interface AddSignatureBody {
  signerIdentityUuid: string;
  signerDidDocumentUuid?: string;
  signature: string; // base64
}

interface RevokeBody {
  reason?: string;
}

interface SignatureResult {
  signerIdentityUuid: string;
  signerName: string;
  valid: boolean | null; // true = verified, false = invalid, null = unverifiable (no local key)
}

interface VerifyResult {
  valid: boolean;
  /**
   * F-031: true when the threshold was missed WITHOUT any signature being proven
   * invalid — i.e. the verifier could not check, because no locally-known key
   * exists for the signer. That is a different outcome with different
   * consequences from a failed verification: "forged" and "I cannot tell" must
   * not read the same. Absent on the pre-signature short-circuits (expired,
   * revoked, no signatures at all), which are definite.
   */
  indeterminate?: boolean;
  /** Per-outcome tallies; `valid + invalid + indeterminate` = signatures checked. */
  signatureCounts?: { valid: number; invalid: number; indeterminate: number };
  reason: string;
  signatureResults: SignatureResult[];
}

/**
 * Verify a single Ed25519 signature against a signer's locally-known public key.
 * Returns null if the signer's key material is not available locally.
 */
async function verifySignature(
  db: DataSource,
  signerIdentityUuid: string,
  signerDidDocumentUuid: string | null,
  signatureBytes: Uint8Array,
  messageToVerify: Uint8Array,
): Promise<boolean | null> {
  // Determine which DID document to look up keys for
  let didDocUuid: string | null | undefined = signerDidDocumentUuid
    ? (await didDocumentsRepo.findByUuid(db, signerDidDocumentUuid))?.uuid
    : undefined;
  if (didDocUuid === undefined) {
    // Fall back to the primary DID document for the signer identity
    const primaryDoc = await didDocumentsRepo.findPrimaryForIdentity(db, signerIdentityUuid);
    if (!primaryDoc) return null;
    didDocUuid = primaryDoc.uuid;
  }

  const signerIdentity = await identitiesRepo.findByUuid(db, signerIdentityUuid);
  if (!signerIdentity) return null;

  // Look up the signer's current Ed25519 public key for this DID document
  const allKeys = await keysRepo.findByIdentityUuid(db, signerIdentity.uuid);
  const edKey = allKeys.filter(k => k.keyType === 'ed25519').sort((a, b) => (b.rotationVersion ?? 0) - (a.rotationVersion ?? 0))[0];
  if (!edKey) return null;

  try {
    return verifyEd25519(signatureBytes, messageToVerify, new Uint8Array(edKey.publicKey));
  } catch {
    return false;
  }
}

export function registerCredentialRoutes(app: FastifyInstance, db: DataSource): void {
  // -------------------------------------------------------------------------
  // POST /credentials — issue a credential
  // -------------------------------------------------------------------------
  app.post(
    '/credentials',
    async (req: FastifyRequest<{ Body: CreateCredentialBody }>, reply: FastifyReply) => {
      const body = req.body;
      if (!body?.vcType || !body?.issuerIdentityUuid || !body?.subjectIdentityUuid) {
        return reply
          .code(400)
          .send({ error: { message: 'vcType, issuerIdentityUuid, and subjectIdentityUuid are required' } });
      }

      if (!await identitiesRepo.findByUuid(db, body.issuerIdentityUuid)) {
        return reply.code(404).send({ error: { message: `issuer identity ${body.issuerIdentityUuid} not found` } });
      }
      if (!await identitiesRepo.findByUuid(db, body.subjectIdentityUuid)) {
        return reply.code(404).send({ error: { message: `subject identity ${body.subjectIdentityUuid} not found` } });
      }

      const threshold = body.thresholdRequired;
      const status: CredentialStatus = threshold !== undefined && threshold > 1 ? 'pending_signatures' : 'issued';
      const validFrom = body.validFrom ?? Math.floor(Date.now() / 1000);

      let claimPayload = body.claim;
      if (body.profileUuid !== undefined) {
        let profileCard;
        try {
          profileCard = await getProfileCard(db, body.profileUuid, body.profileCardRequestedKeys ?? []);
        } catch (err) {
          if (err instanceof ProfileNotFoundError) {
            return reply.code(404).send({ error: { message: err.message } });
          }
          throw err;
        }
        claimPayload =
          claimPayload && typeof claimPayload === 'object'
            ? { ...(claimPayload as Record<string, unknown>), profileCard }
            : { value: claimPayload, profileCard };
      }

      const issuer = await identitiesRepo.findByUuid(db, body.issuerIdentityUuid);
      const subject = await identitiesRepo.findByUuid(db, body.subjectIdentityUuid);
      if (!issuer || !subject) {
        return reply.code(404).send({ error: { message: 'issuer or subject identity not found' } });
      }
      const uuid = await credentialsRepo.create(db, {
        vcType: body.vcType,
        issuerIdentityUuid: issuer.uuid,
        subjectIdentityUuid: subject.uuid,
        claim: claimPayload !== undefined ? JSON.stringify(claimPayload) : undefined,
        status,
        thresholdRequired: threshold,
        validFrom,
        validUntil: body.validUntil,
      });

      const credential = await credentialsRepo.findByUuid(db, uuid);
      return reply.code(201).send(credential);
    },
  );


  app.get('/credentials', async (req: FastifyRequest<{ Querystring: ListQuery }>, _reply: FastifyReply) => {
    const { subjectUuid, issuerUuid, vcType } = req.query;

    return credentialsRepo.list(db, { subjectUuid, issuerUuid, vcType });
  });

  app.get('/credentials/:uuid', async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
    const uuid = req.params.uuid;
    const credential = await credentialsRepo.findByUuid(db, uuid);
    if (!credential) {
      return reply.code(404).send({ error: { message: `credential ${uuid} not found` } });
    }
    return credential;
  });

  // -------------------------------------------------------------------------
  // POST /credentials/:id/signatures — add a co-signer signature
  // -------------------------------------------------------------------------
  app.post(
    '/credentials/:uuid/signatures',
    async (req: FastifyRequest<{ Params: { uuid: string }; Body: AddSignatureBody }>, reply: FastifyReply) => {
      const credentialUuid = req.params.uuid;
      const body = req.body;
      if (!credentialUuid || !body?.signerIdentityUuid || !body?.signature) {
        return reply
          .code(400)
          .send({ error: { message: 'uuid (param), signerIdentityUuid, and signature are required' } });
      }

      const credential = await credentialsRepo.findByUuid(db, credentialUuid);
      if (!credential) {
        return reply.code(404).send({ error: { message: `credential ${credentialUuid} not found` } });
      }
      if (credential.status !== 'pending_signatures') {
        return reply
          .code(409)
          .send({ error: { message: `credential ${credentialUuid} is not awaiting signatures (status=${credential.status})` } });
      }
      if (!await identitiesRepo.findByUuid(db, body.signerIdentityUuid)) {
        return reply.code(404).send({ error: { message: `signer identity ${body.signerIdentityUuid} not found` } });
      }
      const signerDid = body.signerDidDocumentUuid !== undefined
        ? await didDocumentsRepo.findByUuid(db, body.signerDidDocumentUuid)
        : undefined;
      if (body.signerDidDocumentUuid !== undefined && !signerDid) {
        return reply.code(404).send({ error: { message: `did_document ${body.signerDidDocumentUuid} not found` } });
      }
      const signerIdentity = await identitiesRepo.findByUuid(db, body.signerIdentityUuid);
      if (await credentialSignaturesRepo.findBySignerForCredential(db, credential.uuid, signerIdentity!.uuid)) {
        return reply
          .code(409)
          .send({ error: { message: `identity ${body.signerIdentityUuid} has already signed credential ${credentialUuid}` } });
      }

      await credentialSignaturesRepo.create(db, {
        credentialUuid: credential.uuid,
        signerIdentityUuid: signerIdentity!.uuid,
        signerDidDocumentUuid: signerDid?.uuid,
        signature: Buffer.from(body.signature, 'base64'),
      });

      const count = await credentialSignaturesRepo.countForCredential(db, credential.uuid);
      if (credential.thresholdRequired !== null && count >= credential.thresholdRequired) {
        await credentialsRepo.updateStatus(db, credential.uuid, 'issued');
      }

      return reply.code(201).send({
        credential: await credentialsRepo.findByUuid(db, credential.uuid),
        signatures: await credentialSignaturesRepo.findForCredential(db, credential.uuid),
      });
    },
  );

  app.get(
    '/credentials/:uuid/signatures',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const credentialUuid = req.params.uuid;
      const credential = await credentialsRepo.findByUuid(db, credentialUuid);
      if (!credential) {
        return reply.code(404).send({ error: { message: `credential ${credentialUuid} not found` } });
      }
      return credentialSignaturesRepo.findForCredential(db, credential.uuid);
    },
  );

  app.post(
    '/credentials/:uuid/verify',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const credentialUuid = req.params.uuid;

      const credential = await credentialsRepo.findByUuid(db, credentialUuid);
      if (!credential) {
        return reply.code(404).send({ error: { message: `credential ${credentialUuid} not found` } });
      }

      // --- Check expiry ---
      const now = Math.floor(Date.now() / 1000);
      if (credential.validUntil !== null && credential.validUntil < now) {
        const result: VerifyResult = {
          valid: false,
          reason: `Credential expired at ${new Date(credential.validUntil * 1000).toISOString()}`,
          signatureResults: [],
        };
        return result;
      }

      // --- Check status ---
      if (credential.status === 'revoked') {
        const result: VerifyResult = {
          valid: false,
          reason: 'Credential has been revoked',
          signatureResults: [],
        };
        return result;
      }

      if (credential.status === 'expired') {
        const result: VerifyResult = {
          valid: false,
          reason: 'Credential has expired',
          signatureResults: [],
        };
        return result;
      }

      // --- Check signatures ---
      const signatures = await credentialSignaturesRepo.findForCredential(db, credential.uuid);
      const threshold = credential.thresholdRequired ?? 1;

      if (signatures.length === 0 && threshold > 0) {
        const result: VerifyResult = {
          valid: false,
          reason: `No signatures found (threshold: ${threshold})`,
          signatureResults: [],
        };
        return result;
      }

      // Construct the message to verify: the credential's signed payload
      // Use the credential's identity + claim as the signed message context
      const signedPayload = new TextEncoder().encode(
        JSON.stringify({
          vcType: credential.vcType,
          issuerIdentityUuid: credential.issuerIdentityUuid,
          subjectIdentityUuid: credential.subjectIdentityUuid,
          claim: credential.claim,
        }),
      );

      const signatureResults: SignatureResult[] = [];
      let validCount = 0;
      let invalidCount = 0;
      let indeterminateCount = 0;

      for (const sig of signatures) {
        const signerIdentity = await identitiesRepo.findByUuid(db, sig.signerIdentityUuid);
        const signerName = signerIdentity?.name ?? `identity ${sig.signerIdentityUuid.slice(0, 8)}`;

        const sigValid = await verifySignature(
          db,
          signerIdentity?.uuid ?? '',
          sig.signerDidDocumentUuid,
          sig.signature,
          signedPayload,
        );

        signatureResults.push({
          signerIdentityUuid: sig.signerIdentityUuid,
          signerName,
          valid: sigValid,
        });

        // F-031: three outcomes, kept apart. `null` means the verifier could not
        // obtain a verdict (no key for the signer locally), which is NOT a failed
        // verification and must not be reported as one.
        if (sigValid === true) validCount++;
        else if (sigValid === false) invalidCount++;
        else indeterminateCount++;
      }

      const thresholdMet = validCount >= threshold;
      // "Could not check" only when nothing was actually proven invalid.
      const indeterminate = !thresholdMet && invalidCount === 0 && indeterminateCount > 0;

      // Build reason — the counts decide the wording, so an operator reading one
      // line can tell a forgery from a missing key.
      let reason: string;
      if (thresholdMet) {
        reason = `${validCount} of ${threshold} required signature(s) verified`;
      } else if (indeterminate) {
        reason =
          `Could not verify: none of the ${indeterminateCount} signature(s) could be checked — ` +
          'no locally-known key for the signer(s). Indeterminate, not invalid.';
      } else if (invalidCount > 0 && indeterminateCount > 0) {
        reason =
          `Only ${validCount} of ${threshold} required signature(s) verified — ` +
          `${invalidCount} invalid, ${indeterminateCount} could not be checked (no local key)`;
      } else if (invalidCount > 0) {
        reason =
          `Only ${validCount} of ${threshold} required signature(s) verified — ${invalidCount} invalid`;
      } else {
        reason = `Only ${validCount} of ${threshold} required signature(s) verified — threshold not met`;
      }

      const result: VerifyResult = {
        valid: thresholdMet,
        indeterminate,
        signatureCounts: { valid: validCount, invalid: invalidCount, indeterminate: indeterminateCount },
        reason,
        signatureResults,
      };
      return result;
    },
  );

  // -------------------------------------------------------------------------
  // POST /credentials/:id/revoke — flip a status_list bit + set status='revoked'
  // -------------------------------------------------------------------------
  app.post(
    '/credentials/:uuid/revoke',
    async (req: FastifyRequest<{ Params: { uuid: string }; Body: RevokeBody }>, reply: FastifyReply) => {
      const credentialUuid = req.params.uuid;
      const credential = await credentialsRepo.findByUuid(db, credentialUuid);
      if (!credential) {
        return reply.code(404).send({ error: { message: `credential ${credentialUuid} not found` } });
      }
      if (credential.status === 'revoked') {
        return reply.code(409).send({ error: { message: `credential ${credentialUuid} is already revoked` } });
      }

      let statusListUuid = credential.statusListUuid;
      let statusListIndex = credential.statusListIndex;

      if (statusListUuid === null) {
        let statusList = await statusListsRepo.findForCommunity(db, credential.issuerIdentityUuid, 'revocation');
        if (!statusList) {
          const issuer = await identitiesRepo.findByUuid(db, credential.issuerIdentityUuid);
          if (!issuer) {
            return reply.code(404).send({ error: { message: `issuer identity ${credential.issuerIdentityUuid} not found` } });
          }
          const newUuid = await statusListsRepo.create(db, {
            communityIdentityUuid: issuer.uuid,
            purpose: 'revocation',
          });
          statusList = await statusListsRepo.findByUuid(db, newUuid);
        }
        statusListUuid = statusList!.uuid;
        statusListIndex = await statusListsRepo.allocateNextIndex(db, statusListUuid);
        await credentialsRepo.setStatusListSlot(db, credentialUuid, statusListUuid, statusListIndex);
      }

      const statusListRow = await statusListsRepo.findByUuid(db, statusListUuid!);
      await statusListsRepo.flip(db, {
        statusListUuid: statusListRow!.uuid,
        slotIndex: statusListIndex!,
        value: 1,
        reason: req.body?.reason,
      });

      await credentialsRepo.updateStatus(db, credentialUuid, 'revoked');
      return credentialsRepo.findByUuid(db, credentialUuid);
    },
  );
}