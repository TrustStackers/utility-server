/**
 * Route-level tests for the VTC invite → join path (H10).
 *
 * Why this file exists: G2d unified invite BUILDING in
 * `src/relationship/vtc-invite.ts` and covered it with 7 unit tests, but the three
 * REST consumers in `utility-server/src/routes/layer5-applications/vtc-invite.ts`
 * were exercised by NOTHING (the graph reports `consumers: []` for all three, with
 * no runtime evidence to fall back on). These routes are the user-visible
 * membership path — a regression there stays silent until a real invite fails —
 * and they are the only place the packed legacy `peerId` field is unpacked.
 *
 * Covered:
 *   - POST /vtcs/:uuid/invite        — the producer (legacy token + connectionOobi)
 *   - POST /vtcs/decode-invite       — reports communityDid / serverDid / peerId
 *   - POST /vtcs/:uuid/join          — accepts a legacy token; refuses a foreign one
 *   - POST /vtcs/join-by-invite      — legacy token joins; a connection-only OOBI is
 *                                      explained, not mistaken for a parse failure
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs --test test/routes/vtc-invite.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify, { type FastifyInstance } from 'fastify';
import type { Libp2p } from 'libp2p';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as keysRepo from '@p2p-trust-stack/core/db/repositories/keys-repo.js';
import { encryptSecretKey } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
import { generateEd25519KeyPair } from '@p2p-trust-stack/core/crypto/primitives.js';
import { COMMUNITY_KEY_PASSPHRASE } from '@p2p-trust-stack/core/services/did-manager.js';
import { buildVtcInvite } from '@p2p-trust-stack/core/relationship/vtc-invite.js';
import { registerVtcInviteRoutes } from '../../src/routes/layer5-applications/vtc-invite.js';
import { setServerNodeDid, setServerNodeInfo } from '../../src/services/server-node-info.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

const COMMUNITY_DID = 'did:scid:vh:1:zTestCommunityDidForInvites';
const OTHER_COMMUNITY_DID = 'did:scid:vh:1:zSomeOtherCommunityDid';
const MEMBER_DID = 'did:scid:vh:1:zTestMemberDidForInvites';
const SERVER_DID = 'did:scid:vh:1:zTestServerDidForInvites';
const PEER_ID = '12D3KooWTestServerPeerForInvites';

/** The minimum of a libp2p node the invite producer touches. */
function nodeStub(): Libp2p {
  return {
    peerId: { toString: () => PEER_ID },
    getMultiaddrs: () => [{ toString: () => `/ip4/127.0.0.1/tcp/4001/p2p/${PEER_ID}` }],
  } as unknown as Libp2p;
}

interface Seeded {
  app: FastifyInstance;
  ds: SqliteDataSource;
  communityUuid: string;
  memberUuid: string;
}

/**
 * A server with the invite routes, a migrated DB, a community that really holds a
 * decryptable signing key (so the producer reports a real VID rather than the
 * all-zero fallback), and a member identity to join with.
 */
async function seed(): Promise<Seeded> {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);

  // Community with a real signing key (same shape createVtc() persists).
  const communityUuid = generateUuid();
  await identitiesRepo.create(ds, {
    uuid: communityUuid, realDid: COMMUNITY_DID, role: 'vtc', subjectKind: 'organization',
    custody: 'local', name: 'Test VTC', recordedByNode: 'test',
  });
  const docUuid = await didDocumentsRepo.create(ds, {
    identityUuid: communityUuid, did: COMMUNITY_DID, method: 'did:scid:vh',
    documentJson: JSON.stringify({ id: COMMUNITY_DID }), isPrimary: true, recordedByNode: 'test',
  });
  const signing = generateEd25519KeyPair();
  const encrypted = await encryptSecretKey(signing.secretKey, COMMUNITY_KEY_PASSPHRASE);
  await keysRepo.createWithSecret(ds, {
    identityUuid: communityUuid, didDocumentUuid: docUuid, keyType: 'ed25519',
    publicKey: signing.publicKey, encryptedSecretKey: encrypted.ciphertext,
    salt: encrypted.salt, nonce: encrypted.nonce, authTag: encrypted.authTag,
  });

  // The prospective member (a VTA — the identities table constrains role to vta/vtc/vtn).
  // Its DID document matters: `findByRealDid` (used by join-by-invite) JOINs
  // did_documents, while `findByUuid` (used by /vtcs/:uuid/join) does not — so an
  // identity with no document is reachable by one route and not the other.
  const memberUuid = generateUuid();
  await identitiesRepo.create(ds, {
    uuid: memberUuid, realDid: MEMBER_DID, role: 'vta', custody: 'local',
    name: 'Member', recordedByNode: 'test',
  });
  await didDocumentsRepo.create(ds, {
    identityUuid: memberUuid, did: MEMBER_DID, method: 'did:scid:vh',
    documentJson: JSON.stringify({ id: MEMBER_DID }), isPrimary: true, recordedByNode: 'test',
  });

  // The server's own DID, which a connection-only OOBI is addressed to.
  setServerNodeInfo(PEER_ID, [`/ip4/127.0.0.1/tcp/4001/p2p/${PEER_ID}`]);
  setServerNodeDid(SERVER_DID);

  const app = Fastify();
  registerVtcInviteRoutes(app, ds, nodeStub());
  await app.ready();

  return { app, ds, communityUuid, memberUuid };
}

/** Produce the two invite artifacts from the route itself (the real producer). */
async function issueInvite(s: Seeded): Promise<{ invite: string; connectionOobi: string }> {
  const res = await s.app.inject({
    method: 'POST',
    url: `/vtcs/${s.communityUuid}/invite`,
    payload: {},
  });
  assert.equal(res.statusCode, 200, `invite production failed: ${res.body}`);
  const body = res.json() as { invite: string; connectionOobi: string; communityDid: string };
  assert.equal(body.communityDid, COMMUNITY_DID);
  return body;
}

// ---------------------------------------------------------------------------
// Producer
// ---------------------------------------------------------------------------

test('POST /vtcs/:uuid/invite returns both artifacts, legacy token first', async () => {
  const s = await seed();
  const { invite, connectionOobi } = await issueInvite(s);

  // The legacy token and the dialable OOBI are both CESR group frames.
  assert.ok(invite.startsWith('-TA'), `legacy token must be a CESR group frame, got "${invite.slice(0, 8)}"`);
  assert.ok(connectionOobi.startsWith('-TA'), 'connectionOobi must be a CESR group frame');
  assert.notEqual(invite, connectionOobi, 'the two artifacts address different identities');

  await s.app.close();
});

// ---------------------------------------------------------------------------
// decode-invite
// ---------------------------------------------------------------------------

test('POST /vtcs/decode-invite unpacks a legacy token (community DID + plain peerId)', async () => {
  const s = await seed();
  const { invite } = await issueInvite(s);

  const res = await s.app.inject({ method: 'POST', url: '/vtcs/decode-invite', payload: { invite } });
  assert.equal(res.statusCode, 200, res.body);
  const body = res.json() as { communityDid: string | null; serverPeerId: string; serverDid: string };

  assert.equal(body.communityDid, COMMUNITY_DID, 'the legacy token names its community');
  // The producer packs "<communityDid>|<peerId>" into the peer field; the route must
  // hand back the PLAIN peerId, because a libp2p dial of the packed form fails.
  assert.equal(body.serverPeerId, PEER_ID, 'the packed peer field must be unpacked');
  // Documented behaviour: for the legacy token `serverDid` is the community DID
  // (that token predates the server-addressed form).
  assert.equal(body.serverDid, COMMUNITY_DID);

  await s.app.close();
});

test('POST /vtcs/decode-invite reports the SERVER did for a connection-only OOBI', async () => {
  const s = await seed();
  const { connectionOobi } = await issueInvite(s);

  const res = await s.app.inject({ method: 'POST', url: '/vtcs/decode-invite', payload: { invite: connectionOobi } });
  assert.equal(res.statusCode, 200, res.body);
  const body = res.json() as { communityDid: string | null; serverDid: string; serverPeerId: string };

  assert.equal(body.communityDid, null, 'a connection OOBI carries no community reference');
  assert.equal(body.serverDid, SERVER_DID, 'the OOBI must be addressed to the node the peerId reaches');
  assert.equal(body.serverPeerId, PEER_ID);

  await s.app.close();
});

test('POST /vtcs/decode-invite answers 400 for a malformed token (no crash)', async () => {
  const s = await seed();

  const res = await s.app.inject({ method: 'POST', url: '/vtcs/decode-invite', payload: { invite: 'not-a-cesr-token' } });
  assert.equal(res.statusCode, 400);
  assert.ok((res.json() as { error: { message: string } }).error.message.length > 0);

  await s.app.close();
});

// ---------------------------------------------------------------------------
// join — admission presentation (audit F-026 / decision F-001b)
// ---------------------------------------------------------------------------

test('F-001b: UNDER ENFORCE a join with no presentation is REFUSED and creates nothing', async () => {
  const s = await seed();
  const { invite } = await issueInvite(s);

  const prev = process.env.TSP_MEMBERSHIP_PRESENTATION_POLICY;
  process.env.TSP_MEMBERSHIP_PRESENTATION_POLICY = 'enforce';
  try {
    const res = await s.app.inject({
      method: 'POST',
      url: `/vtcs/${s.communityUuid}/join`,
      payload: { memberIdentityUuid: s.memberUuid, invite },
    });

    // Before F-001b this returned 201: admission required no proof of any kind.
    assert.equal(res.statusCode, 403, res.body);
    const body = res.json() as { admission?: { verdict: string; policy: string } };
    assert.equal(body.admission?.verdict, 'absent');
    assert.equal(body.admission?.policy, 'enforce');

    // Nothing was created — the refusal is not cosmetic. Queried directly so the
    // assertion does not depend on the list route's response envelope.
    const rows = await s.ds.all<{ uuid: string }>(
      'SELECT uuid FROM memberships WHERE member_identity_uuid = ? AND community_identity_uuid = ?',
      s.memberUuid, s.communityUuid,
    );
    assert.equal(rows.length, 0, 'a refused admission leaves no membership row behind');
  } finally {
    if (prev === undefined) delete process.env.TSP_MEMBERSHIP_PRESENTATION_POLICY;
    else process.env.TSP_MEMBERSHIP_PRESENTATION_POLICY = prev;
  }
});

test('F-001b: UNDER THE DEFAULT (warn) the join is admitted and the verdict is REPORTED', async () => {
  const s = await seed();
  const { invite } = await issueInvite(s);

  const prev = process.env.TSP_MEMBERSHIP_PRESENTATION_POLICY;
  delete process.env.TSP_MEMBERSHIP_PRESENTATION_POLICY;
  try {
    const res = await s.app.inject({
      method: 'POST',
      url: `/vtcs/${s.communityUuid}/join`,
      payload: { memberIdentityUuid: s.memberUuid, invite },
    });

    assert.equal(res.statusCode, 201, res.body);
    const body = res.json() as { status: string; admission?: { policy: string; verdict: string } };
    assert.equal(body.status, 'pending', 'behaviour is unchanged for deployments that have not opted in');
    // …but the admission now SAYS whether it was proven, instead of the caller having to
    // infer it from the policy value.
    assert.equal(body.admission?.policy, 'warn');
    assert.equal(body.admission?.verdict, 'absent');
  } finally {
    if (prev !== undefined) process.env.TSP_MEMBERSHIP_PRESENTATION_POLICY = prev;
  }
});

// ---------------------------------------------------------------------------
// join — the legacy token is accepted; a foreign one is refused with a reason
// ---------------------------------------------------------------------------

test('POST /vtcs/:uuid/join ACCEPTS a legacy token and creates a pending membership', async () => {
  const s = await seed();
  const { invite } = await issueInvite(s);

  const res = await s.app.inject({
    method: 'POST',
    url: `/vtcs/${s.communityUuid}/join`,
    payload: { memberIdentityUuid: s.memberUuid, invite },
  });

  assert.equal(res.statusCode, 201, res.body);
  const body = res.json() as { status: string; role?: string };
  assert.equal(body.status, 'pending', 'a join is a PENDING membership, not an active one');

  // And a second attempt is refused as a duplicate rather than silently re-adding.
  const again = await s.app.inject({
    method: 'POST',
    url: `/vtcs/${s.communityUuid}/join`,
    payload: { memberIdentityUuid: s.memberUuid, invite },
  });
  assert.equal(again.statusCode, 409);
  assert.match((again.json() as { error: { message: string } }).error.message, /already has a membership/);

  await s.app.close();
});

test('POST /vtcs/:uuid/join REFUSES an invite that names a different community', async () => {
  const s = await seed();
  // A structurally valid legacy token, but for someone else's community: the whole
  // point of the cross-check is to catch "pasted the wrong VTC's invite" BEFORE a
  // membership row exists.
  const foreign = buildVtcInvite({
    communityDid: OTHER_COMMUNITY_DID,
    serverDid: SERVER_DID,
    vid: 'D'.repeat(44),
    peerId: PEER_ID,
    multiaddrs: [],
  }).invite;

  const res = await s.app.inject({
    method: 'POST',
    url: `/vtcs/${s.communityUuid}/join`,
    payload: { memberIdentityUuid: s.memberUuid, invite: foreign },
  });

  assert.equal(res.statusCode, 409);
  const message = (res.json() as { error: { message: string } }).error.message;
  assert.match(message, /invite is for community DID/);
  assert.match(message, new RegExp(OTHER_COMMUNITY_DID.slice(0, 24)), 'the refusal names the offending DID');

  await s.app.close();
});

// ---------------------------------------------------------------------------
// join-by-invite
// ---------------------------------------------------------------------------

test('POST /vtcs/join-by-invite joins with a legacy token', async () => {
  const s = await seed();
  const { invite } = await issueInvite(s);

  const res = await s.app.inject({
    method: 'POST',
    url: '/vtcs/join-by-invite',
    payload: { invite, memberDid: MEMBER_DID, role: 'member' },
  });

  assert.equal(res.statusCode, 201, res.body);
  assert.equal((res.json() as { status: string }).status, 'pending');

  await s.app.close();
});

test('POST /vtcs/join-by-invite EXPLAINS a connection-only OOBI instead of failing to parse it', async () => {
  const s = await seed();
  const { connectionOobi } = await issueInvite(s);

  // This is the assertion the plan asks for: the connection OOBI parses FINE — it
  // simply cannot name a community — so the operator must get the route to use,
  // not a parse error that reads like a corrupt invite.
  const res = await s.app.inject({
    method: 'POST',
    url: '/vtcs/join-by-invite',
    payload: { invite: connectionOobi, memberDid: MEMBER_DID },
  });

  assert.equal(res.statusCode, 400);
  const message = (res.json() as { error: { message: string } }).error.message;
  assert.match(message, /does not name a community/);
  assert.match(message, /connection-only OOBI/);
  assert.match(message, /POST \/vtcs\/:uuid\/join/, 'the error must name the route that DOES work');

  await s.app.close();
});

test('POST /vtcs/join-by-invite answers 404 when the member is unknown on this server', async () => {
  const s = await seed();
  const { invite } = await issueInvite(s);

  const res = await s.app.inject({
    method: 'POST',
    url: '/vtcs/join-by-invite',
    payload: { invite, memberDid: 'did:scid:vh:1:zNobodyHere' },
  });

  assert.equal(res.statusCode, 404);
  assert.match(
    (res.json() as { error: { message: string } }).error.message,
    /not found — register the VTA on this server first/,
    'the remedy must be part of the message',
  );

  await s.app.close();
});


