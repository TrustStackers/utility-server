// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * resolver-html — the human-readable (browser) representation of the public
 * DID resolution surface.
 *
 * Served only when the client asks for it (`Accept: text/html`, which browsers
 * send, or `?format=html`). Programmatic clients keep getting the JSON
 * representation, so nothing here affects machine consumers.
 *
 * Everything is inline (CSS + the small clipboard script) — no external assets,
 * no CDN, no build step, matching the rest of this repo.
 */

import type { DidResolutionReport } from '@p2p-trust-stack/core/did/did-resolution-service.js';
import type { DidDocument, VerificationMethod } from '@p2p-trust-stack/core/did/types.js';

/** HTML-escape a value for safe interpolation into markup. */
function esc(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const STYLE = `
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1rem 4rem;font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
     background:#f6f7f9;color:#14171a}
@media(prefers-color-scheme:dark){body{background:#0f1115;color:#e6e8eb}}
main{max-width:960px;margin:0 auto}
h1{font-size:1.35rem;margin:0 0 .25rem}
h2{font-size:1rem;margin:1.75rem 0 .5rem;text-transform:uppercase;letter-spacing:.04em;opacity:.7}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.86em;
     background:rgba(127,127,127,.14);padding:.1em .35em;border-radius:4px;word-break:break-all}
a{color:#2563eb}
.card{background:#fff;border:1px solid rgba(127,127,127,.22);border-radius:10px;padding:1rem 1.15rem;margin:.75rem 0}
@media(prefers-color-scheme:dark){.card{background:#161a20}}
.muted{opacity:.65}
.small{font-size:.85rem}
.badge{display:inline-block;font-size:.75rem;font-weight:600;padding:.15em .6em;border-radius:999px;
       border:1px solid rgba(127,127,127,.35);margin-right:.35rem;vertical-align:middle}
.badge.good{background:rgba(22,163,74,.16);border-color:rgba(22,163,74,.5);color:#15803d}
.badge.warn{background:rgba(217,119,6,.16);border-color:rgba(217,119,6,.5);color:#b45309}
.badge.bad{background:rgba(220,38,38,.16);border-color:rgba(220,38,38,.5);color:#b91c1c}
@media(prefers-color-scheme:dark){.badge.good{color:#4ade80}.badge.warn{color:#fbbf24}.badge.bad{color:#f87171}}
.did{font-size:1.02rem;font-weight:600;word-break:break-all;margin:.35rem 0 .6rem}
.row{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center}
button{font:inherit;padding:.4rem .8rem;border-radius:8px;border:1px solid rgba(127,127,127,.4);
       background:transparent;color:inherit;cursor:pointer}
button:hover{border-color:#2563eb;color:#2563eb}
input{font:inherit;padding:.55rem .7rem;border-radius:8px;border:1px solid rgba(127,127,127,.4);
      background:transparent;color:inherit;width:100%}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid rgba(127,127,127,.18);vertical-align:top}
th{font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;opacity:.6;font-weight:600}
td.key code{white-space:nowrap}
.svc{padding:.5rem 0;border-bottom:1px solid rgba(127,127,127,.14)}
.svc ul{margin:.3rem 0 0;padding-left:1.1rem}
.svc li{font-size:.85rem}
ol.timeline{list-style:none;margin:.25rem 0;padding:0}
ol.timeline li{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;padding:.4rem 0;
               border-bottom:1px solid rgba(127,127,127,.14)}
ol.timeline .v{font-weight:700;min-width:2.4rem}
.links{margin-top:1.25rem}
form.card{display:flex;flex-direction:column;gap:.6rem}
`;

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>${STYLE}</style></head>
<body><main>${body}</main></body></html>`;
}

/** The landing page: a DID entry form (for a human arriving at the resolver root). */
export function renderLandingPage(): string {
  return page(
    'did:scid:vh Resolver',
    `<h1>did:scid:vh Resolver</h1>
<p class="muted">Resolve a <code>did:scid:vh</code> (or <code>did:peer:4</code>) DID to its DID document.</p>
<form id="f" class="card">
  <label for="did" class="small muted">DID</label>
  <input id="did" name="did" placeholder="did:scid:vh:1:…" autofocus spellcheck="false" autocomplete="off">
  <div class="row"><button type="submit">Resolve</button></div>
</form>
<p class="muted small">Example:
  <code>did:scid:vh:1:6Mkr6cy8emkvrxxEdW2rBfGv61cPpZxHmrBmEFXJS6LyPJ2</code></p>
<script>
document.getElementById('f').addEventListener('submit', function (e) {
  e.preventDefault();
  var v = document.getElementById('did').value.trim();
  if (v) location.href = '/1.0/identifiers/' + encodeURIComponent(v);
});
</script>`,
  );
}

// ---------------------------------------------------------------------------
// Resolution page
// ---------------------------------------------------------------------------

/** Best-effort algorithm label from a verification method's id + multibase prefix. */
function algorithmOf(vm: VerificationMethod): string {
  if (vm.type === 'MLKEM768X25519PublicKey') return 'MLKEM768-X25519 (PQ)';
  if (vm.id === '#key-mldsa') return 'ML-DSA-65 (PQ)';
  const k = vm.publicKeyMultibase ?? '';
  if (k.startsWith('z6Mk')) return 'Ed25519';
  if (k.startsWith('z6LS')) return 'X25519';
  return vm.type;
}

/** Truncate a long key for display (the full value stays in the raw JSON). */
function shortKey(key: string | undefined): string {
  const k = key ?? '';
  return k.length > 28 ? `${k.slice(0, 24)}…${k.slice(-4)}` : k;
}

function hex(bytes: Uint8Array | undefined): string {
  if (!bytes) return '';
  return Buffer.from(bytes).toString('hex');
}

/** Which verification relationships reference this method id. */
function relationshipOf(doc: DidDocument, id: string): string {
  const rels: string[] = [];
  if ((doc.authentication ?? []).includes(id)) rels.push('authentication');
  if ((doc.assertionMethod ?? []).includes(id)) rels.push('assertionMethod');
  if ((doc.keyAgreement ?? []).includes(id)) rels.push('keyAgreement');
  return rels.length > 0 ? rels.join(', ') : '—';
}

/**
 * Render a resolution report as an annotated HTML page.
 *
 * The annotations that matter to a third party are called out deliberately: a
 * status badge, a provenance badge (verified log vs. cached snapshot), an
 * `authorized for` column per key, and the rotation timeline with witness
 * attestation counts.
 */
export function renderResolutionPage(report: DidResolutionReport): string {
  const { result, source } = report;
  const doc = result.didDocument;
  const error = result.didResolutionMetadata.error;

  if (error || !doc) {
    return page(
      'DID not resolved',
      `<div class="card">
  <h1><span class="badge bad">not resolved</span></h1>
  <p class="did">${esc(report.did)}</p>
  <p class="muted">Reason: <code>${esc(error ?? 'notFound')}</code></p>
  <p class="links"><a href="/">← Resolve another DID</a></p>
</div>`,
    );
  }

  const meta = result.didDocumentMetadata;
  const name = (doc.alsoKnownAs ?? [])[0];

  const statusBadge = meta.deactivated
    ? '<span class="badge bad">deactivated</span>'
    : '<span class="badge good">resolved</span>';
  const cacheReason = result.didResolutionMetadata.cacheReason;
  const sourceBadge =
    source === 'log'
      ? '<span class="badge good">verified rotation log</span>'
      : source === 'offline'
        ? '<span class="badge">self-contained (did:peer:4)</span>'
        : `<span class="badge warn">cached snapshot — ${
            cacheReason === 'chain-invalid'
              ? 'rotation log held but chain invalid'
              : 'no rotation log held here'
          }</span>`;

  const summaryBits: string[] = [];
  if (name) summaryBits.push(`<strong>${esc(name)}</strong>`);
  if (meta.versionId !== undefined) summaryBits.push(`version ${esc(meta.versionId)}`);
  if (meta.updated) summaryBits.push(`updated ${esc(meta.updated)}`);
  if (meta.witnessAttested) summaryBits.push('witness-attested');

  const methodRows = (doc.verificationMethod ?? [])
    .map(
      (vm) => `<tr>
    <td><code>${esc(vm.id)}</code></td>
    <td>${esc(vm.type)}</td>
    <td>${esc(algorithmOf(vm))}</td>
    <td>${esc(relationshipOf(doc, vm.id))}</td>
    <td class="key"><code>${esc(shortKey(vm.publicKeyMultibase))}</code></td>
  </tr>`,
    )
    .join('');

  const serviceBlocks =
    (doc.service ?? [])
      .map((s) => {
        const ep = s.serviceEndpoint;
        const detail =
          typeof ep === 'string'
            ? `<div><code>${esc(ep)}</code></div>`
            : `<div>peerId: <code>${esc(ep.peerId)}</code></div>` +
              ((ep.multiaddrs ?? []).length > 0
                ? `<ul>${(ep.multiaddrs ?? []).map((m) => `<li><code>${esc(m)}</code></li>`).join('')}</ul>`
                : '');
        return `<div class="svc"><div><code>${esc(s.id)}</code> · ${esc(s.type)}</div>${detail}</div>`;
      })
      .join('') || '<p class="muted">No service endpoints published.</p>';

  const log = report.log ?? [];
  const history =
    log.length > 0
      ? `<ol class="timeline">${[...log]
          .reverse()
          .map((e) => {
            const att = report.attestationsByVersion[e.version] ?? 0;
            const attBadge =
              att > 0
                ? `<span class="badge good">${att} witness attestation${att === 1 ? '' : 's'}</span>`
                : e.version === 0
                  ? '<span class="badge">genesis</span>'
                  : '<span class="muted small">no attestations</span>';
            return `<li>
    <span class="v">v${e.version}</span>
    <span class="muted small">${esc(new Date(e.createdAt * 1000).toISOString())}</span>
    <code>${esc(hex(e.digest).slice(0, 12))}…</code>
    ${attBadge}
    ${e.mlDsa65Signature ? '<span class="badge">PQ-signed</span>' : ''}
  </li>`;
          })
          .join('')}</ol>`
      : '<p class="muted">Rotation log not available on this server (document served from a cached snapshot).</p>';

  const scid = report.did.split(':').pop() ?? '';
  const jsonHref = `/1.0/identifiers/${encodeURIComponent(report.did)}?format=json`;
  const logHref = log.length > 0 ? `/log/${encodeURIComponent(scid)}/did.jsonl` : null;

  return page(
    report.did,
    `<div class="card">
  <div>${statusBadge}${sourceBadge}</div>
  <div class="did">${esc(report.did)}</div>
  <div class="muted small">${summaryBits.join(' · ') || '&nbsp;'}</div>
  <div class="row" style="margin-top:.75rem">
    <button type="button" data-copy="${esc(report.did)}">Copy DID</button>
    ${logHref ? `<a href="${logHref}"><button type="button">Download did.jsonl</button></a>` : ''}
    <a href="${jsonHref}"><button type="button">Raw JSON</button></a>
    <a href="/"><button type="button">Resolve another</button></a>
  </div>
</div>

<h2>Verification methods</h2>
<div class="card"><table>
  <thead><tr><th>id</th><th>type</th><th>algorithm</th><th>authorized for</th><th>key</th></tr></thead>
  <tbody>${methodRows}</tbody>
</table></div>

<h2>Service endpoints</h2>
<div class="card">${serviceBlocks}</div>

<h2>Rotation history</h2>
<div class="card">${history}</div>

<p class="links muted small">
  ${log.length > 0
    ? 'This document was reconstructed by replaying and verifying the rotation chain; each entry is signed by the previously-committed key.'
    : cacheReason === 'chain-invalid'
      ? 'A rotation log IS held for this DID here, but it did not validate — the document above is the cached copy. That indicates divergence or a partial write and is worth investigating.'
      : 'No rotation log has been sent to this server for this DID, so the document above is the cached copy and its chain cannot be verified here.'}
</p>
<script>
document.querySelectorAll('[data-copy]').forEach(function (b) {
  b.addEventListener('click', function () {
    navigator.clipboard.writeText(b.getAttribute('data-copy'));
    var t = b.textContent; b.textContent = 'Copied';
    setTimeout(function () { b.textContent = t; }, 1200);
  });
});
</script>`,
  );
}
