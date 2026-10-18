// Authoritative, pre-approved per-installation credential registry for the Relay.
// Neither bootstrap nor any client event may create or replace an approval.
import crypto from 'node:crypto';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SECRET_RE = /^[A-Za-z0-9_-]{32,128}$/;
const SHA256_B64URL_RE = /^[A-Za-z0-9_-]{43}$/;
const PLATFORMS = new Set(['ANDROID', 'WINDOWS']);

const digest = (secret) => crypto.createHash('sha256').update(secret, 'utf8').digest('base64url');

function sameHash(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (!SHA256_B64URL_RE.test(a) || !SHA256_B64URL_RE.test(b)) return false;
  const aa = Buffer.from(a, 'ascii');
  const bb = Buffer.from(b, 'ascii');
  return crypto.timingSafeEqual(aa, bb);
}

export function loadApprovedManagerBindings(json) {
  const approvals = new Map();
  if (json === undefined || json === null || json === '') return approvals;
  let entries;
  try { entries = JSON.parse(json); }
  catch { throw new Error('invalid_AUTSYS_MANAGER_BINDINGS_JSON'); }
  if (!entries || typeof entries !== 'object' || Array.isArray(entries)) {
    throw new Error('invalid_AUTSYS_MANAGER_BINDINGS_JSON');
  }
  for (const [installationId, entry] of Object.entries(entries)) {
    if (!UUID_RE.test(installationId) || !entry || typeof entry !== 'object' || Array.isArray(entry) ||
        !PLATFORMS.has(entry.platform) || !SHA256_B64URL_RE.test(entry.binding_sha256 || '')) {
      throw new Error('invalid_manager_binding_record');
    }
    const canonicalId = installationId.toLowerCase();
    if (approvals.has(canonicalId)) throw new Error('duplicate_manager_binding_record');
    approvals.set(canonicalId, Object.freeze({
      platform: entry.platform,
      binding_sha256: entry.binding_sha256
    }));
  }
  return approvals;
}

export function isApprovedManagerBinding(approvals, installationId, platform, bindingSecret) {
  if (typeof installationId !== 'string' || !UUID_RE.test(installationId) ||
      typeof bindingSecret !== 'string' || !SECRET_RE.test(bindingSecret)) return false;
  const expected = approvals.get(installationId.toLowerCase());
  return Boolean(expected && expected.platform === platform && sameHash(expected.binding_sha256, digest(bindingSecret)));
}

export function isApprovedManagerSession(approvals, payload, bindingSecret) {
  if (!payload || typeof payload !== 'object' ||
      typeof payload.binding_sha256 !== 'string' || !SHA256_B64URL_RE.test(payload.binding_sha256)) return false;
  const expected = typeof payload.installation_id === 'string' ? approvals.get(payload.installation_id.toLowerCase()) : null;
  if (!expected || expected.platform !== payload.platform || !sameHash(expected.binding_sha256, payload.binding_sha256)) return false;
  return isApprovedManagerBinding(approvals, payload.installation_id, payload.platform, bindingSecret);
}
