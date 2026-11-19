'use strict';

// Project-specific first-party macaroon-style capabilities. See CAPABILITY.md.
// This module never grants admission, dispatches work, or consumes a use budget.
const { createHash, createHmac, timingSafeEqual, X509Certificate } = require('node:crypto');

const SCHEMA = 'mikaya.act.capability.v1';
const VERSION = 1;
const PREFIX = 'mcap1.';
const MAX_TOKEN_BYTES = 4096;
const MAX_CAVEATS = 16;
const MAX_LIFETIME_MS = 120_000;
const ROOT_DOMAIN = 'MIKAYA-ACT-CAPABILITY-V1-ROOT\0';
const CAVEAT_DOMAIN = 'MIKAYA-ACT-CAPABILITY-V1-CAVEAT\0';
const CLAIM_KEYS = [
  'schema', 'version', 'issuer', 'issuerKeyId', 'audience', 'peer', 'keyBinding',
  'grantId', 'issuerEpoch', 'policyVersion', 'scopes', 'resources',
  'notBeforeMs', 'expiresAtMs', 'limits',
];
const STRING_FIELDS = ['issuer', 'issuerKeyId', 'audience', 'peer', 'grantId', 'policyVersion'];
const EQUALITY_FIELDS = new Set([...STRING_FIELDS, 'keyBinding', 'issuerEpoch']);
const LIMIT_FIELDS = new Set(['limits.uses', 'limits.maxBytes', 'limits.maxConcurrent']);

class CapabilityError extends Error {
  constructor(code) {
    super(`Capability denied (${code})`);
    this.name = 'CapabilityError';
    this.code = code;
  }
}

function deny(code) { throw new CapabilityError(code); }

function record(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) deny('CAP_INVALID');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) deny('CAP_INVALID');
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) deny('CAP_INVALID');
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) deny('CAP_INVALID');
  }
}

function identifier(value, max = 128) {
  if (typeof value !== 'string' || value.length < 1 || value.length > max ||
      !/^[A-Za-z0-9][A-Za-z0-9._:/@+\-]*$/.test(value)) deny('CAP_INVALID');
  return value;
}

function integer(value, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum || Object.is(value, -0)) deny('CAP_INVALID');
  return value;
}

function binding(value) {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value)) deny('CAP_INVALID');
  return value;
}

function stringSet(value, maxString = 128) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) deny('CAP_INVALID');
  for (const entry of value) identifier(entry, maxString);
  if (new Set(value).size !== value.length) deny('CAP_INVALID');
  // Sorted arrays have one representation in every conforming implementation.
  if (value.some((entry, index) => index > 0 && value[index - 1] >= entry)) deny('CAP_INVALID');
  return value;
}

function validateClaims(claims) {
  record(claims, CLAIM_KEYS);
  if (claims.schema !== SCHEMA || claims.version !== VERSION) deny('CAP_VERSION');
  for (const key of STRING_FIELDS) identifier(claims[key]);
  binding(claims.keyBinding);
  integer(claims.issuerEpoch);
  stringSet(claims.scopes);
  stringSet(claims.resources, 192);
  integer(claims.notBeforeMs);
  integer(claims.expiresAtMs);
  if (claims.expiresAtMs <= claims.notBeforeMs ||
      claims.expiresAtMs - claims.notBeforeMs > MAX_LIFETIME_MS) deny('CAP_TIME');
  record(claims.limits, ['uses', 'maxBytes', 'maxConcurrent']);
  integer(claims.limits.uses, 1);
  integer(claims.limits.maxBytes, 1);
  integer(claims.limits.maxConcurrent, 1);
}

function validateCaveat(caveat) {
  record(caveat, ['field', 'value']);
  const { field, value } = caveat;
  if (typeof field !== 'string') deny('CAP_INVALID');
  if (STRING_FIELDS.includes(field)) identifier(value);
  else if (field === 'keyBinding') binding(value);
  else if (field === 'issuerEpoch' || field === 'notBeforeMs' || field === 'expiresAtMs' || LIMIT_FIELDS.has(field)) integer(value);
  else if (field === 'scopes') stringSet(value);
  else if (field === 'resources') stringSet(value, 192);
  else deny('CAP_CAVEAT');
}

// Values reaching here have fixed, validated shapes: ASCII strings, safe
// nonnegative integers, sorted arrays and plain objects. This is not a general
// replacement for the existing federation's canonicalization protocol.
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function keyBytes(rootKey) {
  if (!(rootKey instanceof Uint8Array) || rootKey.byteLength < 32 || rootKey.byteLength > 64) deny('CAP_KEY');
  return Buffer.from(rootKey);
}

function mac(key, domain, value) {
  return createHmac('sha256', key).update(domain, 'ascii').update(canonical(value), 'utf8').digest();
}

function encode(envelope) {
  const result = PREFIX + Buffer.from(canonical(envelope), 'utf8').toString('base64url');
  if (Buffer.byteLength(result, 'utf8') > MAX_TOKEN_BYTES) deny('CAP_SIZE');
  return result;
}

function decode(token) {
  if (typeof token !== 'string') deny('CAP_INVALID');
  if (Buffer.byteLength(token, 'utf8') > MAX_TOKEN_BYTES) deny('CAP_SIZE');
  if (!token.startsWith(PREFIX)) deny('CAP_VERSION');
  const encoded = token.slice(PREFIX.length);
  if (!encoded || !/^[A-Za-z0-9_-]+$/.test(encoded)) deny('CAP_INVALID');
  const bytes = Buffer.from(encoded, 'base64url');
  if (bytes.toString('base64url') !== encoded) deny('CAP_INVALID');
  let envelope;
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) deny('CAP_INVALID');
  try { envelope = JSON.parse(text); } catch { deny('CAP_INVALID'); }
  record(envelope, ['claims', 'caveats', 'mac']);
  validateClaims(envelope.claims);
  if (!Array.isArray(envelope.caveats) || envelope.caveats.length > MAX_CAVEATS) deny('CAP_SIZE');
  for (const caveat of envelope.caveats) validateCaveat(caveat);
  if (typeof envelope.mac !== 'string' || !/^[0-9a-f]{64}$/.test(envelope.mac)) deny('CAP_INVALID');
  // Reject duplicate keys, alternate number spellings, whitespace, reordered
  // object keys, escaped aliases and any other ambiguous wire representation.
  if (canonical(envelope) !== text) deny('CAP_INVALID');
  return envelope;
}

function issue({ rootKey, claims, nowMs }) {
  integer(nowMs);
  validateClaims(claims);
  if (claims.expiresAtMs <= nowMs || claims.expiresAtMs - nowMs > MAX_LIFETIME_MS) deny('CAP_TIME');
  const signature = mac(keyBytes(rootKey), ROOT_DOMAIN, claims);
  return encode({ claims, caveats: [], mac: signature.toString('hex') });
}

function attenuate(token, caveats) {
  const envelope = decode(token);
  if (!Array.isArray(caveats) || caveats.length < 1 ||
      envelope.caveats.length + caveats.length > MAX_CAVEATS) deny('CAP_SIZE');
  let signature = Buffer.from(envelope.mac, 'hex');
  for (const caveat of caveats) {
    validateCaveat(caveat);
    signature = mac(signature, CAVEAT_DOMAIN, caveat);
    envelope.caveats.push(caveat);
  }
  // Attenuation cannot prove authenticity without the issuer's root key.
  // Verification is required at the resource server before any use.
  envelope.mac = signature.toString('hex');
  return encode(envelope);
}

function effectiveClaims(envelope) {
  const effective = JSON.parse(JSON.stringify(envelope.claims));
  for (const { field, value } of envelope.caveats) {
    if (EQUALITY_FIELDS.has(field)) {
      if (effective[field] !== value) deny('CAP_RESTRICTED');
    } else if (field === 'scopes' || field === 'resources') {
      effective[field] = effective[field].filter((entry) => value.includes(entry));
    } else if (field === 'notBeforeMs') {
      effective.notBeforeMs = Math.max(effective.notBeforeMs, value);
    } else if (field === 'expiresAtMs') {
      effective.expiresAtMs = Math.min(effective.expiresAtMs, value);
    } else if (LIMIT_FIELDS.has(field)) {
      const name = field.slice('limits.'.length);
      effective.limits[name] = Math.min(effective.limits[name], value);
    }
  }
  return effective;
}

function verify(token, context) {
  if (context === null || typeof context !== 'object' || context.channelAuthenticated !== true) deny('CAP_CHANNEL');
  integer(context.nowMs);
  const envelope = decode(token);
  let signature = mac(keyBytes(context.rootKey), ROOT_DOMAIN, envelope.claims);
  for (const caveat of envelope.caveats) signature = mac(signature, CAVEAT_DOMAIN, caveat);
  if (!timingSafeEqual(signature, Buffer.from(envelope.mac, 'hex'))) deny('CAP_SIGNATURE');
  const claims = effectiveClaims(envelope);
  for (const key of ['issuer', 'issuerKeyId', 'audience', 'peer', 'policyVersion']) {
    identifier(context[key]);
    if (context[key] !== claims[key]) deny('CAP_CONTEXT');
  }
  binding(context.keyBinding);
  integer(context.issuerEpoch);
  if (context.keyBinding !== claims.keyBinding || context.issuerEpoch !== claims.issuerEpoch) deny('CAP_CONTEXT');
  if (context.nowMs < claims.notBeforeMs || context.nowMs >= claims.expiresAtMs) deny('CAP_TIME');
  identifier(context.operation);
  identifier(context.resource, 192);
  if (!claims.scopes.includes(context.operation)) deny('CAP_SCOPE');
  if (!claims.resources.includes(context.resource)) deny('CAP_RESOURCE');
  if (claims.limits.uses === 0 || claims.limits.maxConcurrent === 0) deny('CAP_LIMIT');
  if (context.requestBytes !== undefined) {
    integer(context.requestBytes);
    if (context.requestBytes > claims.limits.maxBytes) deny('CAP_LIMIT');
  }
  return {
    grantId: claims.grantId,
    usageLimit: claims.limits.uses,
    grantUsageLimit: envelope.claims.limits.uses,
    expiresAtMs: claims.expiresAtMs,
    claims,
  };
}

function keyBindingForCertificate(rawDER) {
  try {
    if (!(rawDER instanceof Uint8Array) || rawDER.byteLength === 0 || rawDER.byteLength > 65_536) deny('CAP_CERTIFICATE');
    const publicKey = new X509Certificate(Buffer.from(rawDER)).publicKey;
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    return `sha256:${createHash('sha256').update(spki).digest('hex')}`;
  } catch (error) {
    if (error instanceof CapabilityError) throw error;
    deny('CAP_CERTIFICATE');
  }
}

module.exports = {
  SCHEMA, VERSION, MAX_TOKEN_BYTES, MAX_CAVEATS, MAX_LIFETIME_MS,
  CapabilityError, issue, attenuate, verify, keyBindingForCertificate,
};
