# Collaboration capability profile v1

`capability.cjs` implements a **project-specific first-party macaroon-style
format**, using Node's standard `node:crypto` HMAC-SHA-256. It is not an L402
serializer, an OAuth token, DPoP, or a claim of interoperability with standard
macaroon libraries. It has no runtime package dependencies or network calls.
The existing paid `m2m-gate.cjs` is unchanged.

The [original macaroon research](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/)
provides the chained-MAC and attenuation model. This implementation uses a
deliberately narrower, separately named serialization and fixed predicate
language. The published
[`go-macaroon/js-macaroon`](https://github.com/go-macaroon/js-macaroon)
implementation was considered; an audited dependency/vendor adoption and its
transitive dependencies were not established in this change. No third-party
implementation has been silently vendored or represented as reviewed. Review
this project profile before interoperable or production admission. The Python
oracle below demonstrates agreement for **this profile only**.

## Security boundary

A valid capability is necessary but never sufficient for authorization.
The receiving gateway must also enforce enrollment, its own current policy,
peer approval, original owner/reviewer and hardware admission gates where
required, operation dispatch restrictions, resource budgets and durable usage
accounting. Verification never enables compute, payment, firmware, shell,
device control, artifact activation or a direct ACT node path.

Each resource server owns its issuer secret. ACT issues authority over ACT
resources; MIKAYA issues authority over MIKAYA resources. Do not send issuer
secrets to a peer. Generate production issuer keys with a cryptographically
secure random generator, store them in protected local state, and use explicit
key IDs and epochs. The module accepts 32–64 bytes of binary key material; byte
length does not establish sufficient entropy. The deterministic fixture key is
public test data and must never be used in deployment.

The authenticated peer comes from the enrolled **TLS socket**, not request
headers or a claimed body field. A caller may set `channelAuthenticated: true`
only after the TLS stack verifies the peer certificate and local enrollment
accepts its SPKI public key. `keyBindingForCertificate()` computes a fingerprint;
it does not validate a certificate chain, expiry, revocation or enrollment.

The key binding is `sha256:` followed by the lowercase hexadecimal SHA-256 of
the DER-encoded SubjectPublicKeyInfo. It is not a certificate-file fingerprint.
Certificate renewal retaining the same key retains this binding; a new public
key requires new enrollment and issuance. Separate token/transport keys from
the established Ed25519 ledger identity.

## API

CommonJS exports:

```js
const {
  SCHEMA, VERSION,
  issue, attenuate, verify, keyBindingForCertificate,
  CapabilityError,
} = require('./capability.cjs');

const token = issue({ rootKey, claims, nowMs });
const restricted = attenuate(token, [
  { field: 'scopes', value: ['receipt.read.v1'] },
  { field: 'limits.uses', value: 1 },
]);

const verified = verify(restricted, {
  rootKey,
  channelAuthenticated: true, // Only from the trusted TLS/enrollment path.
  issuer, issuerKeyId, audience, peer, keyBinding,
  issuerEpoch, policyVersion,
  operation: 'receipt.read.v1',
  resource: manifestOrIntentDigest,
  requestBytes: actualRequestBytes,
  nowMs: trustedCurrentTime,
});
```

These are API examples with required configured variables, not ready-to-run
enrollment commands. Do not read the expected context from token claims and
then pass it back as trusted configuration.

### Required claims

Every listed field is mandatory; additional fields fail validation.

| Field | Contract |
| --- | --- |
| `schema` | Exported `SCHEMA`, exactly `mikaya.act.capability.v1` |
| `version` | Exported `VERSION`, exactly integer `1` |
| `issuer`, `issuerKeyId` | Receiver-configured issuer and local key identifier |
| `audience` | Exact receiver service identity |
| `peer` | Exact enrolled sender identity |
| `keyBinding` | `sha256:` plus 64 lowercase hexadecimal SPKI digest characters |
| `grantId` | Stable issuer-owned budget identity; retain across attenuation |
| `issuerEpoch` | Safe nonnegative integer checked against current local epoch |
| `policyVersion` | Exact current configured policy version |
| `scopes` | Sorted unique array of 1–16 exact operation names |
| `resources` | Sorted unique array of 1–16 exact resource identifiers/digests |
| `notBeforeMs`, `expiresAtMs` | Safe nonnegative integer UTC milliseconds |
| `limits` | Exactly `{uses, maxBytes, maxConcurrent}`, positive safe integers |

Identifiers are nonempty ASCII strings of at most 128 characters; resource
identifiers may contain up to 192. The first character is alphanumeric, followed
by alphanumerics or `._:/@+-`. Wildcards, whitespace, ambiguous Unicode,
duplicate entries and unsorted arrays are rejected. Resources use exact
matching; there is no path-prefix or implicit descendant authorization.

Issuance limits expiry to at most 120 seconds after the supplied trusted time,
and the claim interval must be at most 120 seconds. Verification accepts the
not-before instant and rejects the expiry instant. There is no implicit clock
skew extension. The gateway must detect unreliable/rolled-back clocks and
enforce any shorter owner grant or independent review lifetime; this module
does not infer those records.

### Verification context and result

`verify()` requires the expected `issuer`, `issuerKeyId`, `audience`, `peer`,
`keyBinding`, `issuerEpoch`, `policyVersion`, `operation`, `resource`, `nowMs`
and `channelAuthenticated: true`. The root key and every expected identity
must come from trusted receiver configuration or the authenticated channel.

Pass `requestBytes` to enforce the effective per-request byte limit. The gateway
must additionally enforce parser/header limits before parsing and concurrency
and aggregate budgets at dispatch. Omitting `requestBytes` does not waive the
returned byte limit; it leaves that check to the caller.

The detached result is:

```js
{
  grantId,
  usageLimit,       // Effective uses ceiling after attenuation.
  grantUsageLimit,  // Original issuer grant's ceiling.
  expiresAtMs,     // Effective expiry after attenuation.
  claims,          // Effective scopes/resources/times/limits and fixed bindings.
}
```

Access the effective concurrency and byte ceilings at
`claims.limits.maxConcurrent` and `claims.limits.maxBytes`. The verifier is
stateless: two calls can verify the same credential, and this does not authorize
two effects. Consuming uses is the journal's job.

## Attenuation and accounting

Each appended caveat has exactly `{field, value}`. Supported fields are:

- Equality constraints: `issuer`, `issuerKeyId`, `audience`, `peer`, `keyBinding`,
  `grantId`, `issuerEpoch`, `policyVersion`. They must remain equal to the original
  binding; disagreement makes the token unusable.
- `scopes` and `resources`: intersection with every earlier restriction.
- `notBeforeMs`: maximum of the original and appended values.
- `expiresAtMs`: minimum of the original and appended values.
- `limits.uses`, `limits.maxBytes`, `limits.maxConcurrent`: minimum value wins.

Caveat limits may be zero. Zero uses or concurrency authorizes no operation;
zero bytes permits only an empty request body. Adding a broader list or limit
cannot restore authority removed earlier. Unknown predicates, third-party
discharges and unrecognized fields are rejected.

A token already bound to key A cannot be delegated to key B by adding a B
binding. Issuer-mediated issuance/exchange is necessary for a new peer key.
Possession of a token permits further attenuation but does not prove the
token's authenticity: the resource server still verifies the root MAC.

All attenuated descendants retain the **same `(issuer, grantId)` budget key**.
The journal must atomically reserve/debit usage with first durable transaction
acceptance, reject new work exceeding both original and effective ceilings,
and check current admission before dispatch. Counting each distinct serialized
token separately would incorrectly multiply the parent grant's authority.
Under this conservative shared-counter policy, a descendant with `uses: 1`
cannot submit a new transaction after any use of that grant has been consumed.

Request nonce, immutable transaction-intent ID/digest and token/grant ID are
different concepts. A fresh authorized retry of the same immutable intent may
retrieve its recorded receipt without another use or dispatch. Verify channel,
principal, token integrity/current revocation and receipt authorization first;
recognize a matching recorded intent before charging another use. A consumed
grant cannot create a different transaction. Expired execution authority does
not become valid because a retry has a fresh nonce; use a new independently
authorized receipt-read credential to retrieve an outcome after expiry.

## Wire format and limits

The ASCII token is `mcap1.` followed by unpadded base64url of the canonical UTF-8
JSON envelope:

```json
{"caveats":[],"claims":{},"mac":"64-lowercase-hex-characters"}
```

The abbreviated `claims` and `mac` above only illustrate envelope shape. They
are not a valid token. Canonical JSON sorts object keys lexicographically,
preserves caveat order, uses sorted set arrays, no whitespace, ASCII identifiers
and safe nonnegative integer numbers. The decoder requires the exact canonical
bytes after parsing, rejecting duplicate JSON keys, alternate numeric spellings,
escaped aliases, invalid UTF-8 and alternate base64url spellings.

The root MAC is:

```text
HMAC-SHA256(rootKey, ASCII("MIKAYA-ACT-CAPABILITY-V1-ROOT\0") || canonical(claims))
```

For each caveat, derive the next MAC using the preceding 32-byte MAC as key:

```text
HMAC-SHA256(previousMAC, ASCII("MIKAYA-ACT-CAPABILITY-V1-CAVEAT\0") || canonical(caveat))
```

`\0` denotes one NUL byte. The final MAC is encoded as lowercase hex. The two
distinct contexts prevent using a caveat encoding as a root-message encoding.
MAC comparison uses Node's constant-time `timingSafeEqual` on equal-length
buffers. No encryption or payment/identity proof is implied by this MAC.

The entire token, including prefix, is limited to **4,096 bytes**, with at most
**16 appended caveats**. The parser validates fixed shapes before canonical
serialization. Errors have constant `CAP_*` codes with no input echo or parser
details. Never log the token or put it in URLs, GitHub artifacts or command-line
arguments. Tokens are bearer material even though this receiver also enforces
channel binding.

## Verification performed and reproducible checks

On the implementation workspace's Node **v24.22.3**, the following focused suite
passed **31 tests, zero failures, zero skips**. This is a local software result,
not physical Android, live ACT interoperability or production admission.

```sh
node --test engineering/federation/collaboration/tests/test_capability.cjs
python3 engineering/federation/collaboration/fixtures/capability_oracle.py
```

The independent Python **3.12.14** standard-library oracle checked two fixed
vectors (issuance and chained attenuation). Fixture SHA-256:
`cd14ee65dab07f1d88887c3ae4ceba6164f723b5fd0f8a101be4d8aea09ed0df`.
The committed fixture is verified directly by Node tests, so Python is needed
only to reproduce the independent oracle, not to run the module or Node suite.

The public certificate fixtures have different certificates/serials but the
same SPKI key, proving renewal binding behavior. Their temporary generated
private key was removed and is not part of the repository. These certificates
are parsing fixtures, not trusted TLS enrollment records.

Tests cover forged/modified claims and MACs; removal/reordering of caveats;
scope/resource/identity isolation; expiry and issuer/policy changes; missing
authenticated channel; strict encodings and unknown predicates; token/caveat
size limits; use/concurrency/byte attenuation; SPKI stability and invalid
certificate errors; and independent serialization/HMAC agreement.

Node 22+ is the intended compatibility target. This focused result establishes
the recorded Node 24 workspace execution only; the integration owner must retain
separate runtime-floor, physical F110/Motorola, authenticated transport,
concurrent journal, restart/revocation and bilateral ACT results. No runtime
dependencies were added, so this module adds no package-manager dependency
audit surface; it still inherits the deployed Node/OpenSSL security posture.
