# Public artifact distribution v1

`distribution.cjs` implements a separate **public byte artifact** profile for
Toybox/collaboration fixtures and deliberately published objects. It neither
reads nor exports an AHAVA mesh key. Existing AHAVA encryption, manifests,
private transfers and activation rules remain unchanged. The transport must
still authenticate the channel and authorize every exact manifest/chunk resource.

## Signed contract

The manifest schema is `mikaya.act.public-artifact.v1`. Its exact fields are
`schema`, `publisher`, `artifactId`, `version`, `sequence`, `issuedAtMs`,
`expiresAtMs`, `length`, `chunkSize`, `sha256`, `chunks`, and `signature`.
Each chunk is exactly `{index, offset, length, sha256}`. Unknown fields fail.

- `publisher` is the **existing federation fingerprint**: SHA-256 of canonical
  Ed25519 SPKI **PEM** output via `federation.fp()`. It is distinct from the
  transport capability's SHA-256 of SPKI DER.
- Signatures are Ed25519 over `MIKAYA-ACT-PUBLIC-ARTIFACT/1\n` plus the existing
  federation canonical serialization of every field except `signature`.
- The manifest digest is SHA-256 of the canonical complete signed manifest.
  A receiver checks its locally pinned publisher key and expected digest.
- `artifactId` and `version` are bounded labels, never filenames or source URLs.
  Slashes, traversal sequences, whitespace and arbitrary paths are refused.
- Objects are limited to **1 MiB**, at most **16 chunks**, each at most **65,536
  bytes**, and an **8,192-byte manifest**. The separate transport response budget
  must allow the binary chunk while retaining the existing control-message cap.
- Manifest lifetime is at most 24 hours; issuance defaults to one hour. Access
  capabilities retain their independent, shorter expiry. There is no implicit
  clock-skew allowance.

Resource names are exact:

```text
manifest:<64-lowercase-hex-manifest-digest>
manifest:<64-lowercase-hex-manifest-digest>:chunk:<decimal-index>
```

`manifestResource()` and `chunkResource()` generate these names after validation.
Do not authorize a path prefix, wildcard artifact set or arbitrary URL.

## API

```js
const manifest = signManifest({
  bytes, artifactId, version, sequence,
  privateKey, publicKey, nowMs, expiresAtMs,
});
const verified = verifyManifest({
  manifest, publisherPublicKey, expectedPublisher,
  expectedManifestDigest, expectedArtifactId, nowMs,
});
const chunk = readChunk(sourceBytes, manifest, index);

const receiver = createReceiver({
  directory, manifest, publisherPublicKey, expectedPublisher,
  initialize: false, nowMs,
});
receiver.status({ nowMs });
receiver.acceptChunk({ index, bytes: chunk, nowMs });
const completed = receiver.finalize({ nowMs });
receiver.close();
```

These examples require real configured variables. `nowMs` defaults to the local
clock; tests can inject a trusted time. `verifyManifest()` returns
`{manifestDigest,publisher,artifactId,version,sequence,length,chunks,expiresAtMs}`.

`readChunk()` requires that the caller has independently pinned and verified the
manifest. It verifies the entire supplied source digest before selecting a chunk,
then checks that chunk's signed digest. It does not enroll a publisher or grant
network access. The gateway must use an explicit source-file allowlist and
fixed exact manifest/chunk lookup, with its own safe source-file checks. No path
is accepted from a peer by this module.

## Receiver persistence and exact resume

Use one owner-private receiver directory for one publisher/artifact identity.
`initialize: true` is only for deliberate first setup of an absent directory;
it never resets existing history. Subsequent releases must use that same store.
Creating a new directory for every release would discard the antirollback
history and is not an authorized recovery procedure.

The shared `openPrivateStore()` provides an owner-private state file and
exclusive writer lease. State records the highest accepted sequence, exact
manifest digests and latest observed local time. A lower sequence, same sequence
with a different signed digest, publisher/artifact change or backward observed
clock is refused. A newer accepted sequence uses a separate exact-digest cache;
old verified chunks are not silently reused for a different manifest.

Cache filenames are generated only from the verified manifest digest and bounded
integer index. Every read rechecks owner-only permissions, regular-file type,
single hardlink, file identity, length and SHA-256, using no-follow file opens.
Symlinks, hardlinks, truncated or corrupted files fail closed; they are not
silently overwritten. New writes use exclusive creation and file/directory
`fsync` before reporting success. Finalization rechecks every chunk and the
whole-object digest and writes a fixed `.bin` artifact in the private directory.

State retains up to 16 accepted manifest versions. At the maximum object size,
verified chunks plus complete objects occupy at most 32 MiB for those versions,
excluding bounded state/lease metadata and any failed-write remnants. New
versions are refused when the version budget is exhausted. Maintenance/recovery
must preserve trusted sequence/checkpoint history; the module does not implement
automatic cache deletion, state reset or privileged cleanup.

Private-state checksums detect changed bytes but do not defeat a privileged
attacker who can replace the entire state directory and every checkpoint.
Retain independently signed receipt/checkpoint evidence for that threat model.

## Receipts and non-activation

`acceptChunk()` returns `chunkVerified: true`, **`contentVerified: false`**, and
`activationAuthorized: false`. A chunk acknowledgment never means the artifact
is complete. `status()` lists missing chunk indices, verified byte/chunk counts,
and whether a complete verified artifact exists. `finalize()` returns the
verified file path, whole digest and manifest metadata with `contentVerified:
true` and **`activationAuthorized: false`**.

These are receipt bodies, not standalone signed receipts. The collaboration
gateway's authenticated signed response must bind the body or binary payload
digest to the request and its local transaction record. Do not claim the
distribution module itself signs the receiver's result.

The module never extracts archives, launches code, installs model weights,
activates files, flashes firmware, sends payments or gives a peer access to local
paths. The signed object is stored as opaque public bytes. Content approval and
any future activation require separate local authority and validation.

## Recorded local verification

On Node **v24.22.3**, the focused suite passed **20 tests, zero failures, zero
skips**:

```sh
node --test engineering/federation/collaboration/tests/test_distribution.cjs
```

The 131,109-byte resume fixture reused **65,536 verified bytes** and accepted
only **65,573 additional bytes** before independently checking the whole digest.
Those are local fixture body bytes, not physical transport, latency, battery or
live ACT measurements.

Tests exercise publisher/key/signature pinning, traversal metadata, expiry,
source change, bounded chunks, exact resume, duplicate chunks, missing or corrupt
cache, symlinks/hardlinks, private permissions, duplicate writers, version
rollback/equivocation, clock rollback, whole-object integrity, zero-length files
and the maximum supported object. Authenticated network delivery, capability
accounting and physical Android acceptance remain integration-level evidence.
