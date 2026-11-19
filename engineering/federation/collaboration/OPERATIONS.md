# Operating the MIKAYA collaboration interface

This is the operating procedure for the separate collaboration adapter. The
installed command works from any directory and does not depend on a previous
Termux shell session. Source installation, creation of collaboration state,
starting a listener, and enrolling a real ACT peer are separate explicit actions.

The existing federation identities, owner policy, tollbooth, broker, independent
ledgers and AHAVA implementation remain authoritative. The existing mobile
evidence service continues to use **`127.0.0.1:4188`**. This installer does not
edit, restart or replace that service. The collaboration adapter's local lab
uses a separate ephemeral loopback port. Select a different reviewed port, for
example `4190`, for a manually configured collaboration instance.

## 1. Know which result you have

| Result | What it establishes | What remains separate |
| --- | --- | --- |
| Source manifest and installer checks | Exact reviewed source bytes were copied; the installed command rechecks those bytes before execution. | An unsigned SHA-256 inventory is not an owner signature or authority to activate a peer. |
| Android preflight | Actual readable Android system properties, Node runtime and available paths on that device. | Hardware attestation, native thermal freshness, owner grants, peer enrollment and transport tests. |
| Isolated demo PASS | Two independent software identities exchange authenticated requests on one machine, including transaction and public artifact exercises. | A second physical phone, ACT's endpoint/model, private AHAVA transfer, production admission, payments and network performance. |
| `status` | Configuration is readable and identifies current local policy and the presence of a writer lease. | A lease file alone does not prove a live listener; use an authenticated request for a live round trip. |
| Verified Toybox receipt | The specified statement/intent was durably recorded under the local protocol. | Blockchain verification, payment settlement, arbitrary code execution and model correctness. |
| Verified public artifact | Signed metadata, approved exact chunks and the whole object digest agree. | Installing, extracting, executing or activating the artifact. |

The existing [native acceptance record](../mobile-edge/NATIVE_ACCEPTANCE_20261118.md)
and [pinned evidence launcher](../mobile-edge/operations/README.md) describe the
previous evidence deployment. Keep its historical results separate from this
adapter's new results.

## 2. Android requirements and the fresh device observations

The source targets **Node 22 or newer** and the current ARM64 Android/API 34 and
35 devices. Node's TLS 1.3 and HTTP/2 support must be present in the deployed
build. The isolated demo additionally requires an already installed `openssl`
command to create its own temporary lab certificates. The installer never runs
a package manager, `sudo`, `su`, firmware tools or a boot-service installer.

Run the actual preflight; do not copy one phone's properties onto the other:

```sh
mikaya-collaboration preflight
mikaya-collaboration preflight --strict
```

Before installation, the same read-only observation can run directly from the
reviewed source path:

```sh
node /absolute/source/engineering/federation/collaboration/android-preflight.cjs
```

Without `--strict`, exit zero means a report was collected. With `--strict`, a
runtime incompatibility or device-profile review requirement returns exit 2.
Neither result grants ACT admission. `ro.product.board` and `ro.board.platform`
are distinct fields. Unknown values remain visible as unknown/unreviewed;
the preflight never substitutes an expected identity or changes Android
properties. A newly observed Android API also requires its own compatibility
test rather than inheriting the API 34/35 result.

The module was executed on both connected phones on **2026-11-19 UTC**. The
executed module SHA-256 was
`d97d6f9df096fe5decadb390453a50869d45f42c00ac40b0b34354f91fa08a1c`.
These are native module executions, distinct from the fixture tests below:

| Observation | F110 | Motorola |
| --- | --- | --- |
| Capture time | `17:59:16.529Z` | `17:59:18.413Z` |
| `ro.product.model` | `F110 Pro` | `moto g power 5G - 2023` |
| `ro.product.board` | `e393_qc_f10_w_6835_v0` | `devonn` |
| `ro.board.platform` | `mt6835` | `mt6855` |
| Android/API | `15` / `35` | `14` / `34` |
| Primary ABI | `arm64-v8a` | `arm64-v8a` |
| Node/runtime architecture | `26.13.1` / `arm64` | `26.3.1` / `arm64` |
| Property read errors | None | None |
| Preflight runtime blockers | None | None |
| Profile review required | No discrepancy with documented profile | No discrepancy with documented profile |

Both observations found the existing `mikaya-local-evidence` command, evidence
service directory and pinned evidence source file. The collaboration entrypoint
was absent from the old evidence source directory, as expected. No listener was
started by this check; it did not inspect signed-evidence freshness or claim
hardware attestation. Only a new preflight source file was written into a unique
directory under each phone's `$PREFIX/tmp`; the inspection itself was read-only.

Keep data under the Termux app's private filesystem. Shared-storage mounts are
not a suitable location for owner-private keys, transaction stores or executable
source. The runtime enforces private directory/file permissions and real absolute
paths. Do not loosen those checks to accommodate a copied public-storage folder.

## 3. Install the command without starting a service

Obtain the reviewed source tree, `COLLABORATION-SOURCE-MANIFEST.json`, and its
expected SHA-256 from the release receipt. The manifest must cover the entrypoint
and every transitive source dependency, including the existing federation modules
it imports. Keep the directory structure intact.

Set these two release-specific values once in the shell. Replace the sample
values with the actual source directory and the independently reviewed digest:

```sh
MIKAYA_SOURCE_ROOT="/absolute/path/to/reviewed/mikaya-sovereign"
MIKAYA_MANIFEST_SHA256="REPLACE_WITH_REVIEWED_64_CHARACTER_SHA256"
```

Run the read-only check before the explicit install:

```sh
bash "$MIKAYA_SOURCE_ROOT/engineering/federation/collaboration/install-termux.sh" \
  --check \
  --manifest "$MIKAYA_SOURCE_ROOT/COLLABORATION-SOURCE-MANIFEST.json" \
  --manifest-sha256 "$MIKAYA_MANIFEST_SHA256"

bash "$MIKAYA_SOURCE_ROOT/engineering/federation/collaboration/install-termux.sh" \
  --install \
  --manifest "$MIKAYA_SOURCE_ROOT/COLLABORATION-SOURCE-MANIFEST.json" \
  --manifest-sha256 "$MIKAYA_MANIFEST_SHA256"
```

The installer requires the existing absolute Termux `$PREFIX`, or an explicit
`--prefix /absolute/prefix` for a host installation fixture. Its source root is
derived from the script's real location, never from the caller's working directory.

The only installation locations are:

| Location | Purpose |
| --- | --- |
| `$PREFIX/lib/mikaya-collaboration/installation.json` | Marks this installer's source namespace and prefix. |
| `$PREFIX/lib/mikaya-collaboration/releases/<manifest-sha256>/` | Versioned manifest and exact copied `source/` tree. |
| `$PREFIX/lib/mikaya-collaboration/current.json` | Records the selected release, absolute Node/entrypoint paths and wrapper digest. |
| `$PREFIX/bin/mikaya-collaboration` | Fixed-path command wrapper; revalidates the manifest and source before invoking the gateway CLI. |

Source files, symlink paths, traversal, duplicate manifest entries, unlisted
installed source and digest mismatches are checked. An unrelated existing command
or unowned installation directory is refused. Existing releases are never
silently overwritten. Installation creates no collaboration runtime keys or
state, enrolls no peer, and starts no listener. It also does not change the
existing Termux execution-library setup used by the evidence runtime.

The wrapper clears `NODE_OPTIONS` and `NODE_PATH` for its child execution, while
retaining the existing native environment. Its integrity checks detect changed
source; they do not provide protection from an actor already able to replace the
entire app-private installation and all its receipts.

After installation:

```sh
"$PREFIX/bin/mikaya-collaboration" preflight
bash "$MIKAYA_SOURCE_ROOT/engineering/federation/collaboration/install-termux.sh" --status
```

Generating a new manifest hash from arbitrary downloaded files does not establish
review or approval. Do not reuse an older release signature to describe these
new bytes as signed.

## 4. Run the isolated collaboration exercise

Use a new absolute directory whose parent already exists. The demo refuses an
existing target; it must not reset a prior lab or production state directory.
Resolve the parent with Node's own real-path handling when necessary:

```sh
MIKAYA_LAB_PARENT="$(node -e 'process.stdout.write(require("node:fs").realpathSync(process.env.PREFIX + "/tmp"))')"
MIKAYA_LAB_DIR="$MIKAYA_LAB_PARENT/mikaya-collaboration-lab-$(date -u +%Y%m%dT%H%M%SZ)"
mikaya-collaboration demo --directory "$MIKAYA_LAB_DIR"
```

This explicit command creates fresh lab-only identities and certificates,
starts a loopback gateway, exercises the protocol and stops its listener before
returning. It preserves its lab directory for examination. It never imports or
reinitializes either phone's existing identity.

Require an `acceptance-report.json` with `status: "PASS"` and inspect its
individual checks. The exercise covers authenticated HTTP/2 and HTTP/1.1, signed
responses, a durable Toybox statement receipt, a fresh-nonce retry returning the
same receipt, refusal of exact attempt replay and changed intent, a modified
capability refusal, and exact public-artifact resume plus whole-digest verification.
Its byte fixture is 131,109 bytes: after restarting the receiver it reuses the
first 65,536 verified bytes and fetches the remaining 65,573 bytes.

The transport measurements are **30 paired loopback screening samples**. They
cannot establish cellular/Wi-Fi speed, battery impact, thermal endurance, model
inference performance or bilateral ACT connectivity. Preserve the sample scope
when reporting a result. `actModelConnected`, `hardwareAttested` and
`settlementEnabled` remain false.

The generated lab private keys remain private. Publish only the sanitized
acceptance report, relevant source hashes and approved public fixture metadata.
Do not upload the entire lab directory to GitHub.

## 5. Initialize a real adapter with the existing identity

Use the exact configuration schema documented by `gateway-adapter.cjs` and the
collaboration README. All private files must be regular owner-private files at
real absolute paths. Before initialization, establish these concrete inputs:

| Input | Required decision |
| --- | --- |
| `federationDirectory` | The already existing local node directory; do not create a replacement identity for the production adapter. |
| `tls` | Separate local TLS certificate/private key and reviewed CA bundle. Keep the federation Ed25519 key in its original location. |
| `peers` | Each peer's existing federation fingerprint/public-key pin and separately verified TLS SPKI DER binding. The peer must already exist in the local trust configuration. |
| `listen` | Start with `127.0.0.1` and a port other than 4188. Any later reachable address is a deliberate, reviewed configuration change. |
| `operations` / `resources` | Exact bounded allowlists; begin with `collaboration.describe.v1` / `collaboration:self`. |
| `issuerEpoch` / `policyVersion` | Current local revocation epoch and `collaboration-v1`. Issuer secrets remain local. |
| `brokerUrl` | `null` until the original loopback broker is ready and its unchanged owner/reviewer/hardware gates permit the exact requested work. |
| `artifacts` | An empty list initially, or explicitly approved manifest/source files with exact digests. No peer-supplied filesystem paths. |

An ACT API hostname, real enrolled ACT identity, certificate/CA, supported
operation/model contract and bilateral approval must be supplied by the real
counterparty. A generated lab identity is not evidence that those inputs exist.

Keep a reviewed configuration file at a private absolute path and choose an
**absent** adapter state directory with an existing real parent. Then invoke:

```sh
mikaya-collaboration init \
  --directory "$MIKAYA_COLLAB_DIR" \
  --config "$MIKAYA_REVIEWED_CONFIG"

mikaya-collaboration status --directory "$MIKAYA_COLLAB_DIR"
```

Here `MIKAYA_COLLAB_DIR` is the new adapter's state path and
`MIKAYA_REVIEWED_CONFIG` is the reviewed configuration file's path. The expected
initialization result is `INITIALIZED_STOPPED`. Initialization creates the
adapter's own capability issuer secret, transaction journal, artifact policy
and telemetry/replay state. It does not rewrite the established federation
identity. It refuses an existing target directory; do not add a reset flag or
delete state to get around that refusal.

## 6. Start, authenticate, stop and return after a new shell

| Action | Command or procedure |
| --- | --- |
| Check device/source availability | `mikaya-collaboration preflight` |
| Inspect configured state | `mikaya-collaboration status --directory "$MIKAYA_COLLAB_DIR"` |
| Start one foreground instance | `mikaya-collaboration serve --directory "$MIKAYA_COLLAB_DIR"` |
| Confirm live protocol operation | Send an authorized `collaboration.describe.v1` request from the enrolled peer. |
| Stop that instance | Press Ctrl-C in the same terminal. The CLI handles SIGINT/SIGTERM and closes its own listener/stores. |
| Check retained evidence service | `mikaya-local-evidence status` is a separate read-only service check. |
| Return after opening Termux again | Invoke the installed command using the same explicit state path; do not run `init` again. |

There is no automatic boot activation in this release. The foreground listener
may stop when its session or process stops, while its source and durable state
remain separate. The wrapper's absolute paths remove the need to recover a
previous working directory or shell variable assignment. If `PATH` does not find
the command, use `"$PREFIX/bin/mikaya-collaboration"` directly.

Do not infer current gateway health, signed-evidence freshness or ACT admission
from an open Termux window. Do not clear a writer lock after a crash merely
because it exists. Preserve the affected state and inspect the owning process
and journal. An uncertain transaction stays uncertain until reconciled; a restart
does not authorize automatic redispatch.

### Issue a bounded capability on the receiving resource owner

The receiver issues authority for its own resources. It does not send its issuer
secret or existing federation private key to the requester. The first exercise
can use one describe operation:

```sh
mikaya-collaboration grant \
  --directory "$MIKAYA_COLLAB_DIR" \
  --peer "$MIKAYA_ENROLLED_PEER_FINGERPRINT" \
  --scopes collaboration.describe.v1 \
  --resources collaboration:self \
  --uses 1 \
  --ttl-ms 60000 \
  --output "$MIKAYA_NEW_CAPABILITY_FILE"
```

Use a new private absolute output filename. The CLI writes the token to that file;
keep the token out of URLs, shell arguments, chat, logs and GitHub artifacts.
Deliver it to the intended enrolled requester through an already authorized
confidential channel within its short lifetime. Expiration is at most 120 seconds;
starting a transport session does not extend it.

The project profile is explicitly **macaroon-style**, not a declaration of
standard macaroon/L402/OAuth interoperability. Read [CAPABILITY.md](CAPABILITY.md)
for attenuation, TLS key binding, exact scopes, shared grant usage accounting and
revocation semantics.

### Send a request from the enrolled peer

The request descriptor is a private JSON file, separate from the capability file.
Its exact fields are:

```json
{
  "peer": "RECEIVER_FEDERATION_FINGERPRINT",
  "url": "https://REVIEWED_HOST:REVIEWED_PORT/",
  "capabilityFile": "/absolute/private/capability.token",
  "operation": "collaboration.describe.v1",
  "resource": "collaboration:self",
  "payload": {},
  "transactionId": "NEW_UUID_FOR_THIS_IMMUTABLE_INTENT",
  "expiresAtMs": 0
}
```

The uppercase strings and zero expiry are deliberately invalid placeholders.
Populate them from the approved peer and a currently valid capability; use a
fresh UUID and an expiry no later than the authorized intent lifetime. Do not
copy a stale descriptor as new authority. Node can generate a UUID locally with
`node -e 'console.log(require("node:crypto").randomUUID())'`.

```sh
mikaya-collaboration request \
  --directory "$MIKAYA_COLLAB_DIR" \
  --request "$MIKAYA_PRIVATE_REQUEST_FILE"
```

HTTP/2 is the default. An explicitly selected
`--transport http1` uses the same TLS 1.3 client authentication, enrollment,
capability, signature and policy checks. There is no insecure downgrade. The
programmatic client reuses a connection across multiple requests; separate CLI
invocations create separate client lifetimes and are not a connection-reuse
benchmark.

A retry of the same immutable intent keeps its transaction ID, operation,
resource, payload digest and expiry, but generates a fresh attempt nonce. It
requires currently valid authorization and must return the recorded receipt
without executing again. A timeout or connection loss does not prove the work
failed. Use authorized receipt lookup or reconciliation, especially for an
uncertain journal record. The `receipt.read.v1` payload specifies the original
`operation` and `transactionId` and requires a separately allowed receipt resource.

Public distribution uses exact `manifest:<digest>` and
`manifest:<digest>:chunk:<index>` resources. For a binary response the request
CLI also requires `--output /absolute/new/output.bin`; the output must not
already exist. The verified receipt binds the chunk digest. Whole-object
completion and durable resume belong to the receiver described in
[DISTRIBUTION.md](DISTRIBUTION.md), and do not authorize activation.

## 7. Source rollback and command removal

Stop the specific foreground adapter before changing its selected source version.
Keep runtime schema compatibility under review; a source rollback is not a
transaction, key or policy rollback.

```sh
bash "$MIKAYA_SOURCE_ROOT/engineering/federation/collaboration/install-termux.sh" \
  --rollback --release "$MIKAYA_PREVIOUS_MANIFEST_SHA256"

bash "$MIKAYA_SOURCE_ROOT/engineering/federation/collaboration/install-termux.sh" \
  --remove-command
```

Rollback verifies the already installed prior manifest and all its source before
selecting it. Removal deletes only the unchanged managed command wrapper. Both
operations retain versioned sources, installation receipts and all runtime state.
Neither operation stops an already running process or touches port 4188.

If source verification reports HOLD, compare the exact release against its
reviewed manifest. If the command itself was edited, the installer refuses to
replace or remove it. Preserve the evidence and resolve the mismatch explicitly;
there is no `--force`, key reset, automatic lock stealing or silent state recovery.

## 8. Repeatable verification and GitHub handoff

From a reviewed checkout, run the focused delivery test and the integrated suites:

```sh
node --test engineering/federation/collaboration/tests/test_android_preflight.cjs
node --test engineering/federation/collaboration/tests/test_*.cjs
```

The delivery suite passed **28 tests, zero failures and zero skips** on workspace
Node `v24.22.3`. Twelve tests use explicitly injected Android properties; sixteen
exercise the real installer against temporary host directories. They are
labelled fixtures and are not substituted for the two native observations above.

| Coverage | Required behavior |
| --- | --- |
| F110/Motorola fixture identity | Preserve actual model, product board, platform, API and ABI as separate observations. |
| Unknown or mismatching device | Report review required; never forge a recognized profile. |
| Missing command/property, Node <22, 32-bit runtime, new API | Produce explicit blockers or errors without mutation. |
| Read-only installer check | Verify digests without creating installation/state. |
| Fixed-path installation | Work from unrelated cwd and paths containing spaces/apostrophes. |
| Manifest/source mismatch, traversal, symlink | Refuse before installation. |
| Existing command or unowned directory | Refuse adoption; preserve existing bytes. |
| Later source tampering/unlisted source | Installed command fails before gateway execution. |
| Version rollback/removal | Preserve all release/state/evidence sentinel bytes; change only the managed command. |
| Existing lock or reset/autostart flags | Fail closed; do not steal, reset or start. |

For the engineering PR, include the collaboration source, tests, protocol docs,
source manifest and sanitized acceptance reports. Pin the reviewed head and
manifest digest in the PR description. Record separately: workspace unit results,
native module/installer results, same-device mTLS demo results, cross-device
results, and real ACT interoperability. A passed category must not be used as a
substitute for an unrun category.

The CI job should have read-only repository permissions, run the collaboration
suite and retained federation/mobile-edge regression gates, and check manifest
coverage/digests. Do not attach a phone identity, TLS private key, issuer secret,
capability file, private journal or complete demo directory to CI. Runtime-floor
testing on Node 22, the supported current Node build, authenticated transport
negative tests, restart/revocation, device thermal/endurance and real ACT
contract checks remain distinct acceptance evidence.

The release is ready for a documented collaboration trial when both owners have
approved concrete peer pins, exact operations/resources and transport endpoints;
the existing federation gates still pass; the authenticated describe/Toybox/
distribution tests succeed; rollback and stop have been exercised; and the final
source, results and unresolved limits are recorded together. ACT model access,
compute, payment and device-control authority are never inferred from successful
source installation.
