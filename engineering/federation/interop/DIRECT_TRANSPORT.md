# Direct authenticated transport and owner service

This implementation carries the existing signed MIKAYA compute contract over
an actual TLS 1.3 connection between an explicitly paired set of nodes. Each
node retains its own keys, runtime profile, capability replay state, owner
policy and signed receipt ledger. The client can reuse an authenticated
connection for successive bounded requests.

The implementation is in [direct-transport.cjs](direct-transport.cjs). Its
owner-local lifecycle is in [service-control.cjs](service-control.cjs), and
the separate signed accounting records are in
[ledger-receipts.cjs](ledger-receipts.cjs).

## Execution evidence and its scope

The direct transport's **22 focused tests were executed and passed locally**
on November 19, 2026. They opened real loopback TLS sockets and exercised both
roles, certificate and application identity refusals, channel binding,
restart replay refusal, current owner controls, malformed frames, signed
ledger integration, and a measured latency comparison. These local tests do
not by themselves establish a connection between two physical phones.

The current physical execution, deployment, source inventory and measured
results belong in [LIVE_DEPLOYMENT_20261119.md](LIVE_DEPLOYMENT_20261119.md).
At this guide's initial preparation, that deployment verification was in
progress. Use the completed execution report and its raw records for the
actual final state; do not infer that a proposed command below has run.

[EXECUTED_VALIDATION_20261119.md](EXECUTED_VALIDATION_20261119.md) is the earlier
75-case baseline, identified by source-set digest
`f45fdb7a4af0b2f303139eadc35d1d00d9bc3cbc619aceab98da8e9fa970b47a`.
Its physical exchange used owner-carried packets. That historical report
does not describe this later direct transport or its additional tests.

## Protocol and trust boundary

| Boundary | Implemented check |
| --- | --- |
| Network destination | An explicit literal private or loopback IP and unprivileged port; wildcard and public addresses are refused |
| Encrypted connection | TLS 1.3 with mutual certificate validation and an exact SHA-256 certificate pin at each endpoint |
| Application identity | A separate Ed25519 application key; a signed public manifest binds that identity to the TLS certificate and runtime-profile digest |
| Session binding | SHA-256 of a TLS exporter value is checked on each frame and included in worker-signed transport evidence |
| Message parsing | Length-prefixed canonical JSON, exact envelope fields, bounded structure, strict numbers and UTF-8; duplicate-key/noncanonical frames fail |
| Work authorization | The current persisted owner allowlist and enable/kill state, followed by a first-party Macaroon V2 bound to the verified request |
| Replay and budgets | Durable local request-nonce reservation, one-use grants, expiry and byte limits |
| Result verification | Existing Ed25519 request/result verification and independent recomputation of the two permitted deterministic operations |
| Evidence | Signed request/result/profile contract plus separate signed direct-transport evidence |
| Accounting | Each node independently records the verified receipt under an explicit immutable nonmonetary policy |

The permitted operations remain `compute.dot.v1` and `compute.sha256.v1`.
They use the existing bounded job schema. The service does not accept an
arbitrary executable, shell command, wallet operation or firmware request.

The server grants a capability only after the request is authenticated as
the owner-pinned application identity on the mutually authenticated TLS
channel. A caller cannot supply a different public key to obtain authority.
Each grant is bound to the request body, operation, receiving identity,
observed profile, holder and expiry. The worker verifies and durably reserves
that grant before completing work.

The signed portable evidence retains its existing
`OFFLINE_CONFORMANCE` contract label. The additional `direct-evidence.v1`
record separately identifies `TLSv1.3_MUTUAL_PINNED` and binds the TLS
certificate pins, channel, transcript, profile and worker ledger record.
The portable contract's historical label must not be used to describe the
actual network transport as offline.

## Provision an explicit pair

Requirements are Node.js 22+, installed OpenSSL 3 with Ed25519 support, and a
native filesystem that enforces private POSIX permissions. Android/Termux
private storage is suitable for the implemented checks. The lifecycle
controller requires Linux or Android procfs. The complete acceptance suite
also requires Python 3, as described in the [README](README.md).

Run commands from the reviewed repository root. Choose a new state directory
on each node; the names below are examples. Keep state outside the source
tree so source replacement and private state are distinct operations.

```sh
MIKAYA_STATE="$HOME/mikaya-direct-owner-20261119"
MIKAYA_PEER_JSON="$HOME/mikaya-peer-public.json"
MIKAYA_POLICY_JSON="$HOME/mikaya-pair-policy.json"
MIKAYA_PORT=45871

node engineering/federation/interop/direct-transport.cjs init "$MIKAYA_STATE"
```

`init` generates a new synthetic application identity if the directory is
new, collects its actual runtime profile, and generates a separate local TLS
key and certificate. It refuses to replace an existing transport directory.
It can also add transport state to an existing valid handoff test directory.
The private keys stay on the node that generated them.

Exchange **only** each node's public manifest through an owner-approved
channel:

```text
STATE/direct-transport/public-peer.json
```

Save the other node's manifest at `MIKAYA_PEER_JSON`. Check the manifest's
application fingerprint and certificate fingerprint with that operator
before pinning. A familiar device name, matching board string, repository
star or source profile is not a peer authorization.

### Supply explicit accounting terms

Both nodes must use the same explicit policy for their shared fixture. This
version records `NONMONETARY_COMPUTE_UNIT`; these units do not mean satoshis,
Bitcoin transactions, settlement or mining rewards.

The following example creates an **accounting test fixture**: 1,000 units
per accepted fixed operation, split equally between the two pinned
identities. Use these fixture terms only when the operators agree to test
them. The command reads the actual public identities, validates their
signatures, and writes a new policy file. It does not infer an economic
agreement or authorize a payment.

```sh
node - "$MIKAYA_STATE" "$MIKAYA_PEER_JSON" "$MIKAYA_POLICY_JSON" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const direct = require('./engineering/federation/interop/direct-transport.cjs');
const [state, peerFile, output] = process.argv.slice(2);
const own = direct.validatePeer(JSON.parse(fs.readFileSync(
  path.join(state, 'direct-transport', 'public-peer.json'), 'utf8')));
const peer = direct.validatePeer(JSON.parse(fs.readFileSync(peerFile, 'utf8')));
const policy = {
  schema: 'mikaya.interop.distribution-policy.v1',
  policyId: 'owner-compute-fixture-20261119',
  unit: 'NONMONETARY_COMPUTE_UNIT',
  rates: [
    { capability: 'compute.dot.v1', creditUnits: 1000 },
    { capability: 'compute.sha256.v1', creditUnits: 1000 }
  ],
  beneficiaries: [own, peer]
    .map(p => ({ fingerprint: p.fingerprint, basisPoints: 5000 }))
    .sort((a, b) => a.fingerprint < b.fingerprint ? -1 : 1)
};
fs.writeFileSync(output, JSON.stringify(policy, null, 2) + '\n',
  { flag: 'wx', mode: 0o600 });
NODE

node engineering/federation/interop/direct-transport.cjs pin \
  "$MIKAYA_STATE" "$MIKAYA_PEER_JSON" "$MIKAYA_POLICY_JSON"
```

The same policy contents, including beneficiary order, should be used on
both sides. `pin` writes the explicit peer and owner policy, enables this
bounded pair, and initializes a separate locally signed ledger genesis.
It refuses to overwrite an existing pairing. Rates and allocation are bound
into each ledger's signed genesis. An altered policy cannot silently replace
that history.

## Start a direct listener

Set `MIKAYA_BIND_IP` to this device's current explicit private address and
`MIKAYA_PEER_IP` to the paired device's actual reachable private address.
The completed deployment report records the addresses and route used for
its execution. The guards below deliberately refuse unset addresses.

For a foreground listener:

```sh
node engineering/federation/interop/direct-transport.cjs serve \
  "$MIKAYA_STATE" "${MIKAYA_BIND_IP:?Set this device's private IP}" "$MIKAYA_PORT"
```

The readiness line is `DIRECT_TLS_READY`. The private listener lock first
records `STARTING` and becomes `READY` only after successful binding and a
durable startup event. A process that exists but failed to bind is not a
ready listener.

For the managed owner-local service:

```sh
node engineering/federation/interop/service-control.cjs install \
  "$MIKAYA_STATE" "${MIKAYA_BIND_IP:?Set this device's private IP}" "$MIKAYA_PORT"

node engineering/federation/interop/service-control.cjs start "$MIKAYA_STATE"
node engineering/federation/interop/service-control.cjs status "$MIKAYA_STATE"
```

Installation records the exact source paths and hashes. `start` checks
those pins, starts a detached supervisor and waits for a verified worker
process with a `READY` lock. The supervisor performs bounded restarts for
unexpected early worker exits. It preserves disabled policy and kill state;
it does not recover by erasing replay or ledger history.

The controller identifies its own processes through their exact `/proc`
arguments before signalling them. It does not kill an unrelated process
because that process reused an old PID. An inaccessible or ambiguous process
identity remains a reported stop-verification problem.

The controller does not itself register an Android boot receiver, install
Termux:Boot, or change Android background-execution policy. An installed
owner-controlled boot integration can invoke `resume`. A running detached
process alone does not establish survival across an Android force-stop or
reboot.

### Stop, kill and resume

```sh
node engineering/federation/interop/service-control.cjs stop "$MIKAYA_STATE"
node engineering/federation/interop/service-control.cjs resume "$MIKAYA_STATE"
```

`stop` disables work and stops the identified processes. `resume` respects
that disabled state; it does not reverse the owner's stop. Explicit `start`
is the command to re-enable a normally stopped service.

For a persistent emergency deny marker:

```sh
node engineering/federation/interop/service-control.cjs kill "$MIKAYA_STATE"
node engineering/federation/interop/service-control.cjs status "$MIKAYA_STATE"
```

The stop path places the deny marker before parsing transport configuration
or credentials. It preserves malformed state for diagnosis and attempts to
stop only independently identified service processes. `kill` keeps the
marker, preventing a later automatic resume. After the owner resolves the
reason for the stop, these are separate explicit operations:

```sh
node engineering/federation/interop/service-control.cjs clear-kill "$MIKAYA_STATE"
node engineering/federation/interop/service-control.cjs start "$MIKAYA_STATE"
```

Changing installed executable bytes causes a source-pin refusal at the next
verified start. This version has no automatic in-place trust or source
rotation. Use a reviewed deployment/migration procedure and retain the prior
private state, evidence and peer-held checkpoints; do not delete history to
make a gate pass.

## Execute and verify physical work

With the other node's listener ready:

```sh
node engineering/federation/interop/direct-transport.cjs exercise \
  "$MIKAYA_STATE" "${MIKAYA_PEER_IP:?Set the paired device's private IP}" \
  "$MIKAYA_PORT" "$HOME/mikaya-direct-exchange-001.json"
```

The output destination must be new. `exercise` actually requests a grant,
sends the signed operation, verifies the signed response/profile/transport
evidence and records both fixed operations. It also submits the completed
requests again and requires specific replay refusals. Run it from both
devices to exercise both requester/worker directions.

The public result includes the actual negotiated TLS protocol, cipher,
certificate and application pins, request/result transcript, runtime-profile
binding, worker and holder ledger checkpoints, and measured duration.
Macaroon root secrets and private keys are not included.

The holder independently recomputes the returned accounting using its own
explicit policy. A valid peer signature alone cannot authorize different
unit allocation. Each node retains its own signed ledger; reconciliation
must deduplicate the same work observed in both ledgers rather than adding
both copies as new work.

```sh
node engineering/federation/interop/direct-transport.cjs status "$MIKAYA_STATE"
```

Transport status verifies the local receipt ledger and shows its head and
totals. Service status separately reports the supervisor, worker readiness,
source pins and current owner controls.

## Measure connection reuse

```sh
node engineering/federation/interop/direct-transport.cjs benchmark \
  "$MIKAYA_STATE" "${MIKAYA_PEER_IP:?Set the paired device's private IP}" \
  "$MIKAYA_PORT" 10 "$HOME/mikaya-direct-latency-001.json"
```

The count must be 3–20. Each condition executes that many fixed 32-byte
SHA-256 jobs. One condition creates a fresh mutually authenticated TLS
connection for each job; the other reuses one connection. The order
alternates to reduce simple ordering bias. The reused connection's initial
setup time is recorded separately from its per-job latency.

The recorded job latency includes application verification, grants, work and
durable local accounting. It is not raw network bandwidth, native worker
acceleration, or a prediction for larger payloads. The report retains all
samples, medians, the measured ratio and signed receipts. A ratio above one
means fresh connections took longer in that particular run. Results can
vary with the route, device load, storage and radio conditions.

## Current operational limits

| Limit | Current implementation |
| --- | --- |
| Certificate lifetime | Seven days from local creation; expired/not-yet-valid peer manifests are refused |
| Application work | Two fixed bounded operations; request maximum 8,192 bytes |
| Transport frame | Maximum 65,536 encoded bytes |
| Default concurrent connections | Four; owner policy accepts a range of one to eight |
| Frames per connection | At most 256 |
| Connection byte budget | At most 1 MiB in each direction |
| Default idle/total session duration | 15 seconds idle; 120 seconds total |
| Grant lifetime | 60 seconds; one permitted use |
| Signed request/response timestamp dispersion | At most 10,000 ms in either direction; each timestamp must independently be within 60 seconds of the verifier's clock |
| Capability replay journal | 10,000 records or 4 MiB; no automatic pruning |
| Signed receipt ledger | 1,024 entries including genesis; no automatic successor creation |
| Transport event ledger | 20,000 events or 8 MiB |
| Unexpected quick worker exits | Bounded supervisor retry budget; persistent failure stops recovery |

Owners may narrow supported limits through the persisted policy. Missing,
malformed, disabled or mismatched authority fails closed. Allowlist changes
apply to the next operation; current connection limits are enforced by the
message path and policy poll. Lowered time or connection-count limits may
close existing sessions.

The request/response timestamp bound is an explicit short-work protocol
limit. Its signed delta includes clock disagreement and actual elapsed
processing/transport time; it is not a verified estimate of clock offset or
clock synchronization. The current verifier accepts either direction only
within 10,000 ms, retains both independent 60-second freshness checks, and
requires the signed evidence timestamp to equal the response timestamp.
Signatures, identities, nonce, body/result binding, durable replay reservation
and TLS channel binding remain required. Device clocks and signed timestamps
are not rewritten to satisfy this check. An exchange outside the bound is
refused rather than automatically widening the allowance.

Capacity exhaustion requires an explicit reviewed lifecycle decision. The
implementation deliberately retains evidence instead of deleting old records
to regain service. A reserved request remains consumed if a later durable
receipt write fails, and no successful receipt is then returned. This favors
replay safety; it is not an exactly-once distributed delivery protocol.

## ACT operator handoff

Provide the reviewed source commit or archive, its source inventory, the
acceptance command and execution evidence. The ACT operator should run the
acceptance suite on their own actual runtime and retain its fresh output.
The published ACT hardware profiles are reference comparisons; the runtime
collector must report what their machine actually has.

For a subsequent explicitly approved peer trial, each operator creates its
own local state, verifies the other operator's public fingerprints, agrees
to the bounded test policy, pins that manifest and chooses the exact private
route. Each operator independently starts and can stop their own listener.
An F110/Motorola trial cannot enroll an ACT endpoint or replace that
operator's authorization.

The current profiles and signatures are software evidence. They do not
constitute manufacturer hardware attestation, verified human identity,
Bitcoin transaction validation, L402 settlement, cross-host replay consensus
or a mining reward agreement. Those claims require their own implemented
interfaces and execution evidence. Actual owner-device deployment and
direct network activity should be reported affirmatively where the completed
execution records establish them.
