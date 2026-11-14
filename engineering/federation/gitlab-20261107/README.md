# Historical GitLab federation source — independent evidence

These four files come from the pinned, verified GitLab main tree at `fc40b1cd1950a01d01835895e4f4c05457077b36`. Their original paths and SHA-256 hashes are in `SOURCE_PROVENANCE.json`. They are retained as historical, independently testable source, **not deployed services**.

Current verified phone-to-phone federation and ACT backend contract are in `../live/`. This historical HMAC credential proof is a first-party offline credential, **not** interoperable L402, a real Lightning payment proof, an ACT-owned hardware attestation or authorization to connect to ACT's private mesh. The watcher must not make paid tool calls or grant devices network access.

Test independently:
```sh
node --test engineering/federation/gitlab-20261107/tests/m2m.test.cjs
PYTHONPATH=engineering/federation/gitlab-20261107 python3 -m unittest discover -s engineering/federation/gitlab-20261107/tests -p test_peer_watch.py -v
```

Future use requires explicit owner review, separate ACT owner identity, signed invite/reply and device attestation. No runtime service has been installed by this import.

## Human principal and device authority

Governance follows **human principal → owned device → delegated agents**. Each device has one accountable human owner; the same person may own both F110 and Motorola. Agents act within that owner's existing delegation, while independent collaborators retain their own owners, identities, keys and decisions. A node name, signing identity or hardware proof alone does not grant the human owner's permission. This clarifies the existing design; it adds no enrollment mechanism or claim that real-world human identity has been verified.

The existing `m2m-gate.cjs` flow retains its pinned signed hello, `ownerApproval` and seller-local `settlementVerifier`. Its first-party macaroon remains constrained to `buyer`, `seller`, `jobId`, `capability`, `payloadSha256`, `invoicePaymentHash`, `amountSats`, `expiresAtMs` and `uses: 1`, with durable replay refusal. A machine signature, token, historical payment or telemetry digest cannot replace those checks; `authorizeCredential` still returns `execute: false`. Source integrity, hardware attestation, owner permission and actual invoice settlement remain separate evidence, and this wording enables no payment or remote execution.
