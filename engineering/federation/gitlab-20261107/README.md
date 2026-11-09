# Historical GitLab federation source — independent evidence

These four files come from the pinned, verified GitLab main tree at `fc40b1cd1950a01d01835895e4f4c05457077b36`. Their original paths and SHA-256 hashes are in `SOURCE_PROVENANCE.json`. They are retained as historical, independently testable source, **not deployed services**.

Current verified phone-to-phone federation and ACT backend contract are in `../live/`. This historical HMAC credential proof is a first-party offline credential, **not** interoperable L402, a real Lightning payment proof, an ACT-owned hardware attestation or authorization to connect to ACT's private mesh. The watcher must not make paid tool calls or grant devices network access.

Test independently:
```sh
node --test engineering/federation/gitlab-20261107/tests/m2m.test.cjs
PYTHONPATH=engineering/federation/gitlab-20261107 python3 -m unittest discover -s engineering/federation/gitlab-20261107/tests -p test_peer_watch.py -v
```

Future use requires explicit owner review, separate ACT owner identity, signed invite/reply and device attestation. No runtime service has been installed by this import.
