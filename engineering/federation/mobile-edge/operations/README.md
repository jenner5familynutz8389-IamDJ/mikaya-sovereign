# Exact launcher sources used for native acceptance

These are the exact launcher and proof-reader bytes used with runtime commit
`78a363fd516634cd12331810dbde6a938b157e1b` on the two owner devices. They are
installation-specific audit sources, not a general installer. The runtime's
eleven-file manifest remains pinned to SHA-256
`feb22bd2697ae77c1324d2e61858bcd863454df97bc27a556617ca931c13ca5d`.
The exact manifest is retained as
[`RUNTIME-SOURCE-78a363f.json`](RUNTIME-SOURCE-78a363f.json).

| File | SHA-256 |
| --- | --- |
| `launch-runtime-78a363f.py` | `68aab928b0a19d2c07f07ed5f6839f15185ba9614f426ac8391d26e4a56f53a6` |
| `read-native-proof-78a363f.cjs` | `8d128b032fcc6a32c8c84dfbf23467ca488017ad797fbd3d7ab7609b81dfa2dc` |

The launcher verifies the runtime, private configuration and native MTG source
pins before starting Node. A configured Motorola profile also verifies the
fixed existing Termux execution library and supplies its exact preload path
before Node starts. The F110 observation route retains the existing publisher
coordination lock. The environment is closed; no caller-supplied executable,
remote host, initialization, recovery or policy override is accepted.

The proof reader signs a localhost request using the already installed owner
identity, verifies the reply and emits only its public key, signed request,
signed reply and capture metadata. It never exports the private key. Calling
it does not create an observation or relax the 60-second freshness requirement.

Saved captures can be verified offline with
[`../verify-native-capture.cjs`](../verify-native-capture.cjs), which needs no
phone, private key, remote connection or native execution library. Verification
uses each capture's recorded time and does not establish current freshness.

See the [native acceptance report](../NATIVE_ACCEPTANCE_20261118.md) for the
actual results and the installed `mikaya-local-evidence` command.
