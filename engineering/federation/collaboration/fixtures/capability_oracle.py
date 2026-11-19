#!/usr/bin/env python3
"""Independent stdlib serialization/HMAC oracle for the project capability v1.

This is a fixture oracle, not a production authorization implementation. The
fixed root key below is deliberately public test material. Never enroll it.
"""

import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path


ROOT_DOMAIN = b"MIKAYA-ACT-CAPABILITY-V1-ROOT\0"
CAVEAT_DOMAIN = b"MIKAYA-ACT-CAPABILITY-V1-CAVEAT\0"
FIXTURE = Path(__file__).with_name("capability-v1.json")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def encode(claims, caveats, key):
    signature = hmac.digest(key, ROOT_DOMAIN + canonical(claims), "sha256")
    for caveat in caveats:
        signature = hmac.digest(signature, CAVEAT_DOMAIN + canonical(caveat), "sha256")
    envelope = {"claims": claims, "caveats": caveats, "mac": signature.hex()}
    body = base64.urlsafe_b64encode(canonical(envelope)).rstrip(b"=").decode("ascii")
    return "mcap1." + body


def build_fixture():
    now = 1_800_000_000_000
    claims = {
        "schema": "mikaya.act.capability.v1",
        "version": 1,
        "issuer": "fixture-mikaya",
        "issuerKeyId": "fixture-root-1",
        "audience": "fixture-collaboration",
        "peer": "fixture-act-peer",
        "keyBinding": "sha256:" + "b" * 64,
        "grantId": "fixture-grant-0001",
        "issuerEpoch": 4,
        "policyVersion": "fixture-policy-1",
        "scopes": ["evidence.ingest.v1", "receipt.read.v1"],
        "resources": ["sha256:" + "a" * 64],
        "notBeforeMs": now,
        "expiresAtMs": now + 120_000,
        "limits": {"uses": 3, "maxBytes": 8192, "maxConcurrent": 1},
    }
    caveats = [
        {"field": "scopes", "value": ["receipt.read.v1"]},
        {"field": "limits.uses", "value": 1},
        {"field": "limits.maxBytes", "value": 1024},
        {"field": "expiresAtMs", "value": now + 90_000},
    ]
    key = bytes(range(32))
    return {
        "warning": "Public deterministic test material only. Never use this issuer key or peer binding in deployment.",
        "profile": "mikaya.act.capability.v1",
        "nowMs": now,
        "rootKeyHex": key.hex(),
        "claims": claims,
        "caveats": caveats,
        "baseToken": encode(claims, [], key),
        "attenuatedToken": encode(claims, caveats, key),
        "expected": {
            "grantId": claims["grantId"],
            "usageLimit": 1,
            "grantUsageLimit": 3,
            "expiresAtMs": now + 90_000,
            "scopes": ["receipt.read.v1"],
            "maxBytes": 1024,
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write deterministic fixture instead of checking it")
    args = parser.parse_args()
    generated = build_fixture()
    if args.write:
        FIXTURE.write_text(json.dumps(generated, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
    else:
        recorded = json.loads(FIXTURE.read_text(encoding="ascii"))
        if recorded != generated:
            raise SystemExit("FAIL: capability fixture differs from Python stdlib oracle")
    print(json.dumps({
        "oracle": "python-stdlib-hmac-sha256",
        "result": "PASS",
        "vectors": 2,
        "fixtureSha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
