#!/usr/bin/env python3
"""Synthetic, offline reference for federation-node.cjs wire interoperability.

JSON-line stdin/stdout only: this process opens no listener or remote connection.
It is not ACT software, a device attestation, enrollment, or a production service.
Canonicalization, hashing, and bounded compute use the Python standard library.
Ed25519 uses installed cryptography, or installed OpenSSL 3 via bounded commands.
Private keys remain ephemeral inside this reference process/backend. Its replay
sets last only for this process; production must retain the Node durable journals.

Each line: {"id":1,"op":"...",...}; reply: {"id":1,"ok":true,"result":...}.
Operations: describe, init, pin, revoke, canonical, fingerprint, compute,
sign-request, verify-request, sign-response, verify-response, receipt,
verify-receipt, respond. No key import/export or arbitrary-code operation exists.
"""

import base64
import binascii
import hashlib
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile

MAX_SAFE_INTEGER = 9007199254740991
MAX_LINE_BYTES = 65536
DOMAIN = "MIKAYA-INDEPENDENT-FEDERATION/1\n"
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")
CAPABILITIES = ("compute.dot.v1", "compute.sha256.v1")
ROUTES = ("/v1/hello", "/v1/task")
SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")


class Refused(ValueError):
    """An input failed the reference contract."""


def require(condition, message):
    if not condition:
        raise Refused(message)


def exact(value, fields):
    return type(value) is dict and set(value) == set(fields)


def safe_integer(value):
    # bool is an int subclass in Python, but Number.isSafeInteger(true) is false.
    if type(value) is int:
        return abs(value) <= MAX_SAFE_INTEGER
    return (type(value) is float and math.isfinite(value)
            and value.is_integer() and abs(value) <= MAX_SAFE_INTEGER)


def matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def js_quote(value):
    """JSON.stringify string escaping, including well-formed lone surrogates."""
    escaped = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f',
               '\n': '\\n', '\r': '\\r', '\t': '\\t'}
    result = ['"']
    index = 0
    while index < len(value):
        char = value[index]
        code = ord(char)
        if char in escaped:
            result.append(escaped[char])
        elif code < 32:
            result.append("\\u%04x" % code)
        elif 0xD800 <= code <= 0xDBFF and index + 1 < len(value) and 0xDC00 <= ord(value[index + 1]) <= 0xDFFF:
            result.append(chr(0x10000 + ((code - 0xD800) << 10) + ord(value[index + 1]) - 0xDC00))
            index += 1
        elif 0xD800 <= code <= 0xDFFF:
            result.append("\\u%04x" % code)
        else:
            result.append(char)
        index += 1
    return "".join(result) + '"'


def canonical(value):
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is str:
        return js_quote(value)
    if safe_integer(value):
        return str(int(value))  # Includes JavaScript's -0 -> 0 behavior.
    if type(value) is list:
        return "[" + ",".join(canonical(item) for item in value) + "]"
    if type(value) is dict and all(type(key) is str for key in value):
        # JS Array.sort orders UTF-16 code units, not Unicode scalar values.
        keys = sorted(value, key=lambda key: key.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(js_quote(key) + ":" + canonical(value[key]) for key in keys) + "}"
    raise Refused("noncanonical data refused")


def sha(raw):
    if type(raw) is str:
        raw = raw.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def normalize_public_pem(pem):
    """Exactly the Ed25519 SPKI PEM bytes that Node's key.export emits.

    Fingerprints hash normalized PEM WITH its final LF, not raw input or DER.
    This strict reference intentionally accepts public Ed25519 SPKI only.
    """
    require(type(pem) is str and len(pem) <= 4096, "invalid Ed25519 public PEM")
    match = re.fullmatch(r"\s*-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+/=\s]+)-----END PUBLIC KEY-----\s*", pem)
    require(match is not None, "invalid Ed25519 public PEM")
    try:
        der = base64.b64decode(re.sub(r"\s", "", match.group(1)), validate=True)
    except (ValueError, binascii.Error):
        raise Refused("invalid Ed25519 public PEM") from None
    require(len(der) == 44 and der.startswith(SPKI_ED25519_PREFIX), "public key must be Ed25519 SPKI")
    encoded = base64.b64encode(der).decode("ascii")
    return ("-----BEGIN PUBLIC KEY-----\n" + "\n".join(encoded[n:n + 64] for n in range(0, len(encoded), 64))
            + "\n-----END PUBLIC KEY-----\n")


def fingerprint(pem):
    return sha(normalize_public_pem(pem))


class Crypto:
    """Standard Ed25519 providers; no cryptographic primitive is reimplemented."""

    def __init__(self):
        preference = os.environ.get("MIKAYA_REFERENCE_CRYPTO", "auto")
        require(preference in ("auto", "cryptography", "openssl"), "unknown reference crypto backend")
        if preference != "openssl":
            try:
                import cryptography
                from cryptography.exceptions import InvalidSignature
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                self.serialization = serialization
                self.invalid_signature = InvalidSignature
                self.private = Ed25519PrivateKey.generate()
                self.public_pem = self.private.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
                self.backend = "cryptography"
                self.version = cryptography.__version__
                return
            except ImportError:
                if preference == "cryptography":
                    raise Refused("Ed25519 requires installed Python cryptography; requested backend unavailable") from None
        self.openssl = shutil.which("openssl")
        require(self.openssl is not None,
                "Ed25519 backend unavailable: require installed Python cryptography or OpenSSL 3 with Ed25519 support")
        self.backend = "openssl"
        self.version = self._openssl(["version"]).decode("ascii", errors="replace").strip()
        require(re.match(r"OpenSSL [3-9]\.", self.version) is not None, "OpenSSL 3 or newer required for bounded Ed25519 reference")
        self.private = self._openssl(["genpkey", "-algorithm", "ED25519"])
        self.public_pem = self._openssl(["pkey", "-pubout"], self.private).decode("ascii")
        self.public_pem = normalize_public_pem(self.public_pem)

    def _openssl(self, args, data=None, allow_invalid=False):
        try:
            result = subprocess.run([self.openssl, *args], input=data, capture_output=True,
                                    timeout=5, check=False, shell=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Refused("bounded OpenSSL Ed25519 operation unavailable or timed out") from None
        require(len(result.stdout) <= MAX_LINE_BYTES and len(result.stderr) <= MAX_LINE_BYTES,
                "OpenSSL output exceeded reference bound")
        if allow_invalid:
            return result.returncode == 0
        require(result.returncode == 0, "OpenSSL Ed25519 operation failed")
        return result.stdout

    @staticmethod
    def _write_private_file(directory, name, data):
        path = os.path.join(directory, name)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        return path

    def sign(self, message):
        if self.backend == "cryptography":
            signature = self.private.sign(message)
        else:
            with tempfile.TemporaryDirectory(prefix="mikaya-reference-sign-") as directory:
                os.chmod(directory, 0o700)
                key = self._write_private_file(directory, "key.pem", self.private)
                data = self._write_private_file(directory, "message", message)
                signature = self._openssl(["pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", data])
        require(len(signature) == 64, "invalid Ed25519 provider output")
        return base64.b64encode(signature).decode("ascii")

    def verify(self, pem, message, signature):
        if not (type(signature) is str and len(signature) <= 180
                and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", signature)):
            return False
        try:
            decoded = base64.b64decode(signature, validate=True)
        except (ValueError, binascii.Error):
            return False
        if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != signature:
            return False
        public_pem = normalize_public_pem(pem).encode("ascii")
        if self.backend == "cryptography":
            public = self.serialization.load_pem_public_key(public_pem)
            try:
                public.verify(decoded, message)
                return True
            except self.invalid_signature:
                return False
        with tempfile.TemporaryDirectory(prefix="mikaya-reference-verify-") as directory:
            os.chmod(directory, 0o700)
            key = self._write_private_file(directory, "public.pem", public_pem)
            data = self._write_private_file(directory, "message", message)
            sig = self._write_private_file(directory, "signature", decoded)
            return self._openssl(["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", key,
                                  "-in", data, "-sigfile", sig], allow_invalid=True)


def compute_job(job):
    require(exact(job, ("schema", "id", "capability", "payload"))
            and job["schema"] == "mikaya.federation.job.v1"
            and matches(NONCE_RE, job["id"]) and job["capability"] in CAPABILITIES,
            "job capability or schema refused")
    payload = job["payload"]
    if job["capability"] == "compute.sha256.v1":
        require(exact(payload, ("challengeHex",)) and matches(SHA_RE, payload["challengeHex"]),
                "unbounded hash request")
        return sha(bytes.fromhex(payload["challengeHex"]))
    require(exact(payload, ("a", "b")) and type(payload["a"]) is list
            and type(payload["b"]) is list and 1 <= len(payload["a"]) <= 16
            and len(payload["a"]) == len(payload["b"])
            and all(safe_integer(value) and abs(value) <= 1000 for value in payload["a"] + payload["b"]),
            "unbounded dot product")
    return sum(int(a) * int(b) for a, b in zip(payload["a"], payload["b"]))


def make_receipt(job, worker):
    require(matches(SHA_RE, worker), "invalid worker fingerprint")
    return {"schema": "mikaya.federation.result.v1", "jobId": job["id"],
            "capability": job["capability"], "workerFingerprint": worker,
            "requestSha256": sha(canonical(job)), "result": compute_job(job)}


def verify_receipt(body, job, worker):
    expected = make_receipt(job, worker)
    require(exact(body, expected.keys()) and canonical(body) == canonical(expected),
            "peer computation receipt inconsistent")
    return True


class Reference:
    def __init__(self):
        self.crypto = None
        self.peers = {}
        self.nonces = set()
        self.jobs = set()

    def initialized(self):
        require(self.crypto is not None, "initialize synthetic reference identity first")

    def peer(self, identity):
        require(matches(SHA_RE, identity) and identity in self.peers, "unknown untrusted peer")
        peer = self.peers[identity]
        require(peer["enabled"] is True, "peer revoked")
        return peer["publicPem"]

    def signed(self, kind, envelope):
        self.initialized()
        return {**envelope, "signature": self.crypto.sign((DOMAIN + kind + "\n" + canonical(envelope)).encode("utf-8"))}

    def sign_request(self, args):
        self.initialized()
        require(matches(SHA_RE, args["to"]) and matches(NONCE_RE, args["nonce"])
                and args["route"] in ROUTES and args["method"] == "POST"
                and safe_integer(args["issuedAtMs"]), "invalid outbound request")
        self.peer(args["to"])
        envelope = {"schema": "mikaya.federation.request.v1", "from": self.fingerprint,
                    "to": args["to"], "method": args["method"], "route": args["route"],
                    "bodySha256": sha(canonical(args["body"])), "nonce": args["nonce"],
                    "issuedAtMs": args["issuedAtMs"]}
        return self.signed("REQ", envelope)

    def verify_request(self, args):
        self.initialized()
        auth = args["auth"]
        require(exact(auth, ("schema", "from", "to", "method", "route", "bodySha256", "nonce", "issuedAtMs", "signature"))
                and auth["schema"] == "mikaya.federation.request.v1"
                and matches(SHA_RE, auth["from"]) and auth["to"] == self.fingerprint,
                "wrong recipient target or signed request shape")
        require(matches(NONCE_RE, auth["nonce"]) and safe_integer(auth["issuedAtMs"])
                and safe_integer(args["nowMs"]) and abs(args["nowMs"] - auth["issuedAtMs"]) <= 60000,
                "request expired")
        pem = self.peer(auth["from"])
        require(args["method"] == "POST" and args["route"] in ROUTES
                and auth["method"] == args["method"] and auth["route"] == args["route"]
                and auth["bodySha256"] == sha(canonical(args["body"])), "request path/body mismatch")
        unsigned = {key: value for key, value in auth.items() if key != "signature"}
        require(fingerprint(pem) == auth["from"] and self.crypto.verify(
            pem, (DOMAIN + "REQ\n" + canonical(unsigned)).encode("utf-8"), auth["signature"]),
            "request signature invalid")
        nonce_key = (auth["from"], auth["nonce"])
        require(len(self.nonces) < 20000, "nonce journal capacity reached")
        require(nonce_key not in self.nonces, "request replay refused")
        self.nonces.add(nonce_key)
        return {"verified": True, "fingerprint": auth["from"]}

    def sign_response(self, args):
        self.initialized()
        self.peer(args["to"])
        require(matches(NONCE_RE, args["inReplyTo"]) and safe_integer(args["issuedAtMs"]),
                "invalid outbound response")
        return self.signed("RES", {"schema": "mikaya.federation.response.v1", "from": self.fingerprint,
                                  "to": args["to"], "inReplyTo": args["inReplyTo"],
                                  "bodySha256": sha(canonical(args["body"])), "issuedAtMs": args["issuedAtMs"]})

    def verify_response(self, args):
        self.initialized()
        auth = args["auth"]
        require(exact(auth, ("schema", "from", "to", "inReplyTo", "bodySha256", "issuedAtMs", "signature"))
                and auth["schema"] == "mikaya.federation.response.v1"
                and auth["from"] == args["expectedPeer"] and auth["to"] == self.fingerprint
                and auth["inReplyTo"] == args["nonce"] and auth["bodySha256"] == sha(canonical(args["body"]))
                and safe_integer(auth["issuedAtMs"]) and safe_integer(args["nowMs"])
                and abs(args["nowMs"] - auth["issuedAtMs"]) <= 60000,
                "response origin, digest or nonce mismatch")
        pem = self.peer(args["expectedPeer"])
        unsigned = {key: value for key, value in auth.items() if key != "signature"}
        require(fingerprint(pem) == args["expectedPeer"] and self.crypto.verify(
            pem, (DOMAIN + "RES\n" + canonical(unsigned)).encode("utf-8"), auth["signature"]),
            "response signature invalid")
        return True

    def dispatch(self, args):
        require(type(args) is dict and type(args.get("op")) is str, "expected an operation object")
        operation = args["op"]
        if operation == "describe":
            return {"schema": "mikaya.synthetic-language-reference.v1", "referenceOnly": True,
                    "runtime": "Python " + platform.python_version(), "pid": os.getpid(),
                    "transport": "local-stdio-only", "persistentReplayProtection": False}
        if operation == "canonical":
            encoded = canonical(args["value"])
            return {"canonical": encoded, "utf8Hex": encoded.encode("utf-8").hex(), "sha256": sha(encoded)}
        if operation == "fingerprint":
            pem = normalize_public_pem(args["publicPem"])
            return {"publicPem": pem, "fingerprint": sha(pem)}
        if operation == "compute":
            return compute_job(args["job"])
        if operation == "verify-receipt":
            return verify_receipt(args["body"], args["job"], args["expectedWorker"])
        if operation == "init":
            require(self.crypto is None, "reference identity already initialized")
            self.crypto = Crypto()
            self.fingerprint = fingerprint(self.crypto.public_pem)
            return {"referenceOnly": True, "publicPem": self.crypto.public_pem,
                    "fingerprint": self.fingerprint, "cryptoBackend": self.crypto.backend,
                    "cryptoVersion": self.crypto.version, "privateKeyExported": False, "pid": os.getpid()}
        self.initialized()
        if operation == "pin":
            pem = normalize_public_pem(args["publicPem"])
            identity = fingerprint(pem)
            require(identity == args["expectedFingerprint"] and identity != self.fingerprint,
                    "out-of-band peer fingerprint mismatch")
            require(identity in self.peers or len(self.peers) < 16, "peer capacity reached")
            self.peers[identity] = {"publicPem": pem, "enabled": True}
            return {"fingerprint": identity, "referenceOnly": True}
        if operation == "revoke":
            self.peer(args["fingerprint"])
            self.peers[args["fingerprint"]]["enabled"] = False
            return {"fingerprint": args["fingerprint"], "enabled": False}
        if operation == "sign-request":
            return self.sign_request(args)
        if operation == "verify-request":
            return self.verify_request(args)
        if operation == "sign-response":
            return self.sign_response(args)
        if operation == "verify-response":
            return self.verify_response(args)
        if operation == "receipt":
            return make_receipt(args["job"], self.fingerprint)
        if operation == "respond":
            require(args["route"] == "/v1/task", "reference responds only to bounded task fixtures")
            peer = self.verify_request(args)
            body = make_receipt(args["body"], self.fingerprint)
            key = (peer["fingerprint"], args["body"]["id"])
            require(key not in self.jobs, "duplicate job replay refused")
            require(len(self.jobs) < 20000, "job journal capacity reached")
            self.jobs.add(key)
            auth = self.sign_response({"to": peer["fingerprint"], "inReplyTo": args["auth"]["nonce"],
                                       "body": body, "issuedAtMs": args["nowMs"]})
            return {"auth": auth, "body": body}
        raise Refused("unsupported reference operation")


def invalid_constant(_):
    raise Refused("non-JSON number refused")


def main():
    reference = Reference()
    while True:
        line = sys.stdin.buffer.readline(MAX_LINE_BYTES + 1)
        if not line:
            return
        request_id = None
        try:
            if len(line) > MAX_LINE_BYTES:
                while not line.endswith(b"\n"):
                    line = sys.stdin.buffer.readline(MAX_LINE_BYTES + 1)
                    if not line:
                        break
                raise Refused("reference input exceeds 65536 bytes")
            request = json.loads(line.decode("utf-8"), parse_constant=invalid_constant)
            if type(request) is dict and safe_integer(request.get("id")):
                request_id = int(request["id"])
            result = reference.dispatch(request)
            reply = {"id": request_id, "ok": True, "result": result}
        except (Refused, KeyError, TypeError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
            # Do not echo supplied key material, payloads, tracebacks or file paths.
            message = str(error) if isinstance(error, Refused) else "malformed reference input refused"
            reply = {"id": request_id, "ok": False, "error": message}
        output = json.dumps(reply, ensure_ascii=True, separators=(",", ":"))
        if len(output) > MAX_LINE_BYTES * 8:
            output = json.dumps({"id": request_id, "ok": False, "error": "reference output bound exceeded"})
        sys.stdout.write(output + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
