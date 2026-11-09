"""Device-key signing for telemetry (ES256: ECDSA over P-256 with SHA-256).

Each enrolled device signs the canonical bytes of every batch with a private key that never leaves
the device (Secure Enclave on iOS, Android KeyStore on Android). The server holds only the public key
and verifies. Signatures are DER encoded, which is what both platforms produce.

Not done yet: Protobuf bytes instead of canonical JSON (backlog E1-09, needs the protobuf toolchain),
and key rotation inside a live session.
"""

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

TELEMETRY_CONTEXT = b"fortguard.telemetry.v1\n"  # domain separation: a telemetry signature is never valid elsewhere
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

_VERIFY = ec.ECDSA(hashes.SHA256())
_SIGN_DETERMINISTIC = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d(text: str) -> bytes:
    if not isinstance(text, str):
        raise ValueError("not a string")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical_bytes(payload):
    body = {k: v for k, v in payload.items() if k != "signature"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def key_from_seed(seed: bytes) -> ec.EllipticCurvePrivateKey:
    """A reproducible P-256 key for simulated devices. Real devices generate keys in hardware."""
    value = int.from_bytes(hashlib.sha256(seed).digest(), "big") % (P256_ORDER - 1) + 1
    return ec.derive_private_key(value, ec.SECP256R1())


def public_key_to_b64(public_key) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return b64e(der)


def load_public_key(text: str):
    """Load a base64url SPKI P-256 public key. Raises ValueError for anything else."""
    try:
        key = serialization.load_der_public_key(b64d(text))
    except Exception as exc:
        raise ValueError("not a valid public key") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("public key must be an EC P-256 key")
    return key


def key_sha256(public_key) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def sign_payload(payload, private_key, deterministic=True) -> str:
    """Sign a telemetry batch. `deterministic` makes samples reproducible; hardware keys randomize."""
    algorithm = _SIGN_DETERMINISTIC if deterministic else _VERIFY
    return b64e(private_key.sign(TELEMETRY_CONTEXT + canonical_bytes(payload), algorithm))


def verify_payload(payload, public_key) -> bool:
    signature = payload.get("signature")
    if not isinstance(signature, str):
        return False
    try:
        public_key.verify(b64d(signature), TELEMETRY_CONTEXT + canonical_bytes(payload), _VERIFY)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
