"""Device attestation: proof that a key lives in genuine hardware, inside the genuine app.

Real attestation comes from Google (Play Integrity, Android Key Attestation) and Apple (App Attest).
Those need network calls, Google Cloud credentials and Apple certificate chains, so this slice ships:

* a `Verifier` interface the API depends on,
* a `SimulatedVerifier` plus `SimulatedAuthority`, which stand in for Google and Apple so the whole
  flow can be tested end to end, and
* `PlayIntegrityVerifier` and `AppAttestVerifier` placeholders that say what a real check must do
  and refuse to run. The enrollment API answers 501 until one is wired in.

The simulated authority is NOT a security control. Anyone with this repository can mint its tokens.

Binding: the token commits to the one-time challenge and to the SHA-256 of the device public key, so
a valid token cannot be reused for another key, another device, another challenge or another app.
The same idea is what Play Integrity (`requestHash`) and App Attest (`clientDataHash`) provide.
"""

import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from . import config
from .signing import b64d, b64e, key_from_seed

LEVELS = ("STRONG", "DEVICE", "BASIC")  # mirrors Play Integrity: strong, device, basic
SIM_CONTEXT = b"fortguard.attestation.sim.v1\n"
_ECDSA = ec.ECDSA(hashes.SHA256())
_ECDSA_DET = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)


class AttestationError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


class AttestationNotConfigured(Exception):
    pass


class Verifier:
    def verify(self, *, token, device_guid, app_id, platform, challenge, key_sha256, now_ms):
        """Return the integrity level ("STRONG", "DEVICE" or "BASIC") or raise AttestationError."""
        raise NotImplementedError


class SimulatedAuthority:
    """Plays Google or Apple in tests: signs verdicts about devices."""

    def __init__(self, seed=b"fortguard-dev-attestation-authority"):
        self._private = key_from_seed(seed)
        self.public_key = self._private.public_key()

    def issue(self, *, device_guid, app_id, platform, challenge, key_sha256, level, now_ms):
        claims = {
            "v": 1, "device_guid": device_guid, "app_id": app_id, "platform": platform,
            "challenge": challenge, "key_sha256": key_sha256, "level": level, "iat_ms": now_ms,
        }
        body = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        signature = self._private.sign(SIM_CONTEXT + body, _ECDSA_DET)
        return b64e(body) + "." + b64e(signature)


DEV_AUTHORITY = SimulatedAuthority()  # shared by tests and the demo; development only


class SimulatedVerifier(Verifier):
    def __init__(self, authority_public_key):
        self._public = authority_public_key

    def verify(self, *, token, device_guid, app_id, platform, challenge, key_sha256, now_ms):
        def refuse(message):
            raise AttestationError(403, "attestation_failed", message)

        try:
            body_part, sig_part = token.split(".")
            body = b64d(body_part)
            self._public.verify(b64d(sig_part), SIM_CONTEXT + body, _ECDSA)
            claims = json.loads(body)
        except (InvalidSignature, ValueError, AttributeError, TypeError):
            refuse("attestation token is not valid")
        expected = {
            "device_guid": device_guid, "app_id": app_id, "platform": platform,
            "challenge": challenge, "key_sha256": key_sha256,
        }
        for name, value in expected.items():
            if claims.get(name) != value:
                refuse(f"attestation does not match the enrollment request ({name})")
        iat = claims.get("iat_ms")
        if not isinstance(iat, (int, float)) or abs(now_ms - iat) > config.MAX_SKEW_MS:
            refuse("attestation is not fresh")
        level = claims.get("level")
        if level not in LEVELS:
            refuse("device does not meet integrity requirements")
        return level


class PlayIntegrityVerifier(Verifier):
    """Placeholder. A real check must:

    1. Send the integrity token to Google's decodeIntegrityToken API (or decrypt locally) using the
       project's credentials.
    2. Require `requestDetails.requestHash` to equal SHA-256 over the one-time challenge and the key.
    3. Require `appIntegrity.appRecognitionVerdict == PLAY_RECOGNIZED`, the expected package name
       and the expected signing certificate digest.
    4. Map `deviceIntegrity.deviceRecognitionVerdict` to STRONG / DEVICE / BASIC, and refuse with none.
    5. Check the timestamp is fresh. Optionally verify Android Key Attestation for the key itself.
    """

    def verify(self, **_):
        raise AttestationNotConfigured("Play Integrity verification is not configured")


class AppAttestVerifier(Verifier):
    """Placeholder. A real check must:

    1. Validate the CBOR attestation object: certificate chain to Apple's App Attest root, nonce equal
       to SHA-256 over authData and the clientDataHash (built from the challenge and the key).
    2. Check the app ID hash (team ID plus bundle ID), counter equal to 0, and key identifier.
    3. Store the key and verify later assertions with their counters rising.
    """

    def verify(self, **_):
        raise AttestationNotConfigured("App Attest verification is not configured")
