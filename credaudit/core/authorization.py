"""Cryptographic authorization/signature verification for scope files.

A free-text field like `authorized_by: "Jane Doe, CISO"` establishes
*intent* but cannot be verified by software -- anyone can type that
string into a YAML file. This module adds a real, optional verification
layer on top: an engagement owner (a CISO, engagement lead, whoever your
process designates) holds an Ed25519 private key. The scope file carries
a signature over its own content. Anyone running credaudit can verify
that signature against a public key before the engagement is allowed to
proceed with `require_signature: true` in the scope file.

Two trust modes, in increasing order of assurance:

  1. Embedded key (`signer_public_key` inside the scope YAML itself).
     Verifying against this only proves the file has not been altered
     since it was signed with *some* Ed25519 key -- it does NOT prove
     that key belongs to a legitimate approver, because an attacker who
     can edit the scope file can just as easily replace the embedded
     key and re-sign with a key of their own. This mode exists for
     convenience/testing, not for real assurance.

  2. External trusted key (passed explicitly to `verify_scope_signature`
     / `Scope.load(..., trusted_public_key=...)` from a source outside
     the scope file -- a key file in your own controlled repo, a CI
     secret, a location your org already trusts). This is the mode that
     actually proves something: the verifier's notion of "whose key is
     trusted" comes from somewhere the scope file's own author cannot
     edit.

Stated plainly, because this is a real limitation and not a detail to
gloss over: even mode 2 only proves the scope file's *content* has not
changed since a holder of the trusted private key signed it. It does
NOT prove that signer was actually authorized, by your organization's
real process, to approve this specific engagement -- that is a
governance question this tool cannot answer from inside a YAML file,
cryptographically signed or not. Signing closes the "anyone can type
free text" gap; it does not replace your approval process.
"""
from __future__ import annotations

import base64
import json


class AuthorizationError(Exception):
    """Raised for any signature-generation or -verification failure,
    including the 'cryptography' package not being installed."""


def _load_crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as e:  # pragma: no cover -- exercised only without the dep installed
        raise AuthorizationError(
            "Cryptographic signature verification requires the 'cryptography' "
            "package. Run: pip install cryptography"
        ) from e
    return Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature, serialization


def generate_keypair() -> tuple:
    """Generate a new Ed25519 keypair. Returns (private_key_pem,
    public_key_pem), both as bytes (PKCS8/SubjectPublicKeyInfo, PEM
    encoded, unencrypted).

    credaudit never stores, transmits, or logs the private key -- it is
    generated here purely as a convenience for engagement owners setting
    this up for the first time. Store it wherever your org already
    keeps sensitive key material (password manager, HSM, etc).
    """
    Ed25519PrivateKey, _, _, serialization = _load_crypto()
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def canonical_bytes(data: dict) -> bytes:
    """Deterministic byte representation of a scope dict for signing.

    Signing JSON derived from the parsed YAML (rather than the raw file
    bytes) means formatting-only changes -- re-indenting, comment edits,
    key order, line endings -- never break a valid signature, while any
    change to actual scope *content* does. `default=str` handles the
    `datetime.date` objects PyYAML produces for start_date/end_date.
    """
    return json.dumps(data, sort_keys=True, default=str).encode("utf-8")


def _load_ed25519_private_key(private_key_pem: bytes):
    Ed25519PrivateKey, _, _, serialization = _load_crypto()
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (ValueError, TypeError) as e:
        raise AuthorizationError(f"Could not load private key: {e}") from e
    if not isinstance(private_key, Ed25519PrivateKey):
        raise AuthorizationError("Private key is not an Ed25519 key.")
    return private_key


def sign_scope_data(data: dict, private_key_pem: bytes) -> str:
    """Sign the canonical bytes of `data` (a scope dict with the
    `signature` key already removed, if present) and return a base64
    signature string."""
    private_key = _load_ed25519_private_key(private_key_pem)
    signature = private_key.sign(canonical_bytes(data))
    return base64.b64encode(signature).decode("ascii")


def verify_scope_data(data: dict, signature_b64: str, public_key_pem: bytes) -> bool:
    """Verify a base64 signature over the canonical bytes of `data`.
    Returns True/False; never raises for an invalid (as opposed to
    malformed/unparseable) signature or key."""
    Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature, serialization = _load_crypto()
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, canonical_bytes(data))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def sign_bytes(data: bytes, private_key_pem: bytes) -> str:
    """Lower-level signing helper for arbitrary bytes (used by the audit
    log's signed manifest, which signs a JSON manifest, not a scope
    file)."""
    private_key = _load_ed25519_private_key(private_key_pem)
    return base64.b64encode(private_key.sign(data)).decode("ascii")


def verify_bytes(data: bytes, signature_b64: str, public_key_pem: bytes) -> bool:
    Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature, serialization = _load_crypto()
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        public_key.verify(base64.b64decode(signature_b64), data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
