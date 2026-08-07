"""Pure RSA key helpers.

This module holds no configuration and no cache on purpose: app.auth imports it for the
client public key and app.jwt imports it for the signing key, so any config access here
would create a circular import. Caching lives in those two consumers.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm


def load_public_key_pem(path: str) -> str:
    """Read a PEM-encoded public key from disk."""
    return Path(path).read_text(encoding="utf-8")


def derive_public_key_pem(private_key_pem: str) -> str:
    """Return the PEM-encoded public half of a PEM-encoded RSA private key."""
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        msg = "expected an RSA private key"
        raise TypeError(msg)
    return (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )


def public_key_to_jwk(public_key_pem: str) -> dict[str, str]:
    """Convert a PEM-encoded RSA public key to its JWK key material."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    if not isinstance(public_key, rsa.RSAPublicKey):
        msg = "expected an RSA public key"
        raise TypeError(msg)
    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    # PyJWT emits key_ops; JWKS convention prefers "use", which app.jwks adds instead.
    return {"kty": jwk["kty"], "n": jwk["n"], "e": jwk["e"]}


def compute_kid(public_key_pem: str) -> str:
    """Return the RFC 7638 JWK thumbprint of an RSA public key."""
    jwk = public_key_to_jwk(public_key_pem)
    canonical = json.dumps(
        {"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
