from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa

from app.keys import compute_kid, load_public_key_pem

COMMITTED_KEY_PATH = "app/keys/client_public.pem"
MINIMUM_KEY_SIZE = 2048


def test_committed_client_public_key_exists() -> None:
    assert Path(COMMITTED_KEY_PATH).is_file()


def test_committed_client_public_key_is_a_usable_rsa_key() -> None:
    from cryptography.hazmat.primitives import serialization

    pem = load_public_key_pem(COMMITTED_KEY_PATH)
    key = serialization.load_pem_public_key(pem.encode())

    assert isinstance(key, rsa.RSAPublicKey)
    assert key.key_size >= MINIMUM_KEY_SIZE


def test_committed_client_public_key_has_a_computable_kid() -> None:
    assert compute_kid(load_public_key_pem(COMMITTED_KEY_PATH))


def test_no_private_key_is_committed_alongside_it() -> None:
    committed = list(Path("app/keys").glob("*"))

    assert committed
    for path in committed:
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError, ValueError:
            # A binary/non-UTF-8 file can't be a PEM private key; its presence
            # alongside the public key would be caught by a different guard.
            continue
        assert "PRIVATE" not in content
