from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from app.keys import compute_kid, derive_public_key_pem, load_public_key_pem, public_key_to_jwk

if TYPE_CHECKING:
    from pathlib import Path


def test_load_public_key_pem_reads_file(tmp_path: Path, client_keys: tuple[str, str]) -> None:
    path = tmp_path / "pub.pem"
    path.write_text(client_keys[1], encoding="utf-8")

    assert load_public_key_pem(str(path)) == client_keys[1]


def test_load_public_key_pem_raises_for_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_public_key_pem(str(tmp_path / "absent.pem"))


def test_derive_public_key_pem_matches_generated_public_key(client_keys: tuple[str, str]) -> None:
    private_pem, public_pem = client_keys

    assert derive_public_key_pem(private_pem) == public_pem


def test_public_key_to_jwk_contains_only_rsa_material(client_keys: tuple[str, str]) -> None:
    jwk = public_key_to_jwk(client_keys[1])

    assert set(jwk) == {"kty", "n", "e"}
    assert jwk["kty"] == "RSA"
    assert jwk["e"] == "AQAB"


def test_compute_kid_is_stable_for_the_same_key(client_keys: tuple[str, str]) -> None:
    assert compute_kid(client_keys[1]) == compute_kid(client_keys[1])


def test_compute_kid_differs_between_keys(
    client_keys: tuple[str, str],
    signing_keys: tuple[str, str],
) -> None:
    assert compute_kid(client_keys[1]) != compute_kid(signing_keys[1])


def test_compute_kid_is_unpadded_base64url(client_keys: tuple[str, str]) -> None:
    kid = compute_kid(client_keys[1])

    assert "=" not in kid
    assert "+" not in kid
    assert "/" not in kid
    assert len(kid) == 43  # SHA-256 digest, base64url, unpadded


def test_kid_is_derivable_from_the_private_key_alone(signing_keys: tuple[str, str]) -> None:
    private_pem, public_pem = signing_keys

    assert compute_kid(derive_public_key_pem(private_pem)) == compute_kid(public_pem)
