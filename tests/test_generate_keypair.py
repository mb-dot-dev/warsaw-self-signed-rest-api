from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from scripts.generate_keypair import generate_keypair, main

if TYPE_CHECKING:
    from pathlib import Path


def test_generate_keypair_writes_both_halves(tmp_path: Path) -> None:
    private_path, public_path = generate_keypair(
        name="client",
        out_dir=tmp_path,
        public_out=tmp_path / "client_public.pem",
        key_size=2048,
        force=False,
    )

    assert private_path == tmp_path / "client_private.pem"
    assert public_path == tmp_path / "client_public.pem"
    assert private_path.exists()
    assert public_path.exists()


def test_generated_private_key_is_unencrypted_pkcs8(tmp_path: Path) -> None:
    private_path, _ = generate_keypair(
        name="client", out_dir=tmp_path, public_out=tmp_path / "pub.pem", key_size=2048, force=False
    )

    key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)

    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048
    assert private_path.read_text().startswith("-----BEGIN PRIVATE KEY-----")


def test_generated_public_key_matches_private_key(tmp_path: Path) -> None:
    private_path, public_path = generate_keypair(
        name="client", out_dir=tmp_path, public_out=tmp_path / "pub.pem", key_size=2048, force=False
    )

    private_key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    expected = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    assert public_path.read_bytes() == expected


def test_private_key_file_is_owner_readable_only(tmp_path: Path) -> None:
    private_path, _ = generate_keypair(
        name="client", out_dir=tmp_path, public_out=tmp_path / "pub.pem", key_size=2048, force=False
    )

    assert private_path.stat().st_mode & 0o777 == 0o600


def test_generate_keypair_refuses_to_overwrite_existing_file(tmp_path: Path) -> None:
    (tmp_path / "client_private.pem").write_text("existing")

    with pytest.raises(FileExistsError):
        generate_keypair(name="client", out_dir=tmp_path, public_out=tmp_path / "pub.pem", key_size=2048, force=False)

    assert (tmp_path / "client_private.pem").read_text() == "existing"


def test_generate_keypair_overwrites_when_forced(tmp_path: Path) -> None:
    (tmp_path / "client_private.pem").write_text("existing")

    generate_keypair(name="client", out_dir=tmp_path, public_out=tmp_path / "pub.pem", key_size=2048, force=True)

    assert (tmp_path / "client_private.pem").read_text() != "existing"


def test_generate_keypair_creates_missing_directories(tmp_path: Path) -> None:
    generate_keypair(
        name="warsaw",
        out_dir=tmp_path / "nested" / "out",
        public_out=tmp_path / "other" / "pub.pem",
        key_size=2048,
        force=False,
    )

    assert (tmp_path / "nested" / "out" / "warsaw_private.pem").exists()
    assert (tmp_path / "other" / "pub.pem").exists()


def test_main_returns_zero_and_writes_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["--name", "client", "--out-dir", str(tmp_path)])

    assert exit_code == 0
    assert (tmp_path / "client_private.pem").exists()
    assert "kid" in capsys.readouterr().out


def test_main_returns_one_when_file_exists(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "client_private.pem").write_text("existing")

    exit_code = main(["--name", "client", "--out-dir", str(tmp_path)])

    assert exit_code == 1
    assert "--force" in capsys.readouterr().err
