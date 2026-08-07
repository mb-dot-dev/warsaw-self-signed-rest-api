"""Generate an RSA keypair for warsaw's private_key_jwt flow.

Run once per keypair:

    uv run scripts/generate_keypair.py --name client --public-out app/keys/client_public.pem
    uv run scripts/generate_keypair.py --name warsaw

Private keys are written to the gitignored out/ directory and must never be committed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

DEFAULT_KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537
PRIVATE_KEY_MODE = 0o600


def compute_kid(public_key_pem: str) -> str:
    """Return the RFC 7638 JWK thumbprint of an RSA public key."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    if not isinstance(public_key, rsa.RSAPublicKey):
        msg = "expected an RSA public key"
        raise TypeError(msg)
    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    canonical = json.dumps(
        {"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _check_can_write(*paths: Path, force: bool) -> None:
    """Raise FileExistsError if any of paths already exist, unless force is set.

    Checked up front, before any file in the set is written, so a partially-generated
    keypair can never be left on disk when the guard trips.
    """
    if force:
        return
    existing = [path for path in paths if path.exists()]
    if existing:
        names = ", ".join(str(path) for path in existing)
        msg = f"{names} already exists; pass --force to overwrite"
        raise FileExistsError(msg)


def _write(path: Path, content: str, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def generate_keypair(
    name: str,
    out_dir: Path,
    public_out: Path,
    key_size: int,
    *,
    force: bool,
) -> tuple[Path, Path]:
    """Generate an RSA keypair, returning the (private, public) paths written."""
    private_path = out_dir / f"{name}_private.pem"

    # Check both destinations before writing either one: if only the public half
    # already existed, we must not leave a freshly-generated private key on disk
    # that doesn't correspond to it.
    _check_can_write(private_path, public_out, force=force)

    private_key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )

    _write(private_path, private_pem, mode=PRIVATE_KEY_MODE)
    _write(public_out, public_pem)

    return private_path, public_out


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate an RSA keypair for warsaw.")
    parser.add_argument("--name", required=True, help="Key name, e.g. 'client' or 'warsaw'.")
    parser.add_argument("--out-dir", default="out", help="Directory for the private key (default: out).")
    parser.add_argument("--public-out", default=None, help="Path for the public key PEM.")
    parser.add_argument("--key-size", type=int, default=DEFAULT_KEY_SIZE, help="RSA key size in bits.")
    parser.add_argument("--force", action="store_true", help="Overwrite existing files.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    out_dir = Path(args.out_dir)
    public_out = Path(args.public_out) if args.public_out else out_dir / f"{args.name}_public.pem"

    try:
        private_path, public_path = generate_keypair(
            name=args.name,
            out_dir=out_dir,
            public_out=public_out,
            key_size=args.key_size,
            force=args.force,
        )
    except FileExistsError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    kid = compute_kid(public_path.read_text(encoding="utf-8"))
    print(f"private key: {private_path}  (mode 0600, never commit this)")
    print(f"public key:  {public_path}")
    print(f"kid:         {kid}")
    print()
    if args.name == "client":
        print("Next: commit the public key, deliver the private key to the client, then delete it locally.")
    else:
        print("Next: upload the private key to SSM as a SecureString, then delete it locally:")
        print(
            f"  aws ssm put-parameter --name /projects/warsaw/jwt-private-key --type SecureString "
            f'--overwrite --value "file://{private_path}"'
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
