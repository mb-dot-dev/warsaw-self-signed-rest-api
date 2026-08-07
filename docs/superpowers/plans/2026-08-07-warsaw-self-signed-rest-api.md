# warsaw-self-signed-rest-api Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a REST API that authenticates one machine client via OAuth 2.0 `private_key_jwt` (RFC 7523), issues self-signed RS256 access tokens published through a JWKS endpoint, and enqueues authenticated request bodies to a shared SQS queue.

**Architecture:** One Python 3.14 Lambda behind an API Gateway REST API, built with `aws-lambda-powertools`' `APIGatewayRestResolver` and three routers (`/oauth/token`, `/.well-known/jwks.json`, `/`). Configuration is layered by `mb-config`: YAML defaults, then SSM parameters in prod, then environment variables. Infrastructure is three small CloudFormation/SAM stacks deployed in order by GitHub Actions. The repo is modelled closely on `helsinki-api-gateway-rest-api` — copy its patterns rather than inventing new ones.

**Tech Stack:** Python 3.14, uv, aws-lambda-powertools, pyjwt[crypto], cryptography, pydantic, mb-config[ssm], boto3, pytest, moto, ruff, ty, cfn-lint, AWS SAM.

**Spec:** `docs/superpowers/specs/2026-08-07-warsaw-self-signed-rest-api-design.md`

## Global Constraints

- Python `>=3.14`. Lambda runtime `python3.14`.
- Ruff line length 120. The full rule set and `per-file-ignores` are copied verbatim from helsinki's `pyproject.toml` — do not trim rules to make code pass; fix the code.
- Type-checked with `ty`. `make lint` = `ruff check` + `ruff format --check` + `ty check`, and must pass before every commit.
- `from __future__ import annotations` plus `TYPE_CHECKING`-guarded imports for typing-only symbols is the established pattern; follow it in every module.
- Project name is `warsaw`. AWS region `eu-central-1`. SSM prefix `/projects/warsaw/`.
- Powertools metrics namespace is the literal string `"Warsaw"` in every module that constructs `Metrics()` — never read it from an env var, because `Metrics()` resolves its namespace at construction time.
- JWT issuer `https://auth.molnarbence.dev/`, audience `api://default`.
- `pyjwt[crypto]` — **never** bare `pyjwt`. `cryptography` is otherwise absent from the production dependency closure and RS256 would fail only after deploy.
- Only ever pass `algorithms=["RS256"]` to `jwt.decode`. This is the control that blocks `alg: none` and HMAC-confusion attacks.
- Private keys are never committed. `out/` is gitignored.
- Tests live in `tests/`, which is a package (`tests/__init__.py`) so `from app import ...` resolves without installing the project.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `pyproject.toml` | dependencies, pytest/coverage/ruff config |
| `Makefile` | install, lint, test, coverage, cfn-lint, lambda packaging, keypair targets |
| `scripts/generate_keypair.py` | RSA keypair generator CLI |
| `app/main.py` | Powertools resolver, router registration, `lambda_handler`, `init_config` |
| `app/clients.py` | cached boto3 SQS client factory |
| `app/keys.py` | pure key helpers: load, derive, JWK-convert, thumbprint |
| `app/auth.py` | `AuthConfig`, client public key cache, client assertion validation |
| `app/jwt.py` | `JwtConfig`, signing key derivation cache, `jwt_bearer` middleware |
| `app/oauth.py` | `POST /oauth/token` router |
| `app/jwks.py` | `GET /.well-known/jwks.json` router |
| `app/producer.py` | `POST /` router, `ProducerConfig`, SQS enqueue |
| `app/configs/default.yaml` | config defaults |
| `app/configs/prod.yaml` | SSM parameter mapping |
| `app/keys/client_public.pem` | committed client public key |
| `aws/resource-group.yml` | tag-based resource group |
| `aws/iam-role.yml` | Lambda execution role |
| `template.yaml` | SAM: API Gateway + Lambda + log group |
| `.github/workflows/main.yaml` | CI/CD pipeline |

---

### Task 1: Project scaffolding and tooling gate

Creates the repo skeleton and proves the toolchain works. No application code yet.

**Files:**
- Create: `pyproject.toml`, `Makefile`, `.gitignore`, `samconfig.toml`, `sonar-project.properties`, `.github/dependabot.yml`, `app/__init__.py`, `tests/__init__.py`, `scripts/__init__.py`

**Interfaces:**
- Consumes: nothing.
- Produces: a working `make install-dev`, `make lint`, `make unit` toolchain that every later task depends on.

- [ ] **Step 1: Create `pyproject.toml`**

Copy helsinki's file verbatim except for `name` and the `pyjwt` line. The full content:

```toml
[project]
name = "warsaw-self-signed-rest-api"
version = "0.1.0"
description = "REST API with private_key_jwt client authentication and self-signed RS256 tokens"
readme = "README.md"
requires-python = ">=3.14"
dependencies = [
    "aws-lambda-powertools>=3.31.0",
    "mb-config[ssm]>=0.2.0",
    "pydantic>=2.13.4",
    "pyjwt[crypto]>=2.13",
]

[dependency-groups]
dev = [
    "aws-lambda-powertools[aws-sdk]>=3.31.0",
    "cfn-lint>=1.52.1",
    "moto[sqs]>=5.2.2",
    "pytest>=9.1.1",
    "pytest-cov>=7.1.0",
    "requests>=2.34.2",
    "ruff>=0.15.20",
    "ty>=0.0.56",
]

##### TESTING #####

[tool.pytest.ini_options]
addopts = "-v"
pythonpath = ["."]
testpaths = ["tests"]
python_files = ["test_*.py", "*_test.py"]
filterwarnings = [
    # Expected: only failure/denial paths emit custom metrics, so success-path tests
    # legitimately flush an empty metric set.
    "ignore:No application metrics to publish.*:UserWarning:aws_lambda_powertools.metrics.provider.base",
]

[tool.coverage.run]
branch = true
source = ["app"]
relative_files = true

[tool.coverage.report]
exclude_also = [
    "if TYPE_CHECKING:", # imports / code here is executed during mypy tests.
]
fail_under = 75
precision = 2

[tool.coverage.xml]
output = "build/coverage.xml"

#### LINTING ###

[tool.ruff]
# Set the maximum line length
line-length = 120
exclude = [".git", "__pycache__", ".venv", "build", "dist", "*.egg-info", "out"]

[tool.ruff.lint]
# Enable these rule categories
select = [
    "A",      # flake8-builtins
    "ARG",    # flake8-unusued-arguments
    "ANN",    # flake8-annotations
    "ASYNC",  # flake8-async
    "B",      # flake8-bugbear
    "BLE",    # flake8-blind-except
    "FBT",    # flake8-boolean-trap
    "C4",     # flake8-comprehensions
    "C90",    # McCabe Complexity
    "DTZ",    # flake8-datetimez
    "E",      # pycodestyle
    "EM",     # flake8-errmsg
    "F",      # Pyflakes
    "G",      # flake8-logging-format
    "FLY",    # Flynt
    "I",      # isort
    "ICN",    # flake8-import-conventions
    "N",      # PEP8 Naming
    "PERF",   # Perflint
    "PIE",    # flake8-pie
    "PL",     # Pylint
    "PT",     # flake8-pytest-style
    "PTH",    # flake8-use-pathlib
    "RET",    # flake8-return
    "RUF",    # Ruff-specific
    "RSE",    # flake8-raise
    "S",      # flake8-bandit
    "SIM",    # flake8-simplify
    "SLF001", # flake8-self private-member-access
    "SLOT",   # flake8-slots
    "TCH",    # flake8-typechecking
    "TID",    # flake8-tidy-imports
    "TRY",    # tryceratops
    "T20",    # flake8-print
    "T100",   # flake8-debugger
    "UP",     # pyupgrade
    "W",      # pycodestyle
]

[tool.ruff.lint.per-file-ignores]
"scripts/**/*.py" = [
    "T201",    # Print statements allowed in scripts
]
# Tests can have more flexible rules
"tests/**/*.py" = [
    "ARG001",  # Pytest fixtures appear as unused function arguments
    "PLR2004", # Magic value used in comparison
    "PLC0415", # Local imports inside test functions are a common pattern
    "S101",    # Use of assert
    "S105",
    "S106",
    "S107",
    "T201",    # Print statements in tests
]

[tool.ruff.lint.isort]
force-sort-within-sections = true
split-on-trailing-comma = true

[tool.ruff.lint.pydocstyle]
convention = "pep257"

[tool.ruff.lint.flake8-quotes]
# Use double quotes
docstring-quotes = "double"
inline-quotes = "double"
multiline-quotes = "double"
```

- [ ] **Step 2: Create `Makefile`**

Copy helsinki's `Makefile` verbatim. It already contains `install`, `install-dev`, `outdated`, `upgrade`, `unit`, `lint`, `format`, `test`, `coverage`, `cfn-lint`, `requirements`, `install-pip-ci`, and `build-lambda-package`. The keypair targets are added in Task 2.

Note `cfn-lint` already reads `aws/*.yml template.yaml`, which matches this repo's layout — no change needed.

- [ ] **Step 3: Create `.gitignore`**

```
# Python-generated files
__pycache__/
*.py[oc]
build/
dist/
wheels/
*.egg-info

# Virtual environments
.venv

# Coverage
.coverage

# Generated keypairs - NEVER commit private keys
out/

# Lambda build artifact
lambda.zip
requirements.txt
```

- [ ] **Step 4: Create `samconfig.toml`**

```toml
version = 0.1

[default.deploy.parameters]
region = "eu-central-1"
capabilities = "CAPABILITY_IAM"
confirm_changeset = false
resolve_s3 = false
s3_bucket = "molnarbence-prod-lambda-code"
fail_on_empty_changeset = false
```

- [ ] **Step 5: Create `sonar-project.properties`**

```properties
sonar.projectKey=mb-dot-dev_warsaw-self-signed-rest-api
sonar.organization=mb-dot-dev

sonar.sources=app
sonar.exclusions=**/__pycache__/**

# Encoding of the source code. Default is default system encoding
#sonar.sourceEncoding=UTF-8

# Language and version
sonar.language=python
sonar.python.version=3.14

# Tests & coverage
sonar.tests=tests
sonar.python.coverage.reportPaths=build/coverage.xml
sonar.coverage.exclusions=tests/**
```

- [ ] **Step 6: Create `.github/dependabot.yml`**

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    groups:
      github-actions:
        patterns: ["*"]

  - package-ecosystem: "uv"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    groups:
      python-dependencies:
        patterns: ["*"]
```

- [ ] **Step 7: Create empty package markers**

Create three empty files: `app/__init__.py`, `tests/__init__.py`, `scripts/__init__.py`.

- [ ] **Step 8: Lock and install**

```bash
uv lock
make install-dev
```

Expected: `uv.lock` is created and dependencies install.

- [ ] **Step 9: Verify `cryptography` is in the production closure**

```bash
uv export --frozen --no-dev --no-editable | grep -c '^cryptography'
```

Expected: `1`. If it prints `0`, `pyjwt[crypto]` was written as bare `pyjwt` — fix `pyproject.toml`, re-run `uv lock`, and repeat. This check is the whole reason the extra exists.

- [ ] **Step 10: Verify lint passes**

```bash
make lint
```

Expected: all three checks pass with no files to complain about.

- [ ] **Step 11: Commit**

```bash
git add pyproject.toml uv.lock Makefile .gitignore samconfig.toml sonar-project.properties .github/dependabot.yml app/__init__.py tests/__init__.py scripts/__init__.py
git commit -m "chore: scaffold project tooling and dependencies"
```

---

### Task 2: Keypair generator script

The generator has to exist before anything else, because the committed client public key and the SSM signing key both come from it.

**Files:**
- Create: `scripts/generate_keypair.py`, `tests/test_generate_keypair.py`
- Modify: `Makefile` (append two targets)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `scripts/generate_keypair.py` with `generate_keypair(name: str, out_dir: Path, public_out: Path, key_size: int, *, force: bool) -> tuple[Path, Path]` returning `(private_path, public_path)`, and `main(argv: list[str] | None = None) -> int`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_generate_keypair.py`:

```python
from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
import pytest

from scripts.generate_keypair import generate_keypair, main


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
        generate_keypair(
            name="client", out_dir=tmp_path, public_out=tmp_path / "pub.pem", key_size=2048, force=False
        )

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run --frozen pytest tests/test_generate_keypair.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'scripts.generate_keypair'`

- [ ] **Step 3: Implement the script**

Create `scripts/generate_keypair.py`. Note `compute_kid` is duplicated here rather than imported from `app.keys` (Task 4) — the script must run standalone before the app exists, and this is the only duplicated logic in the repo.

```python
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
    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    canonical = json.dumps(
        {"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _write(path: Path, content: str, *, force: bool, mode: int | None = None) -> None:
    if path.exists() and not force:
        msg = f"{path} already exists; pass --force to overwrite"
        raise FileExistsError(msg)
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

    _write(private_path, private_pem, force=force, mode=PRIVATE_KEY_MODE)
    _write(public_out, public_pem, force=force)

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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --frozen pytest tests/test_generate_keypair.py -v`
Expected: all 9 tests PASS

- [ ] **Step 5: Add the Makefile targets**

Append to `Makefile`:

```make
.PHONY: keypair-client
keypair-client:  ## Generate the client keypair; public into the package, private into out/.
	uv run scripts/generate_keypair.py --name client --public-out app/keys/client_public.pem

.PHONY: keypair-signing
keypair-signing:  ## Generate warsaw's token-signing keypair; upload the private half to SSM.
	uv run scripts/generate_keypair.py --name warsaw
```

- [ ] **Step 6: Verify lint and full suite**

```bash
make lint
make unit
```
Expected: both pass.

- [ ] **Step 7: Commit**

```bash
git add scripts/generate_keypair.py tests/test_generate_keypair.py Makefile
git commit -m "feat: add RSA keypair generator script"
```

---

### Task 3: Configuration, app bootstrap, and test fixtures

Builds the config layer, the bare resolver, the SQS client factory, and the shared `conftest.py` every later task's tests depend on.

**Files:**
- Create: `app/configs/default.yaml`, `app/configs/prod.yaml`, `app/main.py`, `app/clients.py`, `tests/conftest.py`, `tests/test_main.py`, `tests/test_clients.py`

**Interfaces:**
- Consumes: Task 1's toolchain.
- Produces:
  - `app.main.init_config() -> None` (cached), `app.main.lambda_handler(event, context) -> dict[str, object]`, `app.main.app` (the resolver).
  - `app.clients.get_sqs_client() -> BaseClient` (cached).
  - conftest constants `ISSUER`, `AUDIENCE`, `ALLOWED_CLIENT_ID`, `QUEUE_NAME`, `QUEUE_URL`.
  - conftest fixtures `client_keys`, `signing_keys` (session-scoped `tuple[str, str]` of `(private_pem, public_pem)`), `client_public_key_path`, `lambda_context`, `make_event`.

- [ ] **Step 1: Create `app/configs/default.yaml`**

```yaml
producer:
  queue_url: ""

jwt:
  private_key: ""
  issuer: "https://auth.molnarbence.dev/"
  audience: "api://default"
  token_ttl_seconds: 3600
  leeway_seconds: 30

auth:
  allowed_client_id: ""
  client_public_key_path: "app/keys/client_public.pem"
  max_assertion_lifetime_seconds: 300
  leeway_seconds: 30
```

- [ ] **Step 2: Create `app/configs/prod.yaml`**

```yaml
ssm_params:
  "string:/projects/warsaw/allowed-client-id": "auth:allowed_client_id"
  "secure:/projects/warsaw/jwt-private-key": "jwt:private_key"
```

- [ ] **Step 3: Create `app/clients.py`**

```python
from __future__ import annotations

import functools
from typing import TYPE_CHECKING

import boto3

if TYPE_CHECKING:
    from botocore.client import BaseClient


@functools.cache
def get_sqs_client() -> BaseClient:
    return boto3.client("sqs")
```

- [ ] **Step 4: Create `app/main.py` with no routers yet**

```python
from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING

from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.event_handler import APIGatewayRestResolver
from mb_config.workloads import initialize_config

if TYPE_CHECKING:
    from aws_lambda_powertools.utilities.typing import LambdaContext

logger = Logger()
metrics = Metrics(namespace="Warsaw")
app = APIGatewayRestResolver()


@cache
def init_config() -> None:
    initialize_config("app/configs")


@metrics.log_metrics
@logger.inject_lambda_context
def lambda_handler(event: dict[str, object], context: LambdaContext) -> dict[str, object]:
    init_config()
    return app.resolve(event, context)
```

- [ ] **Step 5: Create `tests/conftest.py`**

Note `_lambda_env` sets `JWT__PRIVATE_KEY` to a PEM containing newlines — `mb-config`'s env loader lowercases the key and splits on `__`, so this lands at `jwt: {private_key: ...}` and overrides both YAML and SSM because env vars are loaded last.

```python
from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from mb_config.config_manager import reset_config
import pytest

from app.main import init_config

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

ISSUER = "https://auth.molnarbence.dev/"
AUDIENCE = "api://default"
ALLOWED_CLIENT_ID = "test-client"
QUEUE_NAME = "test-queue"
QUEUE_URL = f"https://sqs.eu-west-1.amazonaws.com/123456789012/{QUEUE_NAME}"


def _generate_keypair() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


# RSA generation is slow; generate each keypair once for the whole session.
@pytest.fixture(scope="session")
def client_keys() -> tuple[str, str]:
    return _generate_keypair()


@pytest.fixture(scope="session")
def signing_keys() -> tuple[str, str]:
    return _generate_keypair()


@pytest.fixture(scope="session")
def client_public_key_path(client_keys: tuple[str, str], tmp_path_factory: pytest.TempPathFactory) -> str:
    path: Path = tmp_path_factory.mktemp("keys") / "client_public.pem"
    path.write_text(client_keys[1], encoding="utf-8")
    return str(path)


@pytest.fixture(autouse=True)
def _lambda_env(
    monkeypatch: pytest.MonkeyPatch,
    signing_keys: tuple[str, str],
    client_public_key_path: str,
) -> None:
    monkeypatch.setenv("JWT__PRIVATE_KEY", signing_keys[0])
    monkeypatch.setenv("AUTH__ALLOWED_CLIENT_ID", ALLOWED_CLIENT_ID)
    monkeypatch.setenv("AUTH__CLIENT_PUBLIC_KEY_PATH", client_public_key_path)
    monkeypatch.setenv("PRODUCER__QUEUE_URL", QUEUE_URL)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")


@pytest.fixture(autouse=True)
def _reset_config_cache() -> None:
    reset_config()
    init_config.cache_clear()


class LambdaContext:
    function_name = "test-function"
    memory_limit_in_mb = 128
    invoked_function_arn = "arn:aws:lambda:eu-west-1:123456789012:function:test-function"
    aws_request_id = "test-request-id"


@pytest.fixture
def lambda_context() -> LambdaContext:
    return LambdaContext()


@pytest.fixture
def make_event() -> Callable[..., dict[str, Any]]:
    def _make_event(
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> dict[str, Any]:
        return {
            "httpMethod": method,
            "path": path,
            "headers": headers or {},
            "multiValueHeaders": {},
            "queryStringParameters": None,
            "multiValueQueryStringParameters": None,
            "pathParameters": None,
            "body": body,
            "isBase64Encoded": False,
            "requestContext": {"httpMethod": method, "resourcePath": path, "path": path},
        }

    return _make_event


@pytest.fixture
def make_assertion(client_keys: tuple[str, str]) -> Callable[..., str]:
    def _make_assertion(
        *,
        signing_key: str | None = None,
        issuer: str = ALLOWED_CLIENT_ID,
        subject: str = ALLOWED_CLIENT_ID,
        audience: str = ISSUER,
        lifetime: int = 60,
        algorithm: str = "RS256",
        include_exp: bool = True,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "jti": str(uuid.uuid4()),
        }
        if include_exp:
            claims["exp"] = now + lifetime
        return jwt.encode(claims, signing_key or client_keys[0], algorithm=algorithm)

    return _make_assertion


@pytest.fixture
def make_token(signing_keys: tuple[str, str]) -> Callable[..., str]:
    def _make_token(
        *,
        signing_key: str | None = None,
        audience: str | None = AUDIENCE,
        expires_in: int = 3600,
        subject: str = ALLOWED_CLIENT_ID,
        algorithm: str = "RS256",
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "sub": subject,
            "azp": subject,
            "iat": now,
            "exp": now + expires_in,
            "scp": ["openid"],
        }
        if audience is not None:
            claims["aud"] = audience
        return jwt.encode(claims, signing_key or signing_keys[0], algorithm=algorithm)

    return _make_token
```

- [ ] **Step 6: Write `tests/test_main.py` and `tests/test_clients.py`**

```python
# tests/test_main.py
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mb_config.config_manager import get_config

from app.main import init_config, lambda_handler
from tests.conftest import ALLOWED_CLIENT_ID, AUDIENCE, ISSUER, QUEUE_URL

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.conftest import LambdaContext


def test_init_config_loads_defaults_and_env_overrides() -> None:
    init_config()
    config = get_config()

    assert config["jwt"]["issuer"] == ISSUER
    assert config["jwt"]["audience"] == AUDIENCE
    assert config["auth"]["allowed_client_id"] == ALLOWED_CLIENT_ID
    assert config["producer"]["queue_url"] == QUEUE_URL


def test_init_config_is_cached() -> None:
    init_config()

    assert init_config.cache_info().currsize == 1


def test_lambda_handler_returns_404_for_unknown_route(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    response = lambda_handler(make_event("GET", "/nope"), lambda_context)

    assert response["statusCode"] == 404
```

```python
# tests/test_clients.py
from __future__ import annotations

from app.clients import get_sqs_client


def test_get_sqs_client_is_cached() -> None:
    get_sqs_client.cache_clear()

    assert get_sqs_client() is get_sqs_client()
```

- [ ] **Step 7: Run tests**

Run: `uv run --frozen pytest tests/test_main.py tests/test_clients.py -v`
Expected: all PASS

- [ ] **Step 8: Verify lint**

Run: `make lint`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add app/configs app/main.py app/clients.py tests/conftest.py tests/test_main.py tests/test_clients.py
git commit -m "feat: add config layer, app bootstrap, and test fixtures"
```

---

### Task 4: Pure key helpers

**Files:**
- Create: `app/keys.py`, `tests/test_keys.py`

**Interfaces:**
- Consumes: nothing (this module is deliberately dependency-free of app config).
- Produces:
  - `load_public_key_pem(path: str) -> str`
  - `derive_public_key_pem(private_key_pem: str) -> str`
  - `public_key_to_jwk(public_key_pem: str) -> dict[str, str]` returning exactly `{"kty", "n", "e"}`
  - `compute_kid(public_key_pem: str) -> str`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_keys.py`:

```python
from __future__ import annotations

from pathlib import Path

import pytest

from app.keys import compute_kid, derive_public_key_pem, load_public_key_pem, public_key_to_jwk


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run --frozen pytest tests/test_keys.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.keys'`

- [ ] **Step 3: Implement `app/keys.py`**

`load_pem_private_key` returns a union type; `ty` needs the `cast` to know `.public_key()` exists.

```python
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
from typing import cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm


def load_public_key_pem(path: str) -> str:
    """Read a PEM-encoded public key from disk."""
    return Path(path).read_text(encoding="utf-8")


def derive_public_key_pem(private_key_pem: str) -> str:
    """Return the PEM-encoded public half of a PEM-encoded RSA private key."""
    private_key = cast(
        "rsa.RSAPrivateKey",
        serialization.load_pem_private_key(private_key_pem.encode(), password=None),
    )
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --frozen pytest tests/test_keys.py -v`
Expected: all 8 tests PASS

- [ ] **Step 5: Verify lint**

Run: `make lint`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add app/keys.py tests/test_keys.py
git commit -m "feat: add pure RSA key helpers"
```

---

### Task 5: Client assertion validation

**Files:**
- Create: `app/auth.py`, `tests/test_auth.py`
- Modify: `tests/conftest.py` (add `get_auth_config` and `get_client_public_key` to the cache-clearing fixture)

**Interfaces:**
- Consumes: `app.keys.load_public_key_pem`; conftest fixtures `make_assertion`, `client_keys`, `signing_keys`.
- Produces:
  - `AuthConfig` with fields `allowed_client_id: str`, `client_public_key_path: str`, `max_assertion_lifetime_seconds: int`, `leeway_seconds: int`.
  - `get_auth_config() -> AuthConfig` (cached), `get_client_public_key() -> str` (cached).
  - `ClientAuthError(Exception)` with a `.reason: str` attribute.
  - `authenticate_client(assertion: str, expected_audience: str) -> str` returning the client id.
  - Reason constants `REASON_MALFORMED`, `REASON_BAD_SIGNATURE`, `REASON_EXPIRED`, `REASON_LIFETIME_TOO_LONG`, `REASON_UNKNOWN_CLIENT`.

- [ ] **Step 1: Add the new cache-clearing calls to `tests/conftest.py`**

Replace the `_reset_config_cache` fixture body with:

```python
@pytest.fixture(autouse=True)
def _reset_config_cache() -> None:
    from app.auth import get_auth_config, get_client_public_key

    reset_config()
    init_config.cache_clear()
    get_auth_config.cache_clear()
    get_client_public_key.cache_clear()
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_auth.py`:

```python
from __future__ import annotations

from typing import TYPE_CHECKING

import jwt
import pytest

from app.auth import (
    REASON_BAD_SIGNATURE,
    REASON_EXPIRED,
    REASON_LIFETIME_TOO_LONG,
    REASON_MALFORMED,
    REASON_UNKNOWN_CLIENT,
    ClientAuthError,
    authenticate_client,
    get_auth_config,
    get_client_public_key,
)
from app.main import init_config
from tests.conftest import ALLOWED_CLIENT_ID, ISSUER

if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.fixture(autouse=True)
def _init_config() -> None:
    init_config()


def test_get_auth_config_reads_settings() -> None:
    config = get_auth_config()

    assert config.allowed_client_id == ALLOWED_CLIENT_ID
    assert config.max_assertion_lifetime_seconds == 300
    assert config.leeway_seconds == 30


def test_get_auth_config_is_cached() -> None:
    assert get_auth_config() is get_auth_config()


def test_get_client_public_key_loads_the_configured_file(client_keys: tuple[str, str]) -> None:
    assert get_client_public_key() == client_keys[1]


def test_authenticate_client_accepts_a_valid_assertion(make_assertion: Callable[..., str]) -> None:
    assert authenticate_client(make_assertion(), ISSUER) == ALLOWED_CLIENT_ID


def test_authenticate_client_rejects_garbage(make_assertion: Callable[..., str]) -> None:
    with pytest.raises(ClientAuthError) as error:
        authenticate_client("not-a-jwt", ISSUER)

    assert error.value.reason == REASON_MALFORMED


def test_authenticate_client_rejects_assertion_signed_by_another_key(
    make_assertion: Callable[..., str],
    signing_keys: tuple[str, str],
) -> None:
    assertion = make_assertion(signing_key=signing_keys[0])

    with pytest.raises(ClientAuthError) as error:
        authenticate_client(assertion, ISSUER)

    assert error.value.reason == REASON_BAD_SIGNATURE


def test_authenticate_client_rejects_hs256_algorithm_confusion(client_keys: tuple[str, str]) -> None:
    # An attacker who knows the public key tries to use it as an HMAC secret.
    forged = jwt.encode({"iss": ALLOWED_CLIENT_ID, "sub": ALLOWED_CLIENT_ID, "aud": ISSUER}, client_keys[1], algorithm="HS256")

    with pytest.raises(ClientAuthError) as error:
        authenticate_client(forged, ISSUER)

    assert error.value.reason == REASON_MALFORMED


def test_authenticate_client_rejects_expired_assertion(make_assertion: Callable[..., str]) -> None:
    with pytest.raises(ClientAuthError) as error:
        authenticate_client(make_assertion(lifetime=-120), ISSUER)

    assert error.value.reason == REASON_EXPIRED


def test_authenticate_client_rejects_assertion_without_exp(make_assertion: Callable[..., str]) -> None:
    with pytest.raises(ClientAuthError) as error:
        authenticate_client(make_assertion(include_exp=False), ISSUER)

    assert error.value.reason == REASON_MALFORMED


def test_authenticate_client_rejects_overlong_lifetime(make_assertion: Callable[..., str]) -> None:
    with pytest.raises(ClientAuthError) as error:
        authenticate_client(make_assertion(lifetime=3600), ISSUER)

    assert error.value.reason == REASON_LIFETIME_TOO_LONG


def test_authenticate_client_accepts_lifetime_at_the_limit(make_assertion: Callable[..., str]) -> None:
    assert authenticate_client(make_assertion(lifetime=300), ISSUER) == ALLOWED_CLIENT_ID


def test_authenticate_client_rejects_wrong_audience(make_assertion: Callable[..., str]) -> None:
    with pytest.raises(ClientAuthError) as error:
        authenticate_client(make_assertion(audience="https://elsewhere.example/"), ISSUER)

    assert error.value.reason == REASON_UNKNOWN_CLIENT


def test_authenticate_client_rejects_wrong_issuer(make_assertion: Callable[..., str]) -> None:
    with pytest.raises(ClientAuthError) as error:
        authenticate_client(make_assertion(issuer="someone-else"), ISSUER)

    assert error.value.reason == REASON_UNKNOWN_CLIENT


def test_authenticate_client_rejects_wrong_subject(make_assertion: Callable[..., str]) -> None:
    with pytest.raises(ClientAuthError) as error:
        authenticate_client(make_assertion(subject="someone-else"), ISSUER)

    assert error.value.reason == REASON_UNKNOWN_CLIENT
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run --frozen pytest tests/test_auth.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.auth'`

- [ ] **Step 4: Implement `app/auth.py`**

The `except` ordering matters: `InvalidSignatureError`, `ExpiredSignatureError`, `InvalidAudienceError`, `InvalidIssuerError` and `MissingRequiredClaimError` are all subclasses of `InvalidTokenError`, so the broad catch must come last.

```python
from __future__ import annotations

from functools import cache
import time
from typing import ClassVar

import jwt
from mb_config import get_config
from pydantic import BaseModel

from app.keys import load_public_key_pem

REASON_MALFORMED = "Malformed"
REASON_BAD_SIGNATURE = "BadSignature"
REASON_EXPIRED = "Expired"
REASON_LIFETIME_TOO_LONG = "LifetimeTooLong"
REASON_UNKNOWN_CLIENT = "UnknownClient"

_REQUIRED_CLAIMS = ["exp", "iss", "sub", "aud"]


class ClientAuthError(Exception):
    """Raised when a client assertion fails validation. `reason` is a metric dimension."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class AuthConfig(BaseModel):
    section_name: ClassVar[str] = "auth"

    allowed_client_id: str
    client_public_key_path: str
    max_assertion_lifetime_seconds: int
    leeway_seconds: int


@cache
def get_auth_config() -> AuthConfig:
    app_config = get_config()
    return AuthConfig.model_validate(app_config[AuthConfig.section_name])


@cache
def get_client_public_key() -> str:
    return load_public_key_pem(get_auth_config().client_public_key_path)


def authenticate_client(assertion: str, expected_audience: str) -> str:
    """Validate an RFC 7523 client assertion, returning the authenticated client id."""
    auth_config = get_auth_config()

    try:
        claims = jwt.decode(
            assertion,
            get_client_public_key(),
            algorithms=["RS256"],
            audience=expected_audience,
            issuer=auth_config.allowed_client_id,
            leeway=auth_config.leeway_seconds,
            options={"require": _REQUIRED_CLAIMS},
        )
    except jwt.ExpiredSignatureError as error:
        raise ClientAuthError(REASON_EXPIRED) from error
    except jwt.InvalidSignatureError as error:
        raise ClientAuthError(REASON_BAD_SIGNATURE) from error
    except (jwt.InvalidAudienceError, jwt.InvalidIssuerError) as error:
        raise ClientAuthError(REASON_UNKNOWN_CLIENT) from error
    except jwt.InvalidTokenError as error:
        raise ClientAuthError(REASON_MALFORMED) from error

    if claims["sub"] != auth_config.allowed_client_id:
        raise ClientAuthError(REASON_UNKNOWN_CLIENT)

    if claims["exp"] - int(time.time()) > auth_config.max_assertion_lifetime_seconds:
        raise ClientAuthError(REASON_LIFETIME_TOO_LONG)

    return auth_config.allowed_client_id
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run --frozen pytest tests/test_auth.py -v`
Expected: all 14 tests PASS

If `test_authenticate_client_accepts_lifetime_at_the_limit` is flaky by one second, it is because `iat` and the comparison happen in different seconds. That is the intended strict behaviour; leave the 300 boundary alone and re-run.

- [ ] **Step 6: Verify lint and full suite**

```bash
make lint
make unit
```
Expected: both pass.

- [ ] **Step 7: Commit**

```bash
git add app/auth.py tests/test_auth.py tests/conftest.py
git commit -m "feat: add private_key_jwt client assertion validation"
```

---

### Task 6: Signing key access and bearer middleware

**Files:**
- Create: `app/jwt.py`, `tests/test_jwt.py`
- Modify: `tests/conftest.py` (extend the cache-clearing fixture)

**Interfaces:**
- Consumes: `app.keys.derive_public_key_pem`, `app.keys.compute_kid`.
- Produces:
  - `JwtConfig` with fields `private_key: str`, `issuer: str`, `audience: str`, `token_ttl_seconds: int`, `leeway_seconds: int`.
  - `get_jwt_config() -> JwtConfig` (cached), `get_signing_public_key() -> str` (cached), `get_signing_kid() -> str` (cached).
  - `jwt_bearer(app, next_middleware) -> Response` — a Powertools middleware.

- [ ] **Step 1: Extend the cache-clearing fixture in `tests/conftest.py`**

```python
@pytest.fixture(autouse=True)
def _reset_config_cache() -> None:
    from app.auth import get_auth_config, get_client_public_key
    from app.jwt import get_jwt_config, get_signing_kid, get_signing_public_key

    reset_config()
    init_config.cache_clear()
    get_auth_config.cache_clear()
    get_client_public_key.cache_clear()
    get_jwt_config.cache_clear()
    get_signing_public_key.cache_clear()
    get_signing_kid.cache_clear()
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_jwt.py`:

```python
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

from aws_lambda_powertools.event_handler import APIGatewayRestResolver
import pytest

from app.jwt import get_jwt_config, get_signing_kid, get_signing_public_key, jwt_bearer
from app.keys import compute_kid
from app.main import init_config
from tests.conftest import AUDIENCE, ISSUER

if TYPE_CHECKING:
    from collections.abc import Callable

    from aws_lambda_powertools.utilities.typing import LambdaContext as PowertoolsLambdaContext

    from tests.conftest import LambdaContext


@pytest.fixture(autouse=True)
def _init_config() -> None:
    init_config()


def _build_resolver() -> APIGatewayRestResolver:
    resolver = APIGatewayRestResolver()

    @resolver.get("/protected", middlewares=[jwt_bearer])
    def protected() -> dict[str, str]:
        return {"message": "ok"}

    return resolver


def _resolve(event: dict[str, Any], context: LambdaContext) -> dict[str, Any]:
    return _build_resolver().resolve(event, cast("PowertoolsLambdaContext", context))


def test_get_jwt_config_reads_settings(signing_keys: tuple[str, str]) -> None:
    config = get_jwt_config()

    assert config.issuer == ISSUER
    assert config.audience == AUDIENCE
    assert config.token_ttl_seconds == 3600
    assert config.private_key == signing_keys[0]


def test_get_signing_public_key_matches_the_generated_public_key(signing_keys: tuple[str, str]) -> None:
    assert get_signing_public_key() == signing_keys[1]


def test_get_signing_kid_matches_the_public_key_thumbprint(signing_keys: tuple[str, str]) -> None:
    assert get_signing_kid() == compute_kid(signing_keys[1])


def test_get_signing_kid_is_cached() -> None:
    assert get_signing_kid() == get_signing_kid()


def test_jwt_bearer_accepts_a_valid_token(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
) -> None:
    event = make_event("GET", "/protected", headers={"Authorization": f"Bearer {make_token()}"})

    response = _resolve(event, lambda_context)

    assert response["statusCode"] == 200
    assert json.loads(response["body"]) == {"message": "ok"}


def test_jwt_bearer_rejects_missing_authorization_header(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    response = _resolve(make_event("GET", "/protected"), lambda_context)

    assert response["statusCode"] == 401
    assert json.loads(response["body"])["message"] == "Unauthorized"


def test_jwt_bearer_rejects_non_bearer_scheme(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    event = make_event("GET", "/protected", headers={"Authorization": "Basic dXNlcjpwYXNz"})

    response = _resolve(event, lambda_context)

    assert response["statusCode"] == 401


def test_jwt_bearer_rejects_expired_token(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
) -> None:
    event = make_event("GET", "/protected", headers={"Authorization": f"Bearer {make_token(expires_in=-120)}"})

    response = _resolve(event, lambda_context)

    assert response["statusCode"] == 401
    assert json.loads(response["body"])["message"] == "Token has expired"


def test_jwt_bearer_rejects_token_signed_with_the_client_key(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    client_keys: tuple[str, str],
    lambda_context: LambdaContext,
) -> None:
    # The client's own key must not be able to mint access tokens.
    token = make_token(signing_key=client_keys[0])
    event = make_event("GET", "/protected", headers={"Authorization": f"Bearer {token}"})

    response = _resolve(event, lambda_context)

    assert response["statusCode"] == 401


def test_jwt_bearer_rejects_wrong_audience(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
) -> None:
    event = make_event("GET", "/protected", headers={"Authorization": f"Bearer {make_token(audience='other')}"})

    response = _resolve(event, lambda_context)

    assert response["statusCode"] == 401


def test_jwt_bearer_rejects_malformed_token(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    event = make_event("GET", "/protected", headers={"Authorization": "Bearer not-a-jwt"})

    response = _resolve(event, lambda_context)

    assert response["statusCode"] == 401


def test_rejected_token_emits_a_metric(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import jwt as app_jwt

    emitted: list[str] = []
    monkeypatch.setattr(
        app_jwt.metrics, "add_metric", lambda *, name, unit, value: emitted.append(name)
    )

    _resolve(make_event("GET", "/protected"), lambda_context)

    assert "TokenRejected" in emitted
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run --frozen pytest tests/test_jwt.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.jwt'`

- [ ] **Step 4: Implement `app/jwt.py`**

```python
from __future__ import annotations

from functools import cache
import json
from typing import TYPE_CHECKING, ClassVar

from aws_lambda_powertools import Metrics
from aws_lambda_powertools.event_handler import Response
from aws_lambda_powertools.metrics import MetricUnit
import jwt
from mb_config import get_config
from pydantic import BaseModel

from app.keys import compute_kid, derive_public_key_pem

if TYPE_CHECKING:
    from aws_lambda_powertools.event_handler import ApiGatewayResolver
    from aws_lambda_powertools.event_handler.middlewares import NextMiddleware

metrics = Metrics(namespace="Warsaw")

_BEARER_PREFIX = "Bearer "


class JwtConfig(BaseModel):
    section_name: ClassVar[str] = "jwt"

    private_key: str
    issuer: str
    audience: str
    token_ttl_seconds: int
    leeway_seconds: int


@cache
def get_jwt_config() -> JwtConfig:
    app_config = get_config()
    return JwtConfig.model_validate(app_config[JwtConfig.section_name])


@cache
def get_signing_public_key() -> str:
    """Derive the public key from the configured private key.

    Deriving rather than shipping a committed PEM makes it impossible for the published
    JWKS to drift from the key that actually signs tokens when the SSM parameter rotates.
    """
    return derive_public_key_pem(get_jwt_config().private_key)


@cache
def get_signing_kid() -> str:
    return compute_kid(get_signing_public_key())


def _unauthorized(message: str) -> Response:
    metrics.add_metric(name="TokenRejected", unit=MetricUnit.Count, value=1)
    return Response(
        status_code=401,
        content_type="application/json",
        body=json.dumps({"message": message}),
    )


def jwt_bearer(app: ApiGatewayResolver, next_middleware: NextMiddleware) -> Response:
    jwt_config = get_jwt_config()

    auth_header = app.current_event.headers.get("Authorization", "")
    if not auth_header.startswith(_BEARER_PREFIX):
        return _unauthorized("Unauthorized")

    token = auth_header[len(_BEARER_PREFIX) :]

    try:
        jwt.decode(
            token,
            get_signing_public_key(),
            algorithms=["RS256"],
            audience=jwt_config.audience,
            issuer=jwt_config.issuer,
            leeway=jwt_config.leeway_seconds,
        )
    except jwt.ExpiredSignatureError:
        return _unauthorized("Token has expired")
    except jwt.InvalidTokenError:
        return _unauthorized("Unauthorized")

    return next_middleware(app)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run --frozen pytest tests/test_jwt.py -v`
Expected: all 12 tests PASS

- [ ] **Step 6: Verify lint and full suite**

```bash
make lint
make unit
```
Expected: both pass.

- [ ] **Step 7: Commit**

```bash
git add app/jwt.py tests/test_jwt.py tests/conftest.py
git commit -m "feat: add signing key derivation and RS256 bearer middleware"
```

---

### Task 7: Token endpoint

**Files:**
- Create: `app/oauth.py`, `tests/test_oauth.py`
- Modify: `app/main.py` (register the router)

**Interfaces:**
- Consumes: `app.auth.authenticate_client`, `app.auth.ClientAuthError`, the reason constants, `app.jwt.get_jwt_config`, `app.jwt.get_signing_kid`.
- Produces: `app.oauth.router`, `_parse_token_request(body: str, content_type: str) -> dict[str, str]`, and constants `CLIENT_ASSERTION_TYPE`, `GRANT_TYPE`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_oauth.py`:

```python
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
import urllib.parse

import jwt
import pytest

from app.main import lambda_handler
from app.oauth import CLIENT_ASSERTION_TYPE, GRANT_TYPE, _parse_token_request
from tests.conftest import ALLOWED_CLIENT_ID, AUDIENCE, ISSUER

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.conftest import LambdaContext

FORM = "application/x-www-form-urlencoded"


def _form_body(**params: str) -> str:
    return urllib.parse.urlencode(params)


def _token_request(assertion: str) -> str:
    return _form_body(
        grant_type=GRANT_TYPE,
        client_assertion_type=CLIENT_ASSERTION_TYPE,
        client_assertion=assertion,
    )


def test_parse_token_request_reads_form_body() -> None:
    parsed = _parse_token_request(_form_body(grant_type="client_credentials", client_assertion="abc"), FORM)

    assert parsed["grant_type"] == "client_credentials"
    assert parsed["client_assertion"] == "abc"


def test_parse_token_request_reads_json_body() -> None:
    body = json.dumps({"grant_type": "client_credentials", "client_assertion": "abc"})

    parsed = _parse_token_request(body, "application/json")

    assert parsed["client_assertion"] == "abc"


def test_parse_token_request_returns_empty_for_malformed_json() -> None:
    assert _parse_token_request("{not json", "application/json") == {}


def test_parse_token_request_returns_empty_for_non_object_json() -> None:
    assert _parse_token_request("[1, 2, 3]", "application/json") == {}


def test_parse_token_request_returns_empty_for_empty_body() -> None:
    assert _parse_token_request("", FORM) == {}


def test_issue_token_succeeds_with_a_valid_assertion(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    signing_keys: tuple[str, str],
    lambda_context: LambdaContext,
) -> None:
    event = make_event(
        "POST", "/oauth/token", headers={"Content-Type": FORM}, body=_token_request(make_assertion())
    )

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 200
    payload = json.loads(response["body"])
    assert payload["token_type"] == "Bearer"
    assert payload["expires_in"] == 3600
    assert payload["scope"] == "openid"

    claims = jwt.decode(payload["access_token"], signing_keys[1], algorithms=["RS256"], audience=AUDIENCE)
    assert claims["sub"] == ALLOWED_CLIENT_ID
    assert claims["azp"] == ALLOWED_CLIENT_ID
    assert claims["iss"] == ISSUER
    assert claims["scp"] == ["openid"]
    assert "jti" in claims


def test_issued_token_header_carries_the_signing_kid(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    lambda_context: LambdaContext,
) -> None:
    from app.jwt import get_signing_kid

    event = make_event(
        "POST", "/oauth/token", headers={"Content-Type": FORM}, body=_token_request(make_assertion())
    )

    response = lambda_handler(event, lambda_context)
    token = json.loads(response["body"])["access_token"]

    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"
    assert header["kid"] == get_signing_kid()


def test_issue_token_accepts_a_json_body(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    lambda_context: LambdaContext,
) -> None:
    body = json.dumps(
        {
            "grant_type": GRANT_TYPE,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": make_assertion(),
        }
    )
    event = make_event("POST", "/oauth/token", headers={"Content-Type": "application/json"}, body=body)

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 200


def test_issue_token_rejects_wrong_grant_type(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    lambda_context: LambdaContext,
) -> None:
    body = _form_body(
        grant_type="authorization_code",
        client_assertion_type=CLIENT_ASSERTION_TYPE,
        client_assertion=make_assertion(),
    )
    event = make_event("POST", "/oauth/token", headers={"Content-Type": FORM}, body=body)

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 400
    assert json.loads(response["body"])["error"] == "invalid_request"


def test_issue_token_rejects_wrong_assertion_type(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    lambda_context: LambdaContext,
) -> None:
    body = _form_body(
        grant_type=GRANT_TYPE,
        client_assertion_type="urn:example:something-else",
        client_assertion=make_assertion(),
    )
    event = make_event("POST", "/oauth/token", headers={"Content-Type": FORM}, body=body)

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 400
    assert json.loads(response["body"])["error"] == "invalid_request"


def test_issue_token_rejects_empty_body(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    event = make_event("POST", "/oauth/token", headers={"Content-Type": FORM}, body="")

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 400
    assert json.loads(response["body"])["error"] == "invalid_request"


def test_issue_token_rejects_an_assertion_signed_by_the_wrong_key(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    signing_keys: tuple[str, str],
    lambda_context: LambdaContext,
) -> None:
    body = _token_request(make_assertion(signing_key=signing_keys[0]))
    event = make_event("POST", "/oauth/token", headers={"Content-Type": FORM}, body=body)

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 401
    assert json.loads(response["body"])["error"] == "invalid_client"


def test_issue_token_rejects_an_expired_assertion(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    lambda_context: LambdaContext,
) -> None:
    event = make_event(
        "POST", "/oauth/token", headers={"Content-Type": FORM}, body=_token_request(make_assertion(lifetime=-120))
    )

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 401
    assert json.loads(response["body"])["error"] == "invalid_client"


def test_error_response_does_not_leak_the_failure_reason(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    lambda_context: LambdaContext,
) -> None:
    event = make_event(
        "POST", "/oauth/token", headers={"Content-Type": FORM}, body=_token_request(make_assertion(subject="other"))
    )

    response = lambda_handler(event, lambda_context)
    description = json.loads(response["body"])["error_description"]

    assert "UnknownClient" not in description
    assert "sub" not in description


def test_client_auth_failure_emits_a_metric_dimensioned_by_reason(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    signing_keys: tuple[str, str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # These 401s are invisible to Lambda's built-in Errors metric, so the custom
    # metric is the only signal that a client is failing to authenticate.
    from app import oauth

    dimensions: list[tuple[str, str]] = []
    monkeypatch.setattr(
        oauth.metrics, "add_dimension", lambda *, name, value: dimensions.append((name, value))
    )

    body = _token_request(make_assertion(signing_key=signing_keys[0]))
    lambda_handler(make_event("POST", "/oauth/token", headers={"Content-Type": FORM}, body=body), lambda_context)

    assert ("reason", "BadSignature") in dimensions


def test_bad_assertion_type_emits_its_own_metric_reason(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import oauth

    dimensions: list[tuple[str, str]] = []
    monkeypatch.setattr(
        oauth.metrics, "add_dimension", lambda *, name, value: dimensions.append((name, value))
    )

    body = _form_body(
        grant_type=GRANT_TYPE,
        client_assertion_type="urn:example:wrong",
        client_assertion=make_assertion(),
    )
    lambda_handler(make_event("POST", "/oauth/token", headers={"Content-Type": FORM}, body=body), lambda_context)

    assert ("reason", "BadAssertionType") in dimensions
```

`tests/test_oauth.py` needs `import pytest` at the top for the `monkeypatch` type annotation.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run --frozen pytest tests/test_oauth.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.oauth'`

- [ ] **Step 3: Implement `app/oauth.py`**

```python
from __future__ import annotations

import json
import time
import urllib.parse
import uuid

from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.event_handler.api_gateway import Response
from aws_lambda_powertools.event_handler.router import APIGatewayRouter
from aws_lambda_powertools.metrics import MetricUnit
import jwt

from app.auth import ClientAuthError, authenticate_client
from app.jwt import get_jwt_config, get_signing_kid

logger = Logger()
metrics = Metrics(namespace="Warsaw")
router = APIGatewayRouter()

GRANT_TYPE = "client_credentials"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
REASON_BAD_ASSERTION_TYPE = "BadAssertionType"


def _error(status_code: int, error: str, description: str) -> Response:
    return Response(
        status_code=status_code,
        content_type="application/json",
        body=json.dumps({"error": error, "error_description": description}),
    )


def _parse_token_request(body: str, content_type: str) -> dict[str, str]:
    if "application/json" in content_type:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return {}
        if not isinstance(data, dict):
            return {}
        return {key: str(value) for key, value in data.items()}

    return {key: values[0] for key, values in urllib.parse.parse_qs(body).items()}


@router.post("/oauth/token")
def issue_token() -> Response:
    event = router.current_event
    headers = dict(event.headers or {})
    content_type = headers.get("content-type", headers.get("Content-Type", ""))

    params = _parse_token_request(event.body or "", content_type)

    if params.get("grant_type") != GRANT_TYPE or params.get("client_assertion_type") != CLIENT_ASSERTION_TYPE:
        metrics.add_metric(name="ClientAuthFailure", unit=MetricUnit.Count, value=1)
        metrics.add_dimension(name="reason", value=REASON_BAD_ASSERTION_TYPE)
        logger.warning("Token request with unsupported grant or assertion type")
        return _error(400, "invalid_request", "Unsupported grant_type or client_assertion_type")

    try:
        client_id = authenticate_client(params.get("client_assertion", ""), get_jwt_config().issuer)
    except ClientAuthError as error:
        metrics.add_metric(name="ClientAuthFailure", unit=MetricUnit.Count, value=1)
        metrics.add_dimension(name="reason", value=error.reason)
        logger.warning("Client assertion rejected", extra={"reason": error.reason})
        return _error(401, "invalid_client", "Client authentication failed")

    jwt_config = get_jwt_config()
    now = int(time.time())
    claims = {
        "iss": jwt_config.issuer,
        "sub": client_id,
        "azp": client_id,
        "aud": jwt_config.audience,
        "iat": now,
        "exp": now + jwt_config.token_ttl_seconds,
        "jti": str(uuid.uuid4()),
        "scp": ["openid"],
    }
    token = jwt.encode(
        claims,
        jwt_config.private_key,
        algorithm="RS256",
        headers={"kid": get_signing_kid()},
    )

    logger.info("Access token issued", extra={"clientId": client_id})
    return Response(
        status_code=200,
        content_type="application/json",
        body=json.dumps(
            {
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": jwt_config.token_ttl_seconds,
                "scope": "openid",
            }
        ),
    )
```

- [ ] **Step 4: Register the router in `app/main.py`**

Add the import and the `include_router` call:

```python
from app.oauth import router as oauth_router

...
app = APIGatewayRestResolver()
app.include_router(oauth_router)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run --frozen pytest tests/test_oauth.py -v`
Expected: all 16 tests PASS

- [ ] **Step 6: Verify lint and full suite**

```bash
make lint
make unit
```
Expected: both pass.

- [ ] **Step 7: Commit**

```bash
git add app/oauth.py app/main.py tests/test_oauth.py
git commit -m "feat: add private_key_jwt token endpoint"
```

---

### Task 8: JWKS endpoint

**Files:**
- Create: `app/jwks.py`, `tests/test_jwks.py`
- Modify: `app/main.py` (register the router)

**Interfaces:**
- Consumes: `app.jwt.get_signing_public_key`, `app.jwt.get_signing_kid`, `app.keys.public_key_to_jwk`.
- Produces: `app.jwks.router`.

- [ ] **Step 1: Write the failing tests**

Powertools' REST resolver returns headers under `multiValueHeaders` (each value a list), **not** `headers` — asserting on `response["headers"]` raises `KeyError`.

Create `tests/test_jwks.py`:

```python
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import jwt
from jwt.algorithms import RSAAlgorithm

from app.jwt import get_signing_kid
from app.main import lambda_handler

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.conftest import LambdaContext


def test_jwks_returns_a_single_key(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    response = lambda_handler(make_event("GET", "/.well-known/jwks.json"), lambda_context)

    assert response["statusCode"] == 200
    keys = json.loads(response["body"])["keys"]
    assert len(keys) == 1


def test_jwks_entry_has_the_expected_fields(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    response = lambda_handler(make_event("GET", "/.well-known/jwks.json"), lambda_context)
    key = json.loads(response["body"])["keys"][0]

    assert set(key) == {"kty", "n", "e", "kid", "alg", "use"}
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert key["use"] == "sig"
    assert "key_ops" not in key


def test_jwks_kid_matches_the_signing_kid(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    response = lambda_handler(make_event("GET", "/.well-known/jwks.json"), lambda_context)
    key = json.loads(response["body"])["keys"][0]

    assert key["kid"] == get_signing_kid()


def test_jwks_sets_a_cache_control_header(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    response = lambda_handler(make_event("GET", "/.well-known/jwks.json"), lambda_context)

    assert response["multiValueHeaders"]["Cache-Control"] == ["public, max-age=300"]


def test_published_jwk_verifies_a_real_issued_token(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
) -> None:
    # The point of the endpoint: a client that only has the JWKS can verify our tokens.
    response = lambda_handler(make_event("GET", "/.well-known/jwks.json"), lambda_context)
    key = json.loads(response["body"])["keys"][0]

    public_key = RSAAlgorithm.from_jwk(json.dumps(key))
    claims = jwt.decode(make_token(), public_key, algorithms=["RS256"], audience="api://default")

    assert claims["scp"] == ["openid"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run --frozen pytest tests/test_jwks.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.jwks'`

- [ ] **Step 3: Implement `app/jwks.py`**

```python
from __future__ import annotations

import json

from aws_lambda_powertools.event_handler.api_gateway import Response
from aws_lambda_powertools.event_handler.router import APIGatewayRouter

from app.jwt import get_signing_kid, get_signing_public_key
from app.keys import public_key_to_jwk

router = APIGatewayRouter()

CACHE_CONTROL = "public, max-age=300"


@router.get("/.well-known/jwks.json")
def jwks() -> Response:
    key = public_key_to_jwk(get_signing_public_key())
    key["kid"] = get_signing_kid()
    key["alg"] = "RS256"
    key["use"] = "sig"

    return Response(
        status_code=200,
        content_type="application/json",
        body=json.dumps({"keys": [key]}),
        headers={"Cache-Control": CACHE_CONTROL},
    )
```

- [ ] **Step 4: Register the router in `app/main.py`**

```python
from app.jwks import router as jwks_router

...
app.include_router(jwks_router)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run --frozen pytest tests/test_jwks.py -v`
Expected: all 5 tests PASS

- [ ] **Step 6: Verify lint and full suite**

```bash
make lint
make unit
```
Expected: both pass.

- [ ] **Step 7: Commit**

```bash
git add app/jwks.py app/main.py tests/test_jwks.py
git commit -m "feat: add JWKS endpoint"
```

---

### Task 9: Producer endpoint

**Files:**
- Create: `app/producer.py`, `tests/test_producer.py`
- Modify: `app/main.py` (register the router), `tests/conftest.py` (clear `get_producer_config`)

**Interfaces:**
- Consumes: `app.clients.get_sqs_client`, `app.jwt.jwt_bearer`.
- Produces: `app.producer.router`, `ProducerConfig` with field `queue_url: str`, `get_producer_config() -> ProducerConfig` (cached).

- [ ] **Step 1: Add `get_producer_config` to the cache-clearing fixture in `tests/conftest.py`**

```python
@pytest.fixture(autouse=True)
def _reset_config_cache() -> None:
    from app.auth import get_auth_config, get_client_public_key
    from app.jwt import get_jwt_config, get_signing_kid, get_signing_public_key
    from app.producer import get_producer_config

    reset_config()
    init_config.cache_clear()
    get_auth_config.cache_clear()
    get_client_public_key.cache_clear()
    get_jwt_config.cache_clear()
    get_signing_public_key.cache_clear()
    get_signing_kid.cache_clear()
    get_producer_config.cache_clear()
```

- [ ] **Step 2: Add the SQS client cache-clearing fixture to `tests/conftest.py`**

Per the project convention, handler tests use moto with a real queue rather than patching `get_sqs_client`, so the cached client must be rebuilt inside the mock context:

```python
@pytest.fixture(autouse=True)
def _reset_sqs_client() -> None:
    from app.clients import get_sqs_client

    get_sqs_client.cache_clear()
```

- [ ] **Step 3: Write the failing tests**

Create `tests/test_producer.py`:

```python
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws
import pytest

from app.main import lambda_handler
from tests.conftest import QUEUE_NAME

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.conftest import LambdaContext


@pytest.fixture
def sqs_queue_url() -> Any:
    with mock_aws():
        client = boto3.client("sqs", region_name="eu-west-1")
        yield client.create_queue(QueueName=QUEUE_NAME)["QueueUrl"]


def _authorized(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def test_enqueue_accepts_an_authorized_request(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
    sqs_queue_url: str,
) -> None:
    monkeypatch.setenv("PRODUCER__QUEUE_URL", sqs_queue_url)
    body = json.dumps({"hello": "world"})
    event = make_event("POST", "/", headers=_authorized(make_token()), body=body)

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 202
    assert json.loads(response["body"])["message"] == "Accepted"


def test_enqueued_message_body_is_the_raw_request_body(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
    sqs_queue_url: str,
) -> None:
    monkeypatch.setenv("PRODUCER__QUEUE_URL", sqs_queue_url)
    body = json.dumps({"hello": "world"})
    event = make_event("POST", "/", headers=_authorized(make_token()), body=body)

    lambda_handler(event, lambda_context)

    messages = boto3.client("sqs", region_name="eu-west-1").receive_message(QueueUrl=sqs_queue_url)["Messages"]
    assert messages[0]["Body"] == body


def test_enqueue_rejects_an_unauthenticated_request(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
    sqs_queue_url: str,
) -> None:
    event = make_event("POST", "/", body=json.dumps({"hello": "world"}))

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 401


def test_enqueue_rejects_an_empty_body(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
    sqs_queue_url: str,
) -> None:
    monkeypatch.setenv("PRODUCER__QUEUE_URL", sqs_queue_url)
    event = make_event("POST", "/", headers=_authorized(make_token()), body="")

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 400
    assert json.loads(response["body"])["message"] == "Request body is required"


def test_enqueue_returns_500_when_sqs_fails(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
    sqs_queue_url: str,
) -> None:
    monkeypatch.setenv("PRODUCER__QUEUE_URL", sqs_queue_url)
    body = json.dumps({"hello": "world"})
    event = make_event("POST", "/", headers=_authorized(make_token()), body=body)

    error = ClientError({"Error": {"Code": "InternalError", "Message": "boom"}}, "SendMessage")
    with patch("app.producer.get_sqs_client") as client:
        client.return_value.send_message.side_effect = error
        response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 500
    assert json.loads(response["body"])["message"] == "Internal Server Error"


def test_sqs_failure_emits_an_enqueue_failure_metric(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
    sqs_queue_url: str,
) -> None:
    from app import producer

    monkeypatch.setenv("PRODUCER__QUEUE_URL", sqs_queue_url)
    emitted: list[str] = []
    monkeypatch.setattr(
        producer.metrics, "add_metric", lambda *, name, unit, value: emitted.append(name)
    )

    body = json.dumps({"hello": "world"})
    event = make_event("POST", "/", headers=_authorized(make_token()), body=body)
    error = ClientError({"Error": {"Code": "InternalError", "Message": "boom"}}, "SendMessage")
    with patch("app.producer.get_sqs_client") as client:
        client.return_value.send_message.side_effect = error
        lambda_handler(event, lambda_context)

    assert "EnqueueFailure" in emitted
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `uv run --frozen pytest tests/test_producer.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.producer'`

- [ ] **Step 5: Implement `app/producer.py`**

```python
from __future__ import annotations

from functools import cache
import json
from typing import ClassVar

from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.event_handler.api_gateway import Response
from aws_lambda_powertools.event_handler.router import APIGatewayRouter
from aws_lambda_powertools.metrics import MetricUnit
from botocore.exceptions import ClientError
from mb_config.config_manager import get_config
from pydantic import BaseModel

from app.clients import get_sqs_client
from app.jwt import jwt_bearer

logger = Logger()
metrics = Metrics(namespace="Warsaw")
router = APIGatewayRouter()


class ProducerConfig(BaseModel):
    section_name: ClassVar[str] = "producer"

    queue_url: str


@cache
def get_producer_config() -> ProducerConfig:
    config = get_config()
    return ProducerConfig.model_validate(config[ProducerConfig.section_name])


@router.post("/", middlewares=[jwt_bearer])
def enqueue() -> Response:
    event_body = router.current_event.body

    if not event_body:
        return Response(
            status_code=400,
            content_type="application/json",
            body=json.dumps({"message": "Request body is required"}),
        )

    try:
        producer_config = get_producer_config()
        result = get_sqs_client().send_message(QueueUrl=producer_config.queue_url, MessageBody=event_body)
    except ClientError:
        metrics.add_metric(name="EnqueueFailure", unit=MetricUnit.Count, value=1)
        logger.exception("Failed to enqueue request")
        return Response(
            status_code=500,
            content_type="application/json",
            body=json.dumps({"message": "Internal Server Error"}),
        )

    logger.info("Request allowed and enqueued", extra={"decision": "ALLOW", "messageId": result["MessageId"]})
    return Response(status_code=202, content_type="application/json", body=json.dumps({"message": "Accepted"}))
```

- [ ] **Step 6: Register the router in `app/main.py`**

```python
from app.producer import router as producer_router

...
app.include_router(producer_router)
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run --frozen pytest tests/test_producer.py -v`
Expected: all 6 tests PASS

- [ ] **Step 8: Verify lint and full suite**

```bash
make lint
make unit
```
Expected: both pass.

- [ ] **Step 9: Commit**

```bash
git add app/producer.py app/main.py tests/test_producer.py tests/conftest.py
git commit -m "feat: add authenticated SQS producer endpoint"
```

---

### Task 10: Committed client key, end-to-end test, and prod config test

Ties the pieces together and creates the real committed key the deployment needs.

**Files:**
- Create: `app/keys/client_public.pem`, `tests/test_committed_client_key.py`, `tests/test_end_to_end.py`, `tests/test_prod_config.py`

**Interfaces:**
- Consumes: everything from Tasks 2–9.
- Produces: nothing new; this task only adds verification and the committed key artifact.

- [ ] **Step 1: Generate the real client keypair**

```bash
make keypair-client
```

Expected: `app/keys/client_public.pem` and `out/client_private.pem` are created, and the `kid` is printed. `out/` is gitignored, so only the public key can be committed.

- [ ] **Step 2: Write the committed-key guard test**

Create `tests/test_committed_client_key.py`. This is the one test that must NOT use the generated fixture key — its whole job is to check the file that ships in the zip.

```python
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

    assert all("PRIVATE" not in path.read_text(encoding="utf-8") for path in committed)
```

- [ ] **Step 3: Write the end-to-end test**

Create `tests/test_end_to_end.py`. This is the only test that proves the token-signing key and the middleware's verification key are the same key.

```python
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
import urllib.parse

import boto3
from moto import mock_aws
import pytest

from app.main import lambda_handler
from app.oauth import CLIENT_ASSERTION_TYPE, GRANT_TYPE
from tests.conftest import QUEUE_NAME

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.conftest import LambdaContext

FORM = "application/x-www-form-urlencoded"


@pytest.fixture
def sqs_queue_url() -> Any:
    with mock_aws():
        client = boto3.client("sqs", region_name="eu-west-1")
        yield client.create_queue(QueueName=QUEUE_NAME)["QueueUrl"]


def test_token_from_the_token_endpoint_is_accepted_by_the_producer(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
    sqs_queue_url: str,
) -> None:
    monkeypatch.setenv("PRODUCER__QUEUE_URL", sqs_queue_url)

    token_body = urllib.parse.urlencode(
        {
            "grant_type": GRANT_TYPE,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": make_assertion(),
        }
    )
    token_response = lambda_handler(
        make_event("POST", "/oauth/token", headers={"Content-Type": FORM}, body=token_body),
        lambda_context,
    )
    assert token_response["statusCode"] == 200
    access_token = json.loads(token_response["body"])["access_token"]

    payload = json.dumps({"hello": "world"})
    enqueue_response = lambda_handler(
        make_event(
            "POST",
            "/",
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            body=payload,
        ),
        lambda_context,
    )

    assert enqueue_response["statusCode"] == 202

    messages = boto3.client("sqs", region_name="eu-west-1").receive_message(QueueUrl=sqs_queue_url)["Messages"]
    assert messages[0]["Body"] == payload
```

- [ ] **Step 4: Write the prod config test**

Create `tests/test_prod_config.py`:

```python
from __future__ import annotations

from typing import TYPE_CHECKING

from mb_config.config_manager import ConfigManager
from mb_config.loaders import ssm_param_loader

if TYPE_CHECKING:
    import pytest

FAKE_PARAMETERS = {
    "/projects/warsaw/allowed-client-id": {"Type": "String", "Value": "prod-client-id"},
    "/projects/warsaw/jwt-private-key": {"Type": "SecureString", "Value": "prod-private-key-pem"},
}


class FakeSsmClient:
    def get_parameter(self, *, Name: str, WithDecryption: bool = False) -> dict:  # noqa: N803, ARG002
        parameter = FAKE_PARAMETERS[Name]
        return {"Parameter": {"Type": parameter["Type"], "Value": parameter["Value"]}}


def test_prod_config_resolves_ssm_parameters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ssm_param_loader, "_create_client", FakeSsmClient)

    config = (
        ConfigManager()
        .add_yaml("app/configs/default.yaml")
        .add_yaml("app/configs/prod.yaml")
        .add_ssm_parameters()
        .get_config()
    )

    assert config["auth"]["allowed_client_id"] == FAKE_PARAMETERS["/projects/warsaw/allowed-client-id"]["Value"]
    assert config["jwt"]["private_key"] == FAKE_PARAMETERS["/projects/warsaw/jwt-private-key"]["Value"]
    assert "ssm_params" not in config


def test_prod_config_keeps_non_secret_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ssm_param_loader, "_create_client", FakeSsmClient)

    config = (
        ConfigManager()
        .add_yaml("app/configs/default.yaml")
        .add_yaml("app/configs/prod.yaml")
        .add_ssm_parameters()
        .get_config()
    )

    assert config["jwt"]["issuer"] == "https://auth.molnarbence.dev/"
    assert config["auth"]["client_public_key_path"] == "app/keys/client_public.pem"
    assert config["auth"]["max_assertion_lifetime_seconds"] == 300
```

- [ ] **Step 5: Run the full suite with coverage**

```bash
make coverage
```
Expected: all tests PASS and coverage is at or above the 75% gate.

- [ ] **Step 6: Verify lint**

Run: `make lint`
Expected: PASS

- [ ] **Step 7: Confirm no private key is staged**

```bash
git status --short
git diff --cached --name-only | grep -i private && echo "STOP: private key staged" || echo "clean"
```
Expected: `clean`. `out/` must not appear in `git status`.

- [ ] **Step 8: Commit**

```bash
git add app/keys/client_public.pem tests/test_committed_client_key.py tests/test_end_to_end.py tests/test_prod_config.py
git commit -m "feat: add committed client key with end-to-end and prod config tests"
```

---

### Task 11: Infrastructure templates

**Files:**
- Create: `aws/resource-group.yml`, `aws/iam-role.yml`, `template.yaml`

**Interfaces:**
- Consumes: nothing from the app tasks.
- Produces: stack outputs consumed by Task 12's workflow — `aws/iam-role.yml` exports `LambdaExecutionRoleArn`; `template.yaml` exports `FunctionArn`, `FunctionName`, `ApiGatewayUrl`.

- [ ] **Step 1: Create `aws/resource-group.yml`**

Copy helsinki's file verbatim:

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Resource group stack'

Parameters:
  ProjectName:
    Type: String
    Description: The name of the project to which this application belongs.

Outputs:
  ResourceGroupArn:
    Description: The ARN of the tag-based resource group containing the application's resources.
    Value: !GetAtt ApplicationResourceGroup.Arn

Resources:
  # Tag-based resource group: every resource tagged Project=<ProjectName>
  # automatically shows up in this group in the AWS Resource Groups console.
  ApplicationResourceGroup:
    Type: AWS::ResourceGroups::Group
    Properties:
      Name: !Ref ProjectName
      Description: "Application resource group managed via CloudFormation and visible in AWS Resource Groups."
      ResourceQuery:
        Type: TAG_FILTERS_1_0
        Query:
          ResourceTypeFilters:
            - AWS::AllSupported
          TagFilters:
            - Key: Project
              Values:
                - !Ref ProjectName
      Tags:
        - Key: Project
          Value: !Ref ProjectName
        - Key: Name
          Value: !Ref ProjectName
```

- [ ] **Step 2: Create `aws/iam-role.yml`**

Helsinki's role with the SSM path changed to `/projects/warsaw/*`.

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: IAM role for the Lambda function

Parameters:
  ProjectName:
    Type: String
    Description: Name of the project
  QueueArn:
    Type: AWS::SSM::Parameter::Value<String>
    Description: ARN of the SQS queue
    Default: /sqs/oslo/queue-arn
  RoleName:
    Type: String
    Description: Name of the IAM role for the Lambda function

Outputs:
  LambdaExecutionRoleArn:
    Description: ARN of the Lambda execution role
    Value: !GetAtt LambdaExecutionRole.Arn

Resources:
  LambdaExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: !Sub "${RoleName}-policy"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: sqs:SendMessage
                Resource: !Ref QueueArn
              - Effect: Allow
                Action: ssm:GetParameter
                Resource: !Sub "arn:aws:ssm:${AWS::Region}:${AWS::AccountId}:parameter/projects/warsaw/*"
              - Effect: Allow
                Action: kms:Decrypt
                Resource: !Sub "arn:aws:kms:${AWS::Region}:${AWS::AccountId}:alias/aws/ssm"
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Tags:
        - Key: Project
          Value: !Ref ProjectName
        - Key: Name
          Value: !Ref RoleName
```

- [ ] **Step 3: Create `template.yaml`**

Helsinki's SAM template with `PRODUCER__QUEUE_URL` wiring unchanged. The `ANY /` and `ANY /{proxy+}` events already cover `/oauth/token` and `/.well-known/jwks.json`, so no route additions are needed.

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Transform: AWS::Serverless-2016-10-31
Description: Serverless REST API with private_key_jwt authentication

Parameters:
  ProjectName:
    Type: String
    Description: Name of the project
  FunctionName:
    Type: String
    Description: Name of the Lambda function
  LambdaExecutionRoleArn:
    Type: String
    Description: ARN of the existing IAM role for the Lambda execution

  AllowedIps:
    Type: AWS::SSM::Parameter::Value<List<String>>
    Description: Comma-separated list of allowed source IP addresses
    Default: /allowed-ips/all
  QueueUrl:
    Type: AWS::SSM::Parameter::Value<String>
    Description: URL of the existing SQS queue
    Default: /sqs/oslo/queue-url

Outputs:
  FunctionArn:
    Description: ARN of the Lambda function
    Value: !GetAtt Function.Arn

  FunctionName:
    Description: Name of the Lambda function
    Value: !Ref FunctionName

  ApiGatewayUrl:
    Description: URL of the API Gateway endpoint
    Value: !Sub "https://${ApiGateway}.execute-api.${AWS::Region}.amazonaws.com/"

Resources:
  ApiGateway:
    Type: AWS::Serverless::Api
    Properties:
      StageName: Prod
      EndpointConfiguration: REGIONAL
      Auth:
        ResourcePolicy:
          CustomStatements:
            - Effect: Allow
              Principal: "*"
              Action: execute-api:Invoke
              Resource: "arn:aws:execute-api:*:*:*/*/*/*"
            - Effect: Deny
              Principal: "*"
              Action: execute-api:Invoke
              Resource: "arn:aws:execute-api:*:*:*/*/*/*"
              Condition:
                NotIpAddress:
                  aws:SourceIp: !Ref AllowedIps

  Function:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Ref FunctionName
      Runtime: python3.14
      Handler: app.main.lambda_handler
      CodeUri: lambda.zip
      Role: !Ref LambdaExecutionRoleArn
      Timeout: 10
      MemorySize: 128
      Environment:
        Variables:
          POWERTOOLS_SERVICE_NAME: !Ref FunctionName
          POWERTOOLS_LOG_LEVEL: INFO
          CONFIG_ENV: prod
          PRODUCER__QUEUE_URL: !Ref QueueUrl
      Tags:
        Project: !Ref ProjectName
        Name: !Ref FunctionName
      Events:
        ApiEventRoot:
          Type: Api
          Properties:
            RestApiId: !Ref ApiGateway
            Path: /
            Method: ANY
        ApiEvent:
          Type: Api
          Properties:
            RestApiId: !Ref ApiGateway
            Path: /{proxy+}
            Method: ANY

  LogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub "/aws/lambda/${FunctionName}"
      RetentionInDays: 30
      Tags:
        - Key: Project
          Value: !Ref ProjectName
        - Key: Name
          Value: !Sub "/aws/lambda/${FunctionName}"
```

- [ ] **Step 4: Run cfn-lint**

Run: `make cfn-lint`
Expected: PASS with no findings.

- [ ] **Step 5: Verify the Lambda package builds**

```bash
make build-lambda-package
unzip -l lambda.zip | grep -E "app/main.py|app/keys/client_public.pem|cryptography"
```

Expected: `app/main.py`, `app/keys/client_public.pem`, and `cryptography` files all appear. The `cryptography` entries confirm the RS256 dependency actually reaches the deployment artifact.

- [ ] **Step 6: Confirm no private key reached the zip**

```bash
unzip -p lambda.zip $(unzip -l lambda.zip | awk '/app\/keys\//{print $4}') | grep -c "PRIVATE KEY" || true
```

Expected: `0`.

- [ ] **Step 7: Clean the build artifacts and commit**

```bash
rm -rf build lambda.zip requirements.txt
git add aws/resource-group.yml aws/iam-role.yml template.yaml
git commit -m "feat: add resource group, IAM role, and SAM templates"
```

---

### Task 12: CI pipeline and README

**Files:**
- Create: `.github/workflows/main.yaml`
- Modify: `README.md`

**Interfaces:**
- Consumes: `aws/iam-role.yml`'s `LambdaExecutionRoleArn` output; the Makefile targets from Task 1.
- Produces: nothing consumed by other tasks.

- [ ] **Step 1: Create `.github/workflows/main.yaml`**

Helsinki's workflow with `PROJECT_NAME: warsaw` and the unused `jwt_issuer` / `jwt_audience` outputs removed from `prepare`.

```yaml
name: Main
run-name: Build & deploy 🚀
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

env:
  PROJECT_NAME: warsaw

permissions:
  id-token: write # REQUIRED for OIDC
  contents: read

jobs:
  prepare:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    outputs:
      project_name: ${{ steps.vars.outputs.project_name }}
    steps:
      - id: vars
        run: |
          echo "project_name=${{ env.PROJECT_NAME }}" >> "$GITHUB_OUTPUT"

  sonarqube:
    name: SonarQube
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          fetch-depth: 0  # Shallow clones should be disabled for a better relevancy of analysis

      - uses: astral-sh/setup-uv@11f9893b081a58869d3b5fccaea48c9e9e46f990 # v8.3.2
        with:
          enable-cache: true

      - name: Install dependencies
        run: make install-dev

      - name: Lint
        run: make lint

      - name: Coverage
        run: make coverage

      - name: SonarQube Scan
        uses: SonarSource/sonarqube-scan-action@713881670b6b3676cda39549040e2d88c70d582e # v8.2.0
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        with:
          args: >
            -Dsonar.qualitygate.wait=true

  build-lambda-zip:
    runs-on: ubuntu-latest
    needs:
      - sonarqube
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0

      - name: Install uv
        uses: astral-sh/setup-uv@11f9893b081a58869d3b5fccaea48c9e9e46f990 # v8.3.2

      - name: Build lambda package
        run: |
          make build-lambda-package

      - name: Upload Lambda ZIP artifact
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: lambda-zip
          path: lambda.zip

  cfn-lint:
    name: CloudFormation Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0

      - name: Install uv
        uses: astral-sh/setup-uv@11f9893b081a58869d3b5fccaea48c9e9e46f990 # v8.3.2

      - name: Run cfn-lint
        run: make cfn-lint

  deploy-resource-group:
    name: Deploy Resource Group
    needs:
      - prepare
      - cfn-lint
    uses: mb-dot-dev/reusable-workflows/.github/workflows/deploy-cloudformation.yaml@main
    secrets: inherit
    with:
      stack-name: ${{ needs.prepare.outputs.project_name }}-resource-group
      template: aws/resource-group.yml
      project: ${{ needs.prepare.outputs.project_name }}
      parameter-overrides: >-
        ProjectName=${{ needs.prepare.outputs.project_name }}

  deploy-iam-role:
    name: Deploy IAM Role
    needs:
      - prepare
      - cfn-lint
    uses: mb-dot-dev/reusable-workflows/.github/workflows/deploy-cloudformation.yaml@main
    with:
      stack-name: ${{ needs.prepare.outputs.project_name }}-iam-role
      template: aws/iam-role.yml
      parameter-overrides: >-
        ProjectName=${{ needs.prepare.outputs.project_name }},
        RoleName=${{ needs.prepare.outputs.project_name }}-lambda
      project: ${{ needs.prepare.outputs.project_name }}
    secrets: inherit

  deploy-lambda:
    name: Deploy Lambda
    runs-on: ubuntu-latest
    needs:
      - prepare
      - build-lambda-zip
      - deploy-iam-role
      - cfn-lint
    outputs:
      function_arn: ${{ steps.output.outputs.FunctionArn }}
      function_name: ${{ steps.output.outputs.FunctionName }}
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0

      - name: Download Lambda ZIP artifact
        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: lambda-zip

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@517a711dbcd0e402f90c77e7e2f81e849156e31d # v6.2.2
        with:
          role-to-assume: ${{ secrets.DEPLOY_ROLE_ARN }}
          aws-region: eu-central-1

      - name: Install AWS SAM CLI
        uses: aws-actions/setup-sam@89ddb14d60e682855e3fea4be85b3c56485de310 # v3
        with:
          version: 1.161.0
          use-installer: true

      - name: Define function stack name
        run: |
          echo "FUNCTION_STACK_NAME=${{ needs.prepare.outputs.project_name }}-lambda" >> "$GITHUB_ENV"

      - name: SAM Deploy
        run: |
          sam deploy \
            --stack-name $FUNCTION_STACK_NAME \
            --parameter-overrides \
            ProjectName=${{ needs.prepare.outputs.project_name }} \
            FunctionName=${{ needs.prepare.outputs.project_name }} \
            LambdaExecutionRoleArn=${{ fromJSON(needs.deploy-iam-role.outputs.stack-outputs-json).LambdaExecutionRoleArn }} \
            --tags Project=${{ needs.prepare.outputs.project_name }}

      - name: Output Lambda function details
        id: output
        run: |
          echo "FunctionArn=$(aws cloudformation describe-stacks --stack-name $FUNCTION_STACK_NAME --query 'Stacks[0].Outputs[?OutputKey==`FunctionArn`].OutputValue' --output text)" >> "$GITHUB_OUTPUT"
          echo "FunctionName=$(aws cloudformation describe-stacks --stack-name $FUNCTION_STACK_NAME --query 'Stacks[0].Outputs[?OutputKey==`FunctionName`].OutputValue' --output text)" >> "$GITHUB_OUTPUT"
```

- [ ] **Step 2: Rewrite `README.md`**

````markdown
# warsaw-self-signed-rest-api

REST API with `private_key_jwt` client authentication (RFC 7523) and self-signed RS256 access
tokens, published through a JWKS endpoint. Authenticated request bodies are enqueued to the
shared oslo SQS queue.

## Endpoints

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `POST` | `/oauth/token` | client assertion | issue an access token |
| `GET` | `/.well-known/jwks.json` | none (IP-gated) | publish the token verification key |
| `POST` | `/` | `Bearer` token | enqueue the request body |

All routes additionally sit behind an API Gateway resource policy that denies any source IP
outside the `/allowed-ips/all` SSM list.

## Getting a token

```bash
curl -X POST "$API/oauth/token" \
  -d grant_type=client_credentials \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion="$ASSERTION"
```

The assertion is a JWT signed with the client's private key (RS256) carrying `iss` and `sub`
set to the client id, `aud` set to `https://auth.molnarbence.dev/`, and an `exp` no more than
300 seconds out.

## Keys

| Key | Location | Purpose |
| --- | --- | --- |
| client private | held by the client only | signs the client assertion |
| client public | `app/keys/client_public.pem` | verifies the assertion |
| signing private | SSM `/projects/warsaw/jwt-private-key` | signs access tokens |
| signing public | derived at runtime | served at `/.well-known/jwks.json` |

Generate them with `make keypair-client` and `make keypair-signing`. Private keys land in the
gitignored `out/` directory and must never be committed.

## Development

```bash
make install-dev   # install dependencies
make test          # lint + unit tests
make cfn-lint      # lint CloudFormation templates
```

## CloudFormation stack diagram

```mermaid
flowchart TD
    RG["resource-group.yml<br/>tag-based group"]
    ROLE["iam-role.yml<br/>Out: LambdaExecutionRoleArn"]
    FN["template.yaml<br/>API Gateway + Lambda<br/>Out: ApiGatewayUrl"]
    SSM_Q["SSM /sqs/oslo/*<br/>(external)"]
    SSM_K["SSM /projects/warsaw/*<br/>(external)"]

    SSM_Q -->|"queue-arn"| ROLE
    SSM_Q -->|"queue-url"| FN
    ROLE -->|"LambdaExecutionRoleArn"| FN
    SSM_K -.->|"read at cold start"| FN
```
````

- [ ] **Step 3: Validate the workflow YAML parses**

```bash
uv run python -c "import yaml,pathlib; yaml.safe_load(pathlib.Path('.github/workflows/main.yaml').read_text()); print('ok')"
```
Expected: `ok`

- [ ] **Step 4: Run the full local gate**

```bash
make test
make cfn-lint
```
Expected: everything passes.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/main.yaml README.md
git commit -m "ci: add build and deploy pipeline, document the API"
```

---

## Deployment runbook

Not part of the plan's tasks — these are the manual steps needed once before the first deploy.

1. `make keypair-signing`, then:
   ```bash
   aws ssm put-parameter --name /projects/warsaw/jwt-private-key --type SecureString \
     --overwrite --value "file://out/warsaw_private.pem"
   rm out/warsaw_private.pem
   ```
2. ```bash
   aws ssm put-parameter --name /projects/warsaw/allowed-client-id --type String \
     --overwrite --value "<the agreed client id>"
   ```
3. Deliver `out/client_private.pem` (from Task 10) to the client over a secure channel, then
   delete the local copy.
4. Push to `main` to trigger the deploy.

## Post-deploy smoke test

```bash
API=$(aws cloudformation describe-stacks --stack-name warsaw-lambda \
  --query 'Stacks[0].Outputs[?OutputKey==`ApiGatewayUrl`].OutputValue' --output text)
curl -s "${API}Prod/.well-known/jwks.json" | jq .
```

Expected: a single JWK whose `kid` matches the one printed by `make keypair-signing`. A `kid`
mismatch means the SSM parameter and the key you distributed are different keys.
