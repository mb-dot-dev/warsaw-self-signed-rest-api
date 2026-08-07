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
    from app.auth import get_auth_config, get_client_public_key

    reset_config()
    init_config.cache_clear()
    get_auth_config.cache_clear()
    get_client_public_key.cache_clear()


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
    def _make_assertion(  # noqa: PLR0913
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
