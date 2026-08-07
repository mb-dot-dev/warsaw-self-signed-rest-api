from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import TYPE_CHECKING

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
    # An attacker who knows the public key tries to use it as an HMAC secret. PyJWT >=2.10
    # refuses to jwt.encode() a PEM-formatted key under HS256 (its own defense against this
    # exact attack), so the forged token is assembled by hand here to prove that it is our
    # `algorithms=["RS256"]` allowlist in app.auth, not PyJWT's encode-side guard, that stops it.
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"iss": ALLOWED_CLIENT_ID, "sub": ALLOWED_CLIENT_ID, "aud": ISSUER}).encode()
    ).rstrip(b"=")
    signing_input = header + b"." + payload
    digest = hmac.new(client_keys[1].encode(), signing_input, hashlib.sha256).digest()
    signature = base64.urlsafe_b64encode(digest).rstrip(b"=")
    forged = (signing_input + b"." + signature).decode()

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
