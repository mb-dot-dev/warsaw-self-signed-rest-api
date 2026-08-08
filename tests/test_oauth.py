from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
import urllib.parse

from cryptography.hazmat.primitives import serialization
import jwt

from app.main import lambda_handler
from app.oauth import CLIENT_ASSERTION_TYPE, GRANT_TYPE, _parse_token_request
from tests.conftest import ALLOWED_CLIENT_ID, AUDIENCE, ISSUER, generate_non_rsa_private_key_pem

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import pytest

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
    event = make_event("POST", "/oauth/token", headers={"Content-Type": FORM}, body=_token_request(make_assertion()))

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

    event = make_event("POST", "/oauth/token", headers={"Content-Type": FORM}, body=_token_request(make_assertion()))

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
    monkeypatch.setattr(oauth.metrics, "add_dimension", lambda *, name, value: dimensions.append((name, value)))

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
    monkeypatch.setattr(oauth.metrics, "add_dimension", lambda *, name, value: dimensions.append((name, value)))

    body = _form_body(
        grant_type=GRANT_TYPE,
        client_assertion_type="urn:example:wrong",
        client_assertion=make_assertion(),
    )
    lambda_handler(make_event("POST", "/oauth/token", headers={"Content-Type": FORM}, body=body), lambda_context)

    assert ("reason", "BadAssertionType") in dimensions


def test_issue_token_returns_server_error_when_client_public_key_file_is_missing(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import oauth

    dimensions: list[tuple[str, str]] = []
    monkeypatch.setattr(oauth.metrics, "add_dimension", lambda *, name, value: dimensions.append((name, value)))
    monkeypatch.setenv("AUTH__CLIENT_PUBLIC_KEY_PATH", "/nonexistent/path/does-not-exist.pem")

    event = make_event("POST", "/oauth/token", headers={"Content-Type": FORM}, body=_token_request(make_assertion()))

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 500
    assert json.loads(response["body"])["error"] == "server_error"
    assert ("reason", "Misconfigured") in dimensions


def test_issue_token_returns_server_error_when_client_public_key_is_garbage(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from app import oauth

    dimensions: list[tuple[str, str]] = []
    monkeypatch.setattr(oauth.metrics, "add_dimension", lambda *, name, value: dimensions.append((name, value)))

    bad_key_path = tmp_path / "garbage.pem"
    bad_key_path.write_text("this is not a PEM key", encoding="utf-8")
    monkeypatch.setenv("AUTH__CLIENT_PUBLIC_KEY_PATH", str(bad_key_path))

    event = make_event("POST", "/oauth/token", headers={"Content-Type": FORM}, body=_token_request(make_assertion()))

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 500
    assert json.loads(response["body"])["error"] == "server_error"
    assert ("reason", "Misconfigured") in dimensions


def test_issue_token_returns_server_error_when_signing_private_key_is_malformed(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Mirrors the client-key misconfiguration tests above: a corrupt signing key is the
    # same class of operator fault as a corrupt client key, and must fail the same clean way
    # (500 server_error, Misconfigured metric) rather than an unhandled 502.
    from app import oauth

    dimensions: list[tuple[str, str]] = []
    monkeypatch.setattr(oauth.metrics, "add_dimension", lambda *, name, value: dimensions.append((name, value)))
    monkeypatch.setenv("JWT__PRIVATE_KEY", "this is not a PEM key")

    event = make_event("POST", "/oauth/token", headers={"Content-Type": FORM}, body=_token_request(make_assertion()))

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 500
    assert json.loads(response["body"])["error"] == "server_error"
    assert ("reason", "Misconfigured") in dimensions


def test_issue_token_returns_server_error_when_signing_key_is_valid_but_not_rsa(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A valid non-RSA signing key raises TypeError rather than ValueError; it must still
    # produce the clean 500 + Misconfigured metric, not an unhandled 502.
    from app import oauth

    dimensions: list[tuple[str, str]] = []
    monkeypatch.setattr(oauth.metrics, "add_dimension", lambda *, name, value: dimensions.append((name, value)))
    monkeypatch.setenv("JWT__PRIVATE_KEY", generate_non_rsa_private_key_pem())

    event = make_event("POST", "/oauth/token", headers={"Content-Type": FORM}, body=_token_request(make_assertion()))

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 500
    assert json.loads(response["body"])["error"] == "server_error"
    assert ("reason", "Misconfigured") in dimensions


def test_issue_token_returns_server_error_when_client_public_key_is_valid_but_not_rsa(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Same fault on the verifying side: a valid but non-RSA client public key.
    key_path = tmp_path / "not_rsa_public.pem"
    private_key = serialization.load_pem_private_key(generate_non_rsa_private_key_pem().encode(), password=None)
    key_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setenv("AUTH__CLIENT_PUBLIC_KEY_PATH", str(key_path))

    event = make_event("POST", "/oauth/token", headers={"Content-Type": FORM}, body=_token_request(make_assertion()))

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 500
    assert json.loads(response["body"])["error"] == "server_error"
