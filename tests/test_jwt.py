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
        app_jwt.metrics,
        "add_metric",
        lambda *, name, unit, value: emitted.append(name),  # noqa: ARG005
    )

    _resolve(make_event("GET", "/protected"), lambda_context)

    assert "TokenRejected" in emitted
