from __future__ import annotations

from functools import cache
import json
from typing import TYPE_CHECKING, ClassVar

from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.event_handler import Response
from aws_lambda_powertools.metrics import MetricUnit
import jwt
from mb_config import get_config
from pydantic import BaseModel

from app.keys import compute_kid, derive_public_key_pem

if TYPE_CHECKING:
    from aws_lambda_powertools.event_handler import ApiGatewayResolver
    from aws_lambda_powertools.event_handler.middlewares import NextMiddleware

logger = Logger()
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


def _signing_key_unavailable(log_message: str) -> Response:
    # The configured signing private key is missing or malformed. This is a server
    # misconfiguration, not a bad token, so it must not surface as (or be counted
    # alongside) a 401 TokenRejected — an unauthenticated caller must not be told
    # their token is invalid when the real fault is on our side.
    metrics.add_metric(name="SigningKeyUnavailable", unit=MetricUnit.Count, value=1)
    logger.exception(log_message)
    return Response(
        status_code=500,
        content_type="application/json",
        body=json.dumps({"message": "Internal Server Error"}),
    )


def jwt_bearer(app: ApiGatewayResolver, next_middleware: NextMiddleware) -> Response:
    jwt_config = get_jwt_config()

    auth_header = app.current_event.headers.get("Authorization", "")
    # Compare only the scheme prefix case-insensitively (RFC 6750 §2.1) so the JWT itself
    # is never copied/lowercased on every request.
    if auth_header[: len(_BEARER_PREFIX)].lower() != _BEARER_PREFIX.lower():
        return _unauthorized("Unauthorized")

    token = auth_header[len(_BEARER_PREFIX) :]

    try:
        signing_public_key = get_signing_public_key()
    except ValueError, TypeError:
        # ValueError: cryptography rejecting an unparseable PEM.
        # TypeError: app.keys' isinstance guard on a valid but non-RSA key (e.g. Ed25519).
        return _signing_key_unavailable("Token verification failed due to a server misconfiguration")

    try:
        jwt.decode(
            token,
            signing_public_key,
            algorithms=["RS256"],
            audience=jwt_config.audience,
            issuer=jwt_config.issuer,
            leeway=jwt_config.leeway_seconds,
            options={"require": ["exp", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError:
        return _unauthorized("Token has expired")
    except jwt.InvalidTokenError:
        return _unauthorized("Unauthorized")

    return next_middleware(app)
