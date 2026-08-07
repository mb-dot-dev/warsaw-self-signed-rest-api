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
