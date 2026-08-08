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

# Config faults (corrupt/missing configured client public key) are operator errors, not
# a client authentication failure — kept distinct from app.auth's ClientAuthError reasons
# so this dimension value can never collide with one raised by authenticate_client.
REASON_MISCONFIGURED = "Misconfigured"


def _error(status_code: int, error: str, description: str) -> Response:
    return Response(
        status_code=status_code,
        content_type="application/json",
        body=json.dumps({"error": error, "error_description": description}),
    )


def _misconfigured_error(log_message: str) -> Response:
    # A bad key in configuration — client or signing side — is a server-side
    # misconfiguration, not a bad client credential. Logged at exception level so the
    # stack trace reaches the operator; the response body stays as generic as any other
    # error here, and the status code stays a 5xx so clients don't mistake a broken
    # deployment for their own invalid credentials.
    metrics.add_metric(name="ClientAuthFailure", unit=MetricUnit.Count, value=1)
    metrics.add_dimension(name="reason", value=REASON_MISCONFIGURED)
    logger.exception(log_message)
    return _error(500, "server_error", "The server encountered an unexpected error")


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
    except jwt.InvalidKeyError, OSError, TypeError, ValueError:
        # The configured client public key is missing, unreadable, malformed, or not RSA.
        # TypeError comes from app.keys' isinstance guard when a valid but non-RSA key
        # (e.g. Ed25519) is configured; ValueError from cryptography on an unparseable PEM.
        return _misconfigured_error("Client authentication failed due to a server misconfiguration")

    try:
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
    except ValueError, TypeError, jwt.InvalidKeyError:
        # The configured signing private key is missing, malformed, or not RSA: ValueError
        # from `cryptography` on an unparseable PEM, TypeError from app.keys' isinstance
        # guard on a valid but non-RSA key (e.g. Ed25519), InvalidKeyError from PyJWT.
        # Mirrors the client-key handling above — same failure mode, same clean 500
        # instead of an unhandled exception surfacing as an opaque Lambda 502.
        return _misconfigured_error("Token issuance failed due to a server misconfiguration")

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
