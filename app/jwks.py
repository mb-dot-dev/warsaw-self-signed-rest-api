from __future__ import annotations

import json

from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.event_handler.api_gateway import Response
from aws_lambda_powertools.event_handler.router import APIGatewayRouter
from aws_lambda_powertools.metrics import MetricUnit

from app.jwt import get_signing_kid, get_signing_public_key
from app.keys import public_key_to_jwk

logger = Logger()
metrics = Metrics(namespace="Warsaw")
router = APIGatewayRouter()

CACHE_CONTROL = "public, max-age=300"


@router.get("/.well-known/jwks.json")
def jwks() -> Response:
    try:
        signing_public_key = get_signing_public_key()
    except ValueError, TypeError:
        # The configured signing private key is missing, malformed (ValueError from
        # cryptography), or valid but not RSA (TypeError from app.keys' isinstance
        # guard, e.g. an Ed25519 key). A server misconfiguration, not a client-facing
        # fault — same failure mode as the jwt_bearer middleware, so it gets the same
        # clean 500 and metric.
        metrics.add_metric(name="SigningKeyUnavailable", unit=MetricUnit.Count, value=1)
        logger.exception("JWKS publication failed due to a server misconfiguration")
        return Response(
            status_code=500,
            content_type="application/json",
            body=json.dumps({"message": "Internal Server Error"}),
        )

    key = public_key_to_jwk(signing_public_key)
    key["kid"] = get_signing_kid()
    key["alg"] = "RS256"
    key["use"] = "sig"

    return Response(
        status_code=200,
        content_type="application/json",
        body=json.dumps({"keys": [key]}),
        headers={"Cache-Control": CACHE_CONTROL},
    )
