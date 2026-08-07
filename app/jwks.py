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
