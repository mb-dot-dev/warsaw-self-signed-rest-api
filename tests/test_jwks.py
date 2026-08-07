from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.asymmetric import rsa
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


def test_jwks_entry_has_no_private_key_material(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    # Guard against a catastrophic private key disclosure: if the derivation ever
    # swapped to serializing the private key, these RSA private-JWK params (d, p, q,
    # dp, dq, qi) would appear alongside n/e. They must never be present.
    response = lambda_handler(make_event("GET", "/.well-known/jwks.json"), lambda_context)
    key = json.loads(response["body"])["keys"][0]

    private_key_params = {"d", "p", "q", "dp", "dq", "qi"}
    assert not private_key_params & set(key)


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
    assert isinstance(public_key, rsa.RSAPublicKey)
    claims = jwt.decode(make_token(), public_key, algorithms=["RS256"], audience="api://default")

    assert claims["scp"] == ["openid"]
