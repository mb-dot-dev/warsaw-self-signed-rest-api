from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mb_config.config_manager import get_config

from app.main import init_config, lambda_handler
from tests.conftest import ALLOWED_CLIENT_ID, AUDIENCE, ISSUER, QUEUE_URL

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.conftest import LambdaContext


def test_init_config_loads_defaults_and_env_overrides() -> None:
    init_config()
    config = get_config()

    assert config["jwt"]["issuer"] == ISSUER
    assert config["jwt"]["audience"] == AUDIENCE
    assert config["auth"]["allowed_client_id"] == ALLOWED_CLIENT_ID
    assert config["producer"]["queue_url"] == QUEUE_URL


def test_init_config_is_cached() -> None:
    init_config()

    assert init_config.cache_info().currsize == 1


def test_lambda_handler_returns_404_for_unknown_route(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    response = lambda_handler(make_event("GET", "/nope"), lambda_context)

    assert response["statusCode"] == 404
