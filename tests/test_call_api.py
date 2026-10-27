from __future__ import annotations

from typing import TYPE_CHECKING
import urllib.parse

import httpx2
import jwt
import pytest

from app.oauth import CLIENT_ASSERTION_TYPE, GRANT_TYPE
from scripts import call_api

if TYPE_CHECKING:
    from collections.abc import Callable

API_URL = "https://api.example.test/Prod/"


def test_build_assertion_carries_rfc7523_claims(client_keys: tuple[str, str]) -> None:
    private_pem, public_pem = client_keys

    assertion = call_api.build_assertion(private_pem, "warsaw-cli", now=1_000)
    claims = jwt.decode(
        assertion,
        public_pem,
        algorithms=["RS256"],
        audience=call_api.AUDIENCE,
        options={"verify_exp": False, "verify_iat": False},
    )

    assert claims["iss"] == "warsaw-cli"
    assert claims["sub"] == "warsaw-cli"
    assert claims["exp"] - claims["iat"] == call_api.ASSERTION_TTL_SECONDS
    assert claims["jti"]


def test_build_assertion_uses_a_fresh_jti(client_keys: tuple[str, str]) -> None:
    first = jwt.decode(call_api.build_assertion(client_keys[0], "c"), options={"verify_signature": False})
    second = jwt.decode(call_api.build_assertion(client_keys[0], "c"), options={"verify_signature": False})

    assert first["jti"] != second["jti"]


def _accepting_handler(request: httpx2.Request) -> httpx2.Response:
    if request.url.path.endswith("/oauth/token"):
        return httpx2.Response(200, json={"access_token": "the-token"})
    return httpx2.Response(202, json={"message": "Accepted"})


@pytest.fixture
def fake_backend(monkeypatch: pytest.MonkeyPatch, client_keys: tuple[str, str]) -> Callable[..., list[httpx2.Request]]:
    """Set the env vars op run would inject and stub the API; call the result to get the requests made."""
    requests: list[httpx2.Request] = []
    handler: list[Callable[[httpx2.Request], httpx2.Response]] = [_accepting_handler]

    def transport(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return handler[0](request)

    def make_client(api_url: str) -> httpx2.Client:
        return httpx2.Client(base_url=api_url, transport=httpx2.MockTransport(transport))

    def install(new_handler: Callable[[httpx2.Request], httpx2.Response] | None = None) -> list[httpx2.Request]:
        if new_handler is not None:
            handler[0] = new_handler
        return requests

    monkeypatch.setenv(call_api.ENV_API_URL, API_URL.rstrip("/"))
    monkeypatch.setenv(call_api.ENV_CLIENT_ID, "warsaw-cli")
    monkeypatch.setenv(call_api.ENV_CLIENT_PRIVATE_KEY, client_keys[0])
    monkeypatch.setattr(call_api, "make_client", make_client)
    return install


def test_main_exchanges_an_assertion_then_posts_the_body(
    fake_backend: Callable[..., list[httpx2.Request]],
    client_keys: tuple[str, str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert call_api.main(['{"a": 1}']) == 0

    token_request, enqueue_request = fake_backend()
    form = dict(urllib.parse.parse_qsl(token_request.content.decode()))
    assert str(token_request.url) == f"{API_URL}oauth/token"
    assert form["grant_type"] == GRANT_TYPE
    assert form["client_assertion_type"] == CLIENT_ASSERTION_TYPE
    claims = jwt.decode(form["client_assertion"], client_keys[1], algorithms=["RS256"], audience=call_api.AUDIENCE)
    assert claims["iss"] == "warsaw-cli"

    assert str(enqueue_request.url) == API_URL
    assert enqueue_request.content == b'{"a": 1}'
    assert enqueue_request.headers["Authorization"] == "Bearer the-token"
    assert "Accepted" in capsys.readouterr().out


def test_main_reports_every_missing_env_var_without_calling_the_api(
    fake_backend: Callable[..., list[httpx2.Request]],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv(call_api.ENV_CLIENT_ID)
    monkeypatch.setenv(call_api.ENV_CLIENT_PRIVATE_KEY, "")

    assert call_api.main([]) == 1

    assert fake_backend() == []
    err = capsys.readouterr().err
    assert call_api.ENV_CLIENT_ID in err
    assert call_api.ENV_CLIENT_PRIVATE_KEY in err
    assert call_api.ENV_API_URL not in err


def test_main_reports_a_rejected_token_request(
    fake_backend: Callable[..., list[httpx2.Request]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    requests = fake_backend(lambda _request: httpx2.Response(401, json={"error": "invalid_client"}))

    assert call_api.main([]) == 1

    assert len(requests) == 1  # never reached the enqueue call
    err = capsys.readouterr().err
    assert "401" in err
    assert "invalid_client" in err


def test_main_rejects_invalid_json_without_calling_the_api(
    fake_backend: Callable[..., list[httpx2.Request]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert call_api.main(["not json"]) == 1
    assert fake_backend() == []
    assert "not valid JSON" in capsys.readouterr().err


def test_make_client_is_rooted_at_the_stage_url() -> None:
    with call_api.make_client(API_URL) as client:
        assert str(client.build_request("POST", "oauth/token").url) == f"{API_URL}oauth/token"
        assert str(client.build_request("POST", "").url) == API_URL
