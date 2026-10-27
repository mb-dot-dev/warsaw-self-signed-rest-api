"""Call the deployed warsaw API end to end.

Signs a client assertion, exchanges it for an access token, then POSTs a JSON body to the
producer endpoint:

    op run --env-file op.env -- uv run python -m scripts.call_api '{"hello": "world"}'

Configuration comes only from environment variables (see ENV_VARS). op.env maps each one to a
1Password secret reference, so `op run` injects them for the lifetime of the process and the
private key never touches disk.

Like generate_keypair, this must be run as a module (`-m scripts.call_api`) so `app` is
importable.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import TYPE_CHECKING
import uuid

import httpx2
import jwt

from app.oauth import CLIENT_ASSERTION_TYPE, GRANT_TYPE

if TYPE_CHECKING:
    from collections.abc import Mapping

DEFAULT_BODY = '{"hello": "world"}'
AUDIENCE = "https://auth.molnarbence.dev/"
ASSERTION_TTL_SECONDS = 60
REQUEST_TIMEOUT_SECONDS = 30

ENV_API_URL = "WARSAW_API_URL"
ENV_CLIENT_ID = "WARSAW_CLIENT_ID"
ENV_CLIENT_PRIVATE_KEY = "WARSAW_CLIENT_PRIVATE_KEY"
ENV_VARS = (ENV_API_URL, ENV_CLIENT_ID, ENV_CLIENT_PRIVATE_KEY)


class MissingEnvError(Exception):
    """Raised when required environment variables are unset or empty."""


def read_env(environ: Mapping[str, str] = os.environ) -> dict[str, str]:
    """Return the required settings, raising MissingEnvError naming every missing one."""
    missing = [name for name in ENV_VARS if not environ.get(name)]
    if missing:
        msg = f"missing environment variables: {', '.join(missing)} (run via `op run --env-file op.env --`)"
        raise MissingEnvError(msg)
    return {name: environ[name] for name in ENV_VARS}


def build_assertion(private_key_pem: str, client_id: str, *, now: int | None = None) -> str:
    """Return an RFC 7523 client assertion signed with the client private key."""
    issued_at = int(time.time()) if now is None else now
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": AUDIENCE,
        "iat": issued_at,
        "exp": issued_at + ASSERTION_TTL_SECONDS,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, private_key_pem, algorithm="RS256")


def make_client(api_url: str) -> httpx2.Client:
    """Return an HTTP client rooted at the API's stage URL."""
    return httpx2.Client(base_url=api_url, timeout=REQUEST_TIMEOUT_SECONDS)


def fetch_access_token(client: httpx2.Client, assertion: str) -> str:
    response = client.post(
        "oauth/token",
        data={
            "grant_type": GRANT_TYPE,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion,
        },
    )
    response.raise_for_status()
    return response.json()["access_token"]


def enqueue(client: httpx2.Client, access_token: str, body: str) -> str:
    response = client.post(
        "",
        content=body,
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
    )
    response.raise_for_status()
    return response.text


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Call the deployed warsaw API.")
    parser.add_argument("body", nargs="?", default=DEFAULT_BODY, help=f"JSON body to POST (default: {DEFAULT_BODY}).")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        json.loads(args.body)
    except json.JSONDecodeError as error:
        print(f"error: body is not valid JSON: {error}", file=sys.stderr)
        return 1

    try:
        env = read_env()
    except MissingEnvError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    api_url = env[ENV_API_URL].rstrip("/") + "/"
    try:
        assertion = build_assertion(env[ENV_CLIENT_PRIVATE_KEY], env[ENV_CLIENT_ID])
        with make_client(api_url) as client:
            access_token = fetch_access_token(client, assertion)
            print(enqueue(client, access_token, args.body))
    except httpx2.HTTPStatusError as error:
        response = error.response
        print(f"error: {error.request.url} returned {response.status_code}: {response.text}", file=sys.stderr)
        return 1
    except httpx2.HTTPError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
