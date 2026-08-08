from __future__ import annotations

from app.clients import get_sqs_client


def test_get_sqs_client_is_cached() -> None:
    get_sqs_client.cache_clear()

    assert get_sqs_client() is get_sqs_client()
