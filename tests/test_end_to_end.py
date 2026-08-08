from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
import urllib.parse

import boto3
from moto import mock_aws
import pytest

from app.main import lambda_handler
from app.oauth import CLIENT_ASSERTION_TYPE, GRANT_TYPE
from tests.conftest import QUEUE_NAME

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from tests.conftest import LambdaContext

FORM = "application/x-www-form-urlencoded"


@pytest.fixture
def sqs_queue_url() -> Iterator[str]:
    with mock_aws():
        client = boto3.client("sqs", region_name="eu-west-1")
        yield client.create_queue(QueueName=QUEUE_NAME)["QueueUrl"]


def test_token_from_the_token_endpoint_is_accepted_by_the_producer(
    make_event: Callable[..., dict[str, Any]],
    make_assertion: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
    sqs_queue_url: str,
) -> None:
    monkeypatch.setenv("PRODUCER__QUEUE_URL", sqs_queue_url)

    token_body = urllib.parse.urlencode(
        {
            "grant_type": GRANT_TYPE,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": make_assertion(),
        }
    )
    token_response = lambda_handler(
        make_event("POST", "/oauth/token", headers={"Content-Type": FORM}, body=token_body),
        lambda_context,
    )
    assert token_response["statusCode"] == 200
    access_token = json.loads(token_response["body"])["access_token"]

    payload = json.dumps({"hello": "world"})
    enqueue_response = lambda_handler(
        make_event(
            "POST",
            "/",
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            body=payload,
        ),
        lambda_context,
    )

    assert enqueue_response["statusCode"] == 202

    messages = boto3.client("sqs", region_name="eu-west-1").receive_message(QueueUrl=sqs_queue_url)["Messages"]
    assert messages[0]["Body"] == payload
