from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws
import pytest

from app.main import lambda_handler
from tests.conftest import QUEUE_NAME

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from tests.conftest import LambdaContext


@pytest.fixture
def sqs_queue_url() -> Iterator[str]:
    with mock_aws():
        client = boto3.client("sqs", region_name="eu-west-1")
        yield client.create_queue(QueueName=QUEUE_NAME)["QueueUrl"]


def _authorized(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def test_enqueue_accepts_an_authorized_request(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
    sqs_queue_url: str,
) -> None:
    monkeypatch.setenv("PRODUCER__QUEUE_URL", sqs_queue_url)
    body = json.dumps({"hello": "world"})
    event = make_event("POST", "/", headers=_authorized(make_token()), body=body)

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 202
    assert json.loads(response["body"])["message"] == "Accepted"


def test_enqueued_message_body_is_the_raw_request_body(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
    sqs_queue_url: str,
) -> None:
    monkeypatch.setenv("PRODUCER__QUEUE_URL", sqs_queue_url)
    body = json.dumps({"hello": "world"})
    event = make_event("POST", "/", headers=_authorized(make_token()), body=body)

    lambda_handler(event, lambda_context)

    messages = boto3.client("sqs", region_name="eu-west-1").receive_message(QueueUrl=sqs_queue_url)["Messages"]
    assert messages[0]["Body"] == body


def test_enqueued_message_body_is_not_parsed_or_validated_as_json(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
    sqs_queue_url: str,
) -> None:
    # Pins the "raw body, no parsing" contract: a downstream consumer depends on receiving
    # exactly what the client sent, even if it is not valid JSON. If someone later adds
    # JSON validation to this handler, this test must fail.
    monkeypatch.setenv("PRODUCER__QUEUE_URL", sqs_queue_url)
    body = "not json at all {{{"
    event = make_event("POST", "/", headers=_authorized(make_token()), body=body)

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 202
    messages = boto3.client("sqs", region_name="eu-west-1").receive_message(QueueUrl=sqs_queue_url)["Messages"]
    assert messages[0]["Body"] == body


def test_enqueue_rejects_an_unauthenticated_request(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
    sqs_queue_url: str,
) -> None:
    event = make_event("POST", "/", body=json.dumps({"hello": "world"}))

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 401


def test_enqueue_rejects_an_empty_body(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
    sqs_queue_url: str,
) -> None:
    monkeypatch.setenv("PRODUCER__QUEUE_URL", sqs_queue_url)
    event = make_event("POST", "/", headers=_authorized(make_token()), body="")

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 400
    assert json.loads(response["body"])["message"] == "Request body is required"


def test_enqueue_returns_500_when_sqs_fails(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
    sqs_queue_url: str,
) -> None:
    monkeypatch.setenv("PRODUCER__QUEUE_URL", sqs_queue_url)
    body = json.dumps({"hello": "world"})
    event = make_event("POST", "/", headers=_authorized(make_token()), body=body)

    error = ClientError({"Error": {"Code": "InternalError", "Message": "boom"}}, "SendMessage")
    with patch("app.producer.get_sqs_client") as client:
        client.return_value.send_message.side_effect = error
        response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 500
    assert json.loads(response["body"])["message"] == "Internal Server Error"


def test_sqs_failure_emits_an_enqueue_failure_metric(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
    monkeypatch: pytest.MonkeyPatch,
    sqs_queue_url: str,
) -> None:
    from app import producer

    monkeypatch.setenv("PRODUCER__QUEUE_URL", sqs_queue_url)
    emitted: list[str] = []
    monkeypatch.setattr(producer.metrics, "add_metric", lambda **kwargs: emitted.append(kwargs["name"]))

    body = json.dumps({"hello": "world"})
    event = make_event("POST", "/", headers=_authorized(make_token()), body=body)
    error = ClientError({"Error": {"Code": "InternalError", "Message": "boom"}}, "SendMessage")
    with patch("app.producer.get_sqs_client") as client:
        client.return_value.send_message.side_effect = error
        lambda_handler(event, lambda_context)

    assert "EnqueueFailure" in emitted
