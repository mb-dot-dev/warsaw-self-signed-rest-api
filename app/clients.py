from __future__ import annotations

import functools
from typing import TYPE_CHECKING

import boto3

if TYPE_CHECKING:
    from botocore.client import BaseClient


@functools.cache
def get_sqs_client() -> BaseClient:
    return boto3.client("sqs")
