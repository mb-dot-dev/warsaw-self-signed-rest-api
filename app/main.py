from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING

from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.event_handler import APIGatewayRestResolver
from mb_config.workloads import initialize_config

if TYPE_CHECKING:
    from aws_lambda_powertools.utilities.typing import LambdaContext

logger = Logger()
metrics = Metrics(namespace="Warsaw")
app = APIGatewayRestResolver()


@cache
def init_config() -> None:
    initialize_config("app/configs")


@metrics.log_metrics
@logger.inject_lambda_context
def lambda_handler(event: dict[str, object], context: LambdaContext) -> dict[str, object]:
    init_config()
    return app.resolve(event, context)
