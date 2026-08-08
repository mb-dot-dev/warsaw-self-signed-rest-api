from __future__ import annotations

from typing import TYPE_CHECKING

from mb_config.config_manager import ConfigManager
from mb_config.loaders import ssm_param_loader

if TYPE_CHECKING:
    import pytest

FAKE_PARAMETERS = {
    "/projects/warsaw/allowed-client-id": {"Type": "String", "Value": "prod-client-id"},
    "/projects/warsaw/jwt-private-key": {"Type": "SecureString", "Value": "prod-private-key-pem"},
}


class FakeSsmClient:
    def get_parameter(self, *, Name: str, WithDecryption: bool = False) -> dict:  # noqa: N803, ARG002
        parameter = FAKE_PARAMETERS[Name]
        return {"Parameter": {"Type": parameter["Type"], "Value": parameter["Value"]}}


def test_prod_config_resolves_ssm_parameters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ssm_param_loader, "_create_client", FakeSsmClient)

    config = (
        ConfigManager()
        .add_yaml("app/configs/default.yaml")
        .add_yaml("app/configs/prod.yaml")
        .add_ssm_parameters()
        .get_config()
    )

    assert config["auth"]["allowed_client_id"] == FAKE_PARAMETERS["/projects/warsaw/allowed-client-id"]["Value"]
    assert config["jwt"]["private_key"] == FAKE_PARAMETERS["/projects/warsaw/jwt-private-key"]["Value"]
    assert "ssm_params" not in config


def test_prod_config_keeps_non_secret_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ssm_param_loader, "_create_client", FakeSsmClient)

    config = (
        ConfigManager()
        .add_yaml("app/configs/default.yaml")
        .add_yaml("app/configs/prod.yaml")
        .add_ssm_parameters()
        .get_config()
    )

    assert config["jwt"]["issuer"] == "https://auth.molnarbence.dev/"
    assert config["auth"]["client_public_key_path"] == "app/keys/client_public.pem"
    assert config["auth"]["max_assertion_lifetime_seconds"] == 300
