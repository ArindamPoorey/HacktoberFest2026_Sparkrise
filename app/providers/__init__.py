"""Provider factory and registry for Permission Fence."""

from __future__ import annotations

from typing import Optional
import httpx

from app.config import FenceSettings
from app.providers.base import DecisionProvider
from app.providers.custom import CustomProvider
from app.providers.jev import JevProvider
from app.providers.laya import LayaProvider
from app.providers.mock import MockProvider


def get_provider(
    settings: FenceSettings,
    http_client: Optional[httpx.Client] = None,
    mock_scenario: Optional[str] = None,
) -> DecisionProvider:
    """Instantiate the configured DecisionProvider adapter."""
    provider_key = settings.model_provider.strip().lower()
    if provider_key == "jev":
        return JevProvider(settings=settings, http_client=http_client)
    if provider_key == "laya":
        return LayaProvider(settings=settings, http_client=http_client)
    if provider_key == "custom":
        return CustomProvider(settings=settings, http_client=http_client)
    if provider_key == "mock":
        return MockProvider(settings=settings, scenario_override=mock_scenario)
    raise ValueError(f"Unsupported provider '{settings.model_provider}'.")


__all__ = [
    "DecisionProvider",
    "JevProvider",
    "LayaProvider",
    "CustomProvider",
    "MockProvider",
    "get_provider",
]
