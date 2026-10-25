"""Custom compatible System One endpoint adapter (FR-03)."""

from __future__ import annotations

from typing import Optional
import httpx

from app.config import FenceSettings
from app.providers.jev import JevProvider


class CustomProvider(JevProvider):
    """Adapter for any custom or self-hosted endpoint implementing the /v1/systemone schema."""

    def __init__(
        self,
        settings: FenceSettings,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        super().__init__(settings, http_client=http_client)

    @property
    def provider_name(self) -> str:
        return "custom"
