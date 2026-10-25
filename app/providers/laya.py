"""Laya Studio System One provider adapter (FR-03, Section 9.3)."""

from __future__ import annotations

from typing import Any, Dict, Optional
import httpx

from app.config import FenceSettings
from app.providers.base import STANDARD_SYSTEMONE_QUESTIONS, build_systemone_state
from app.providers.jev import JevProvider
from app.schemas import DecisionRequest


class LayaProvider(JevProvider):
    """
    Adapter for Laya Studio / laya-serve (POST https://api.laya.studio/v1/systemone).
    Implements the Jev-compatible /v1/systemone wire protocol with Laya checkpoint routing support.
    """

    def __init__(
        self,
        settings: FenceSettings,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        super().__init__(settings, http_client=http_client)

    @property
    def provider_name(self) -> str:
        return "laya"

    def _build_payload(self, request: DecisionRequest) -> Dict[str, Any]:
        # Laya supports 'english', 'multilingual', or 'typed-decisions' checkpoints
        model_id = self.settings.model_id or "typed-decisions"
        return {
            "model": model_id,
            "state": build_systemone_state(request.packed_context),
            "questions": STANDARD_SYSTEMONE_QUESTIONS,
        }
