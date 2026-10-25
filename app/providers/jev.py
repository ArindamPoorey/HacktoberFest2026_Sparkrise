"""Jev System One provider adapter (FR-03, Section 9.3)."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional
import httpx

from app.config import FenceSettings
from app.providers.base import (
    DecisionProvider,
    STANDARD_SYSTEMONE_QUESTIONS,
    build_systemone_state,
    normalize_systemone_response,
)
from app.schemas import DecisionRequest, NormalizedDecisionResult


class JevProvider(DecisionProvider):
    """Adapter for TypeSafe AI's Jev System One API (POST https://api.typesafe.ai/v1/systemone)."""

    def __init__(
        self,
        settings: FenceSettings,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        super().__init__(settings)
        self._client = http_client

    @property
    def provider_name(self) -> str:
        return "jev"

    def _build_headers(self) -> Dict[str, str]:
        api_key = (self.settings.model_api_key or "").strip()
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if api_key and api_key != "replace_me":
            scheme = self.settings.auth_scheme.strip()
            auth_val = f"{scheme} {api_key}" if scheme else api_key
            headers[self.settings.auth_header_name] = auth_val
        return headers

    def _build_payload(self, request: DecisionRequest) -> Dict[str, Any]:
        return {
            "model": self.settings.model_id or "jev-latest",
            "state": build_systemone_state(request.packed_context),
            "questions": STANDARD_SYSTEMONE_QUESTIONS,
        }

    def evaluate(self, request: DecisionRequest) -> NormalizedDecisionResult:
        api_key = (self.settings.model_api_key or "").strip()
        if not api_key or api_key == "replace_me":
            return NormalizedDecisionResult(
                provider=self.provider_name,
                model_id=self.settings.model_id,
                provider_error="Authentication configuration error: MODEL_API_KEY is missing or set to placeholder.",
                is_valid_schema=False,
            )

        url = self.settings.full_endpoint_url
        headers = self._build_headers()
        payload = self._build_payload(request)

        max_attempts = 1 + max(0, self.settings.model_max_transport_retries)
        last_error: Optional[str] = None
        start_ts = time.perf_counter()

        for attempt in range(1, max_attempts + 1):
            attempt_start = time.perf_counter()
            try:
                if self._client is not None:
                    response = self._client.post(
                        url,
                        json=payload,
                        headers=headers,
                        timeout=self.settings.model_timeout_seconds,
                        follow_redirects=False,
                    )
                else:
                    with httpx.Client(
                        timeout=self.settings.model_timeout_seconds,
                        follow_redirects=False,
                    ) as client:
                        response = client.post(url, json=payload, headers=headers)

                latency_ms = (time.perf_counter() - attempt_start) * 1000.0
                req_id = response.headers.get("x-request-id") or response.headers.get("request-id")

                if response.status_code in {401, 403}:
                    return NormalizedDecisionResult(
                        provider=self.provider_name,
                        model_id=self.settings.model_id,
                        latency_ms=round(latency_ms, 2),
                        request_id=req_id,
                        provider_error=f"Provider authentication failed (HTTP {response.status_code}). Check MODEL_API_KEY.",
                        is_valid_schema=False,
                    )

                if response.status_code == 429:
                    return NormalizedDecisionResult(
                        provider=self.provider_name,
                        model_id=self.settings.model_id,
                        latency_ms=round(latency_ms, 2),
                        request_id=req_id,
                        provider_error="Provider rate limit or quota exceeded (HTTP 429).",
                        is_valid_schema=False,
                    )

                if response.status_code >= 500 and attempt < max_attempts:
                    last_error = f"Provider server error (HTTP {response.status_code}) on attempt {attempt}."
                    continue

                if response.status_code != 200:
                    return NormalizedDecisionResult(
                        provider=self.provider_name,
                        model_id=self.settings.model_id,
                        latency_ms=round(latency_ms, 2),
                        request_id=req_id,
                        provider_error=f"Provider returned HTTP {response.status_code}.",
                        is_valid_schema=False,
                    )

                try:
                    data = response.json()
                except Exception:
                    return NormalizedDecisionResult(
                        provider=self.provider_name,
                        model_id=self.settings.model_id,
                        latency_ms=round(latency_ms, 2),
                        request_id=req_id,
                        provider_error="Provider returned invalid JSON.",
                        is_valid_schema=False,
                    )

                return normalize_systemone_response(
                    provider_name=self.provider_name,
                    default_model_id=self.settings.model_id,
                    payload=data,
                    latency_ms=latency_ms,
                    request_id=req_id,
                )

            except httpx.TimeoutException:
                last_error = f"Provider request timed out after {self.settings.model_timeout_seconds}s."
                if attempt < max_attempts:
                    continue
            except httpx.TransportError as exc:
                last_error = f"Transport error communicating with provider: {exc.__class__.__name__}."
                if attempt < max_attempts:
                    continue
            except Exception as exc:
                last_error = f"Unexpected provider error: {exc.__class__.__name__}."
                break

        total_latency = (time.perf_counter() - start_ts) * 1000.0
        return NormalizedDecisionResult(
            provider=self.provider_name,
            model_id=self.settings.model_id,
            latency_ms=round(total_latency, 2),
            provider_error=last_error or "Unknown provider evaluation failure.",
            is_valid_schema=False,
        )
