"""Unit tests for provider response normalization, missing-confidence handling, and HTTP adapters (Section 16)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
import httpx

from app.config import FenceSettings
from app.context import build_operation_request, pack_context
from app.providers.base import normalize_systemone_response
from app.providers.jev import JevProvider
from app.providers.laya import LayaProvider
from app.providers.custom import CustomProvider
from app.schemas import ActionClass, DecisionRequest


class TestProviderNormalization(unittest.TestCase):
    def setUp(self) -> None:
        fixture_path = Path(__file__).parent / "fixtures" / "sample_responses.json"
        self.fixtures = json.loads(fixture_path.read_text(encoding="utf-8"))
        self.settings = FenceSettings(
            model_provider="jev",
            model_base_url="https://api.typesafe.ai",
            model_endpoint="/v1/systemone",
            model_id="jev-latest",
            model_api_key="ts_test_dummy_key_12345",
            allowed_workspace_root=str(Path(__file__).parent.resolve()),
        )

    def test_normalize_valid_jev_response(self) -> None:
        payload = self.fixtures["jev_read_only_allow"]
        res = normalize_systemone_response(
            provider_name="jev",
            default_model_id="jev-latest",
            payload=payload,
            latency_ms=215.4,
            request_id="req_abc123",
        )
        self.assertTrue(res.is_valid_schema)
        self.assertIsNone(res.provider_error)
        self.assertEqual(res.provider, "jev")
        self.assertEqual(res.action_class, ActionClass.READ_ONLY)
        self.assertAlmostEqual(res.confidence or 0.0, 0.97)
        self.assertEqual(res.confidence_source_field, "answers.action_class.confidence")
        self.assertAlmostEqual(res.scores.matches_user_intent or 0.0, 0.98)
        self.assertAlmostEqual(res.scores.target_in_scope or 0.0, 0.99)
        self.assertAlmostEqual(res.scores.unintended_damage_risk or 0.0, 0.02)
        self.assertEqual(res.request_id, "req_abc123")

    def test_normalize_valid_laya_response_with_routing(self) -> None:
        payload = self.fixtures["laya_destructive_block"]
        res = normalize_systemone_response(
            provider_name="laya",
            default_model_id="typed-decisions",
            payload=payload,
            latency_ms=41.2,
        )
        self.assertTrue(res.is_valid_schema)
        self.assertEqual(res.action_class, ActionClass.DESTRUCTIVE_MUTATION)
        self.assertEqual(res.model_version, "laya-en-v1")
        self.assertAlmostEqual(res.confidence or 0.0, 0.96)
        self.assertAlmostEqual(res.scores.unintended_damage_risk or 0.0, 0.91)

    def test_missing_confidence_is_not_fabricated(self) -> None:
        """FR-06 & Section 12: Missing confidence must be marked unavailable (None) and never fabricated."""
        payload = {
            "model": "jev-latest",
            "answers": {
                "action_class": {
                    "type": "choice",
                    "choice": "read_only",
                    # Neither 'confidence' nor 'probabilities' provided
                },
                "matches_user_intent": {"type": "noul", "noul": 0.95},
                "target_in_scope": {"type": "noul", "noul": 0.99},
                "unintended_damage_risk": {"type": "noul", "noul": 0.01},
            },
        }
        res = normalize_systemone_response(
            provider_name="jev",
            default_model_id="jev-latest",
            payload=payload,
            latency_ms=100.0,
        )
        self.assertIsNone(res.confidence)
        self.assertEqual(res.confidence_source_field, "unavailable")
        self.assertFalse(res.is_valid_schema)
        self.assertIn("confidence", res.provider_error or "")

    def test_fallback_confidence_from_choice_probabilities(self) -> None:
        payload = {
            "model": "jev-latest",
            "answers": {
                "action_class": {
                    "type": "choice",
                    "choice": "routine_mutation",
                    "probabilities": {"routine_mutation": 0.93, "read_only": 0.07},
                },
                "matches_user_intent": {"type": "noul", "noul": 0.94},
                "target_in_scope": {"type": "noul", "noul": 0.98},
                "unintended_damage_risk": {"type": "noul", "noul": 0.04},
            },
        }
        res = normalize_systemone_response(
            provider_name="jev",
            default_model_id="jev-latest",
            payload=payload,
            latency_ms=88.0,
        )
        self.assertTrue(res.is_valid_schema)
        self.assertAlmostEqual(res.confidence or 0.0, 0.93)
        self.assertEqual(
            res.confidence_source_field,
            "answers.action_class.probabilities.routine_mutation",
        )

    def test_jev_laya_custom_adapters_via_mock_transport(self) -> None:
        fixture_payload = self.fixtures["jev_read_only_allow"]

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/v1/systemone")
            self.assertTrue(request.headers.get("Authorization", "").startswith("Bearer "))
            body = json.loads(request.content.decode("utf-8"))
            self.assertIn("state", body)
            self.assertIn("questions", body)
            return httpx.Response(200, json=fixture_payload, headers={"x-request-id": "srv_999"})

        transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=transport)

        op = build_operation_request(
            command="Get-ChildItem .",
            working_directory=str(Path(__file__).parent.resolve()),
            user_intent="Inspect test files",
        )
        packed = pack_context(op, self.settings)
        dreq = DecisionRequest(operation_id=op.operation_id, packed_context=packed)

        for adapter_cls, expected_name in [
            (JevProvider, "jev"),
            (LayaProvider, "laya"),
            (CustomProvider, "custom"),
        ]:
            provider = adapter_cls(self.settings, http_client=client)
            result = provider.evaluate(dreq)
            self.assertEqual(result.provider, expected_name)
            self.assertTrue(result.is_valid_schema)
            self.assertEqual(result.action_class, ActionClass.READ_ONLY)
            self.assertEqual(result.request_id, "srv_999")


if __name__ == "__main__":
    unittest.main()
