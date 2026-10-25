"""Deterministic MockProvider for unit tests, integration tests, and offline demos (FR-03, FR-11, Section 16)."""

from __future__ import annotations

import re
from typing import Optional

from app.config import FenceSettings
from app.providers.base import DecisionProvider
from app.schemas import (
    ActionClass,
    DecisionRequest,
    DecisionScores,
    NormalizedDecisionResult,
)


class MockProvider(DecisionProvider):
    """
    Deterministic System 1 decision provider for local testing and hackathon demos without API keys.
    Supports both realistic heuristic evaluation of PowerShell commands and explicit scenario overrides.
    """

    def __init__(
        self,
        settings: FenceSettings,
        scenario_override: Optional[str] = None,
    ) -> None:
        super().__init__(settings)
        self.scenario_override = scenario_override
        self.call_count: int = 0

    @property
    def provider_name(self) -> str:
        return "mock"

    def evaluate(self, request: DecisionRequest) -> NormalizedDecisionResult:
        self.call_count += 1
        ctx = request.packed_context
        cmd = ctx.redacted_command.strip()
        cmd_low = cmd.lower()
        intent = (ctx.redacted_user_intent or "").strip().lower()
        has_intent = ctx.intent_explicitly_supplied and len(intent) >= 3
        in_scope = ctx.targets_within_workspace

        # Check explicit scenario overrides for testing edge cases
        override = self.scenario_override
        if override == "timeout":
            return NormalizedDecisionResult(
                provider="mock",
                model_id="mock-systemone-v1",
                latency_ms=5000.0,
                provider_error="Provider request timed out after 5.0s.",
                is_valid_schema=False,
            )
        if override == "malformed":
            return NormalizedDecisionResult(
                provider="mock",
                model_id="mock-systemone-v1",
                latency_ms=12.0,
                provider_error="Incomplete model response: missing required fields [confidence].",
                is_valid_schema=False,
            )
        if override == "auth_error":
            return NormalizedDecisionResult(
                provider="mock",
                model_id="mock-systemone-v1",
                latency_ms=15.0,
                provider_error="Provider authentication failed (HTTP 401). Check MODEL_API_KEY.",
                is_valid_schema=False,
            )
        if override == "uncertain_then_allow":
            if not request.is_recheck:
                return NormalizedDecisionResult(
                    provider="mock",
                    model_id="mock-systemone-v1",
                    model_version="2026.10-mock",
                    action_class=ActionClass.READ_ONLY,
                    action_class_probabilities={"read_only": 0.78, "routine_mutation": 0.22},
                    confidence=0.78,
                    confidence_source_field="answers.action_class.confidence",
                    scores=DecisionScores(
                        matches_user_intent=0.82,
                        target_in_scope=0.95,
                        unintended_damage_risk=0.05,
                        needs_human_review=0.35,
                    ),
                    latency_ms=42.0,
                    request_id=f"mock-req-{self.call_count}",
                    usage={"input_tokens": 110, "output_tokens": 0},
                )
            else:
                return NormalizedDecisionResult(
                    provider="mock",
                    model_id="mock-systemone-v1",
                    model_version="2026.10-mock",
                    action_class=ActionClass.READ_ONLY,
                    action_class_probabilities={"read_only": 0.96, "routine_mutation": 0.04},
                    confidence=0.96,
                    confidence_source_field="answers.action_class.confidence",
                    scores=DecisionScores(
                        matches_user_intent=0.95,
                        target_in_scope=0.98,
                        unintended_damage_risk=0.02,
                        needs_human_review=0.04,
                    ),
                    latency_ms=38.0,
                    request_id=f"mock-req-{self.call_count}",
                    usage={"input_tokens": 145, "output_tokens": 0},
                )
        if override == "always_uncertain":
            return NormalizedDecisionResult(
                provider="mock",
                model_id="mock-systemone-v1",
                model_version="2026.10-mock",
                action_class=ActionClass.UNCLEAR,
                action_class_probabilities={"unclear": 0.62, "routine_mutation": 0.38},
                confidence=0.62,
                confidence_source_field="answers.action_class.confidence",
                scores=DecisionScores(
                    matches_user_intent=0.55,
                    target_in_scope=0.80,
                    unintended_damage_risk=0.25,
                    needs_human_review=0.75,
                ),
                latency_ms=45.0,
                request_id=f"mock-req-{self.call_count}",
                usage={"input_tokens": 115, "output_tokens": 0},
            )
        if override == "always_block":
            return NormalizedDecisionResult(
                provider="mock",
                model_id="mock-systemone-v1",
                model_version="2026.10-mock",
                action_class=ActionClass.DESTRUCTIVE_MUTATION,
                action_class_probabilities={"destructive_mutation": 0.97, "routine_mutation": 0.03},
                confidence=0.97,
                confidence_source_field="answers.action_class.confidence",
                scores=DecisionScores(
                    matches_user_intent=0.20,
                    target_in_scope=0.40,
                    unintended_damage_risk=0.92,
                    needs_human_review=0.98,
                ),
                latency_ms=39.0,
                request_id=f"mock-req-{self.call_count}",
                usage={"input_tokens": 120, "output_tokens": 0},
            )

        # Heuristic System 1 classification for realistic behavior
        read_only_pattern = re.compile(
            r"^\s*(get-childitem|dir|ls|get-content|cat|type|get-location|pwd|write-output|echo|test-path|select-string|get-item|get-process|get-service|git\s+(status|log|diff|branch)|pytest\s+--collect-only)\b",
            re.IGNORECASE,
        )
        routine_mutation_pattern = re.compile(
            r"^\s*(new-item|mkdir|md|set-content|add-content|out-file|copy-item|cp|copy|move-item|mv|rename-item|git\s+(add|commit|checkout\s+-b)|pytest)\b",
            re.IGNORECASE,
        )
        destructive_pattern = re.compile(
            r"\b(remove-item|rm|del|erase|rmdir|rd|clear-content|format-volume|clear-disk|reset\s+--hard|clean\s+-fd)\b",
            re.IGNORECASE,
        )
        security_pattern = re.compile(
            r"\b(set-executionpolicy|set-mppreference|icacls|takeown|reg\s+add|reg\s+delete|net\s+user| net\s+localgroup|invoke-expression|iex|downloadstring|start-process.*runas)\b",
            re.IGNORECASE,
        )

        # Determine action_class
        if security_pattern.search(cmd_low):
            action_class = ActionClass.SECURITY_SENSITIVE
            conf = 0.97
            damage_risk = 0.88
            needs_review = 0.96
            intent_score = 0.30 if has_intent else 0.05
        elif destructive_pattern.search(cmd_low):
            action_class = ActionClass.DESTRUCTIVE_MUTATION
            conf = 0.95
            # Check if intent explicitly asks to delete or remove the exact file
            explicitly_asks_delete = any(
                w in intent for w in ("delete", "remove", "clean", "erase", "drop")
            )
            if explicitly_asks_delete and in_scope and "-recurse" not in cmd_low and "*" not in cmd_low:
                intent_score = 0.93
                damage_risk = 0.12
                needs_review = 0.20
            else:
                intent_score = 0.18
                damage_risk = 0.89
                needs_review = 0.95
        elif routine_mutation_pattern.search(cmd_low):
            action_class = ActionClass.ROUTINE_MUTATION
            if has_intent:
                conf = 0.95
                intent_score = 0.94
                damage_risk = 0.04
                needs_review = 0.06
            elif request.is_recheck and ctx.additional_recheck_evidence:
                # Still no explicit user intent for a mutation -> remain cautious
                conf = 0.84
                intent_score = 0.45
                damage_risk = 0.18
                needs_review = 0.65
            else:
                conf = 0.81
                intent_score = 0.40
                damage_risk = 0.15
                needs_review = 0.60
        elif read_only_pattern.search(cmd_low):
            action_class = ActionClass.READ_ONLY
            if has_intent:
                conf = 0.98
                intent_score = 0.98
                damage_risk = 0.01
                needs_review = 0.02
            elif request.is_recheck and ctx.additional_recheck_evidence:
                # On recheck with verified deterministic read-only evidence in workspace
                conf = 0.94
                intent_score = 0.91
                damage_risk = 0.02
                needs_review = 0.08
            else:
                # Missing user intent on first check triggers a single recheck
                conf = 0.85
                intent_score = 0.72
                damage_risk = 0.03
                needs_review = 0.30
        else:
            action_class = ActionClass.UNCLEAR
            conf = 0.65
            intent_score = 0.50 if has_intent else 0.25
            damage_risk = 0.35
            needs_review = 0.80

        scope_score = 0.99 if in_scope else 0.08

        return NormalizedDecisionResult(
            provider="mock",
            model_id="mock-systemone-v1",
            model_version="2026.10-mock",
            action_class=action_class,
            action_class_probabilities={action_class.value: conf},
            confidence=conf,
            confidence_source_field="answers.action_class.confidence",
            scores=DecisionScores(
                matches_user_intent=intent_score,
                target_in_scope=scope_score,
                unintended_damage_risk=damage_risk,
                needs_human_review=needs_review,
            ),
            latency_ms=34.5,
            request_id=f"mock-req-{self.call_count}",
            usage={"input_tokens": 128, "output_tokens": 0},
        )
