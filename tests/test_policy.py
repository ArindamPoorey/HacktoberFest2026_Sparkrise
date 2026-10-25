"""Unit tests for deterministic policy rules, threshold comparisons, and secret redaction (Section 16)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.config import FenceSettings
from app.context import build_operation_request, pack_context, redact_secrets
from app.policy import evaluate_policy, run_local_precheck
from app.schemas import (
    ActionClass,
    DecisionScores,
    FinalDecision,
    NormalizedDecisionResult,
)


class TestPolicyAndRedaction(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory(prefix="fence_test_policy_")
        self.workspace = str(Path(self.tmp_dir.name).resolve())
        self.settings = FenceSettings(
            model_provider="mock",
            allow_threshold=0.90,
            recheck_threshold=0.90,
            risk_ceiling=0.15,
            max_rechecks=1,
            allowed_workspace_root=self.workspace,
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _make_model_result(
        self,
        action_class: ActionClass = ActionClass.READ_ONLY,
        confidence: float = 0.95,
        intent_score: float = 0.95,
        scope_score: float = 0.99,
        damage_risk: float = 0.02,
        needs_review: float = 0.02,
    ) -> NormalizedDecisionResult:
        return NormalizedDecisionResult(
            provider="mock",
            model_id="mock-v1",
            action_class=action_class,
            confidence=confidence,
            scores=DecisionScores(
                matches_user_intent=intent_score,
                target_in_scope=scope_score,
                unintended_damage_risk=damage_risk,
                needs_human_review=needs_review,
            ),
        )

    def test_threshold_below_equal_and_above(self) -> None:
        """Section 16: Threshold comparisons at below (0.89), equal to (0.90), and above (0.95) threshold."""
        op = build_operation_request(
            command="Get-ChildItem .",
            working_directory=self.workspace,
            user_intent="List files in workspace",
        )
        precheck = run_local_precheck(op, self.settings)
        self.assertTrue(precheck.passed)

        # 1. Below threshold (0.89 < 0.90) -> RECHECK on first pass, BLOCK on recheck pass
        res_below = self._make_model_result(confidence=0.89)
        dec1, code1, _ = evaluate_policy(op, precheck, res_below, self.settings, is_recheck=False)
        self.assertEqual(dec1, FinalDecision.RECHECK)
        self.assertEqual(code1, "LOW_CONFIDENCE_OR_AMBIGUOUS_RECHECK")

        dec1_recheck, code1_recheck, _ = evaluate_policy(op, precheck, res_below, self.settings, is_recheck=True)
        self.assertEqual(dec1_recheck, FinalDecision.BLOCK)
        self.assertEqual(code1_recheck, "BLOCKED_BELOW_THRESHOLD_OR_UNRESOLVED")

        # 2. Equal to threshold (0.90 == 0.90) -> ALLOW
        res_equal = self._make_model_result(confidence=0.90, intent_score=0.90)
        dec2, code2, _ = evaluate_policy(op, precheck, res_equal, self.settings, is_recheck=False)
        self.assertEqual(dec2, FinalDecision.ALLOW)
        self.assertEqual(code2, "HIGH_CONFIDENCE_IN_SCOPE")

        # 3. Above threshold (0.96 > 0.90) -> ALLOW
        res_above = self._make_model_result(confidence=0.96, intent_score=0.97)
        dec3, _, _ = evaluate_policy(op, precheck, res_above, self.settings, is_recheck=False)
        self.assertEqual(dec3, FinalDecision.ALLOW)

    def test_protected_paths_and_mandatory_deny_cannot_be_overridden_by_high_model_confidence(self) -> None:
        """FR-05 & Section 8: High model confidence (0.99) cannot override mandatory local deny rules."""
        # Protected path (.env)
        op_env = build_operation_request(
            command="Get-Content .\\.env",
            working_directory=self.workspace,
            user_intent="Read environment configuration",
        )
        pre_env = run_local_precheck(op_env, self.settings)
        self.assertFalse(pre_env.passed)
        self.assertTrue(pre_env.mandatory_block)
        self.assertEqual(pre_env.reason_code, "MANDATORY_DENY_PROTECTED_PATH")

        high_conf_allow = self._make_model_result(confidence=0.99, intent_score=0.99)
        dec, code, _ = evaluate_policy(op_env, pre_env, high_conf_allow, self.settings)
        self.assertEqual(dec, FinalDecision.BLOCK)
        self.assertEqual(code, "MANDATORY_DENY_PROTECTED_PATH")

        # High-impact pattern (Format-Volume / Recursive wildcard delete)
        op_fmt = build_operation_request(
            command="Format-Volume -DriveLetter C -FileSystem NTFS",
            working_directory=self.workspace,
            user_intent="Format disk",
        )
        pre_fmt = run_local_precheck(op_fmt, self.settings)
        self.assertFalse(pre_fmt.passed)
        self.assertEqual(pre_fmt.reason_code, "MANDATORY_DENY_HIGH_IMPACT_PATTERN")

        # Out-of-scope target escaping workspace (../outside.txt)
        op_escape = build_operation_request(
            command="Get-Content ..\\outside_secret.txt",
            working_directory=self.workspace,
            user_intent="Read parent directory file",
        )
        pre_escape = run_local_precheck(op_escape, self.settings)
        self.assertFalse(pre_escape.passed)
        self.assertEqual(pre_escape.reason_code, "MANDATORY_DENY_OUT_OF_SCOPE_TARGET")

    def test_secret_redaction_in_context_and_commands(self) -> None:
        """Section 15 & 16: Verify API keys, bearer tokens, and passwords are redacted before packing."""
        self.settings.model_api_key = "ts_live_super_secret_987654321"
        raw_cmd = (
            'Invoke-RestMethod -Headers @{Authorization="Bearer eyJhbGciOiJIUzI1NiJ9.secret"} '
            '-Token ghp_1234567890abcdefghijklmnopqrstuvwx '
            'api_key=sk-proj1234567890abcdefghij ts_live_super_secret_987654321'
        )
        redacted = redact_secrets(raw_cmd, extra_secrets=[self.settings.model_api_key])
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9.secret", redacted)
        self.assertNotIn("ghp_1234567890abcdefghijklmnopqrstuvwx", redacted)
        self.assertNotIn("sk-proj1234567890abcdefghij", redacted)
        self.assertNotIn("ts_live_super_secret_987654321", redacted)
        self.assertIn("[REDACTED", redacted)

        op = build_operation_request(
            command=raw_cmd,
            working_directory=self.workspace,
            user_intent="Test with password=my_secret_pw_123",
        )
        packed = pack_context(op, self.settings)
        self.assertNotIn("my_secret_pw_123", packed.redacted_user_intent or "")
        self.assertNotIn("ts_live_super_secret_987654321", packed.redacted_command)


if __name__ == "__main__":
    unittest.main()
