"""외부 API·호스트 방화벽 변경 없이 판정·복구 실패 경로를 검증한다."""
import importlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

analysis = importlib.import_module("labs.adaptive.analyze_unknown")
blocking = importlib.import_module("labs.adaptive.safe_block")
training = importlib.import_module("labs.adaptive.incremental_train")


class AdaptiveSafetyTests(unittest.TestCase):
    def test_schema_failure_never_becomes_benign(self):
        for invalid in ([], None, {}, {"category": "BENIGN", "severity": True}):
            with self.subTest(invalid=invalid), patch.object(analysis, "_USE_MOCK", True), \
                    patch.object(analysis, "_mock_analyze", return_value=invalid):
                verdict = analysis.analyze_unknown({"payload": "example"})
                self.assertEqual(verdict["category"], "UNKNOWN")
                self.assertEqual(analysis.gate_hitl(verdict), "human_approval")

    def test_evidence_guard_does_not_bypass_review(self):
        verdict = {"category": "RCE", "severity": 5, "confidence": .95,
                   "citation": [], "reasoning": "검증 필요"}
        guarded = analysis.enforce_citation(verdict)
        self.assertEqual(guarded["severity"], 5)
        self.assertEqual(analysis.gate_hitl(guarded), "human_approval")
        self.assertNotIn("requires_review", verdict)

    def test_unknown_rule_match_requires_review(self):
        with patch.object(analysis, "_USE_MOCK", True):
            verdict = analysis.analyze_unknown({"payload": "unrecognized"})
        self.assertEqual(verdict["category"], "UNKNOWN")
        self.assertEqual(analysis.gate_hitl(verdict), "human_approval")

    def test_unconfirmed_labels_cannot_train(self):
        with self.assertRaises(ValueError):
            training.incremental_retrain("unused.pkl", [{"label": {"category": "UNKNOWN"}}])

    def test_fabricated_citation_cannot_authorize_action(self):
        verdict = {"category": "RCE", "severity": 5, "confidence": .99,
                   "attack_id": "T1190", "citation": ["invented"], "reasoning": "example"}
        with patch.object(analysis, "_USE_MOCK", True), \
                patch.object(analysis, "_mock_analyze", return_value=verdict):
            result = analysis.analyze_unknown({"payload": "test"})
        self.assertEqual(result["citation"], [])
        self.assertEqual(analysis.gate_hitl(result), "human_approval")

    def test_schedule_failure_rolls_back(self):
        for error in (FileNotFoundError("at"), subprocess.CalledProcessError(1, "at")):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as tmp, \
                    patch.object(blocking, "ROLLBACK_LOG", Path(tmp) / "rollback.jsonl"), \
                    patch.object(blocking, "_DRY_RUN", False), \
                    patch.object(blocking.subprocess, "run", side_effect=[None, error, None]) as run:
                with self.assertRaises(type(error)):
                    blocking.safe_block("203.0.113.9", "test")
                self.assertEqual(run.call_args_list[2].args[0][1], "-D")
                self.assertTrue(run.call_args_list[1].kwargs["check"])

    def test_dry_run_never_runs_firewall(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(blocking, "ROLLBACK_LOG", Path(tmp) / "rollback.jsonl"), \
                patch.object(blocking, "_DRY_RUN", True), \
                patch.object(blocking.subprocess, "run") as run:
            blocking.safe_block("203.0.113.9", "test")
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
