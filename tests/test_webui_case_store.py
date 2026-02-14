#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from webui.case_store import CaseStore


class CaseStoreTests(unittest.TestCase):
    def test_case_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "cases.db"
            store = CaseStore(db_path)

            case_id = "case_test_1"
            store.create_case(case_id=case_id, filename="sample.eml", eml_path="/tmp/sample.eml", run_mode="mock")
            with self.assertRaises(ValueError):
                store.set_analyst_decision(case_id, "invalid_choice")
            store.set_subject_line(case_id, "Suspicious payroll change")
            store.set_analyst_decision(case_id, "suspicious", "Needs secondary review")
            store.mark_running(case_id)
            store.update_stage_state(case_id, stage="normalize_envelope", state="running", message="normalizing")
            store.update_stage_state(case_id, stage="normalize_envelope", state="done", message="done")

            result_doc = {
                "stop_reason": "confidence_gate_satisfied",
                "final_score": {
                    "verdict": "phish",
                    "risk_score": 88,
                    "confidence_score": 0.92,
                },
            }
            web_report_doc = {
                "schema_version": "1.0",
                "classification": "malicious",
                "key_points": ["a", "b", "c"],
            }
            store.mark_complete(
                case_id=case_id,
                artifacts_dir="/tmp/artifacts",
                result_doc=result_doc,
                web_report_doc=web_report_doc,
            )

            summary = store.list_cases(limit=10)
            self.assertEqual(len(summary), 1)
            self.assertEqual(summary[0]["status"], "complete")
            self.assertEqual(summary[0]["subject_line"], "Suspicious payroll change")
            self.assertEqual(summary[0]["analyst_decision"], "suspicious")

            case = store.get_case(case_id)
            self.assertIsNotNone(case)
            assert case is not None
            self.assertEqual(case["verdict"], "phish")
            self.assertEqual(case["web_report"]["classification"], "malicious")
            self.assertEqual(case["subject_line"], "Suspicious payroll change")
            self.assertEqual(case["analyst_decision"], "suspicious")
            self.assertEqual(case["analyst_note"], "Needs secondary review")
            self.assertEqual(case["runtime"]["stages"][0]["state"], "done")


if __name__ == "__main__":
    unittest.main()
