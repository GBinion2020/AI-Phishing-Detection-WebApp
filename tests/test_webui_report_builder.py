#!/usr/bin/env python3

from __future__ import annotations

import unittest

from webui.report_builder import build_web_report


class _LLMDisabled:
    enabled = False


class WebReportBuilderTests(unittest.TestCase):
    def test_fallback_report_structure(self) -> None:
        envelope = {
            "case_id": "case_123",
            "message_metadata": {
                "subject": "Urgent account verification",
                "from": {"address": "attacker@example.com"},
            },
            "mime_parts": {
                "body_extraction": {
                    "text_plain": "Please verify your account immediately.",
                    "text_html": "<p>Please verify your account immediately.</p>",
                }
            },
            "entities": {
                "urls": [{"normalized": "https://phish.example/login"}],
                "domains": [{"domain": "phish.example"}],
                "ips": [{"ip": "185.1.2.3"}],
            },
            "attachments": [],
        }
        result = {
            "case_id": "case_123",
            "final_score": {
                "verdict": "phish",
                "risk_score": 92,
                "confidence_score": 0.95,
                "reasons": [{"signal_id": "auth.dmarc_fail"}],
            },
            "final_report": {
                "executive_summary": "Likely phishing email.",
                "key_indicators": ["DMARC fail", "Urgent credential lure", "Suspicious URL"],
            },
        }

        report = build_web_report(envelope=envelope, result=result, llm=_LLMDisabled())

        self.assertEqual(report["schema_version"], "1.0")
        self.assertIn(report["classification"], {"malicious", "suspicious", "non_malicious"})
        self.assertEqual(len(report["key_points"]), 3)
        self.assertGreaterEqual(len(report["ioc_items"]), 1)
        self.assertIn("subject_line", report)
        self.assertIn("sender_address", report)
        self.assertIn("sender_domain", report)
        self.assertIn("analysis_details", report)
        self.assertIn("indicator_panels", report)
        self.assertEqual(len(report["indicator_panels"]), 4)
        url_panel = next((x for x in report["indicator_panels"] if x.get("id") == "urls"), {})
        url_items = url_panel.get("items", [])
        self.assertGreaterEqual(len(url_items), 1)
        self.assertIn("phish.example", str(url_items[0].get("display_value")))
        attachments_panel = next((x for x in report["indicator_panels"] if x.get("id") == "attachments"), {})
        self.assertEqual(attachments_panel.get("level"), "neutral")
        self.assertEqual(attachments_panel.get("title"), "No attachments found")
        self.assertIn("subject_level", report)
        self.assertIn("body_level", report)

    def test_semantic_true_overrides_clean_ioc_outcomes(self) -> None:
        envelope = {
            "case_id": "case_456",
            "message_metadata": {
                "subject": "Vendor verification update",
                "from": {"address": "billing@updates.example.com", "domain": "updates.example.com"},
            },
            "mime_parts": {
                "body_extraction": {
                    "text_plain": "Urgent action required. Verify account and login now.",
                }
            },
            "entities": {
                "domains": [{"domain": "updates.example.com"}],
                "urls": [{"normalized": "https://updates.example.com/login"}],
                "ips": [{"ip": "185.1.2.3"}],
            },
            "attachments": [],
        }
        result = {
            "case_id": "case_456",
            "final_score": {"verdict": "suspicious", "risk_score": 70, "confidence_score": 0.84},
            "final_signals": {
                "signals": {
                    "semantic.social_engineering_intent": {
                        "kind": "non_deterministic",
                        "value": "true",
                        "rationale": "Persuasion and urgency language indicate social-engineering risk.",
                        "evidence": ["body.text_plain_excerpt"],
                    }
                }
            },
        }

        report = build_web_report(envelope=envelope, result=result, llm=_LLMDisabled())
        domain_panel = next((x for x in report["indicator_panels"] if x.get("id") == "domains"), {})
        domain_items = domain_panel.get("items", [])
        self.assertGreaterEqual(len(domain_items), 1)
        self.assertEqual(domain_items[0].get("outcome"), "could_be_malicious")
        self.assertGreaterEqual(len(report.get("analysis_details") or []), 1)


if __name__ == "__main__":
    unittest.main()
