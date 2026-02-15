#!/usr/bin/env python3

from __future__ import annotations

import unittest

from webui.report_builder import build_web_report


class _LLMDisabled:
    enabled = False


class _LLMStub:
    enabled = True

    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def call_json(self, **_kwargs):
        return self._payload


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
        self.assertIn("primary_threat_tag", report)
        self.assertIn("threat_tags", report)
        self.assertGreaterEqual(len(report.get("threat_tags") or []), 1)
        self.assertEqual(len(report.get("threat_tags") or []), 1)

    def test_non_sender_semantic_signal_does_not_force_sender_domain_suspicious(self) -> None:
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
        self.assertEqual(domain_items[0].get("outcome"), "not_malicious")
        self.assertGreaterEqual(len(report.get("analysis_details") or []), 1)

    def test_suspicious_snippets_require_actual_suspicious_language(self) -> None:
        envelope = {
            "case_id": "case_789",
            "message_metadata": {
                "subject": "Career opportunities",
                "from": {"address": "alerts@example.com", "domain": "example.com"},
            },
            "mime_parts": {
                "body_extraction": {
                    "text_plain": "Hi there Gabriel,\nWe found new roles you may like.\nUnsubscribe any time.",
                    "text_html": "<p>Hi there Gabriel</p>",
                }
            },
            "entities": {"urls": [], "domains": [{"domain": "example.com"}], "ips": []},
            "attachments": [],
            "auth_summary": {
                "spf": {"result": "pass"},
                "dmarc": {"result": "pass", "aligned": True},
                "dkim": [{"result": "pass"}],
            },
        }
        result = {"case_id": "case_789", "final_score": {"verdict": "suspicious", "risk_score": 24, "confidence_score": 0.75}}

        report = build_web_report(envelope=envelope, result=result, llm=_LLMDisabled())
        self.assertEqual(report.get("analysis_snippets"), [])

    def test_domain_panel_level_matches_domain_item_outcomes(self) -> None:
        envelope = {
            "case_id": "case_321",
            "message_metadata": {
                "subject": "Monthly newsletter",
                "from": {"address": "news@example.com", "domain": "example.com"},
            },
            "mime_parts": {
                "body_extraction": {
                    "text_plain": "Newsletter update. Unsubscribe any time.",
                }
            },
            "entities": {"urls": [], "domains": [{"domain": "example.com"}], "ips": []},
            "attachments": [],
        }
        result = {
            "case_id": "case_321",
            "final_score": {"verdict": "benign", "risk_score": 5, "confidence_score": 0.92},
            "final_signals": {
                "signals": {
                    "identity.lookalike_domain_confirmed": {
                        "kind": "deterministic",
                        "value": "true",
                        "rationale": "Legacy signal present",
                        "evidence": ["entities.domains"],
                    }
                }
            },
        }

        report = build_web_report(envelope=envelope, result=result, llm=_LLMDisabled())
        domain_panel = next((x for x in report["indicator_panels"] if x.get("id") == "domains"), {})
        self.assertEqual(domain_panel.get("level"), "green")
        self.assertEqual(domain_panel.get("title"), "Domains look benign")

    def test_benign_summary_stays_classification_aligned_and_plain(self) -> None:
        envelope = {
            "case_id": "case_777",
            "message_metadata": {
                "subject": "Apply for network engineer roles",
                "from": {"address": "jobs@alerts.example.com", "domain": "alerts.example.com"},
                "headers": {"list-unsubscribe": "<mailto:unsubscribe@example.com>"},
            },
            "mime_parts": {
                "body_extraction": {
                    "text_plain": "Hi there,\nNew roles are available.\nUnsubscribe any time.",
                }
            },
            "entities": {
                "urls": [{"normalized": "https://u111.ct.sendgrid.net/ls/click?upn=abc", "domain": "u111.ct.sendgrid.net"}],
                "domains": [{"domain": "alerts.example.com"}, {"domain": "u111.ct.sendgrid.net"}],
                "ips": [],
            },
            "attachments": [],
            "auth_summary": {
                "spf": {"result": "pass"},
                "dmarc": {"result": "pass", "aligned": True},
                "dkim": [{"result": "pass"}],
            },
        }
        result = {
            "case_id": "case_777",
            "final_score": {
                "verdict": "benign",
                "risk_score": 16,
                "confidence_score": 0.86,
                "primary_threat_tag": "spam_marketing",
                "threat_tags": [
                    {"id": "spam_marketing", "label": "Spam / Marketing", "severity": "low", "confidence": "high", "reasons": []},
                    {"id": "url_obfuscation_redirect", "label": "URL Obfuscation / Redirect", "severity": "medium", "confidence": "medium", "reasons": []},
                ],
            },
            "final_signals": {"signals": {}},
        }

        report = build_web_report(envelope=envelope, result=result, llm=_LLMDisabled())
        summary = str(report.get("analyst_summary") or "").lower()
        self.assertIn("benign", summary)
        self.assertNotIn("treat with caution", summary)
        self.assertNotIn("esp", summary)
        self.assertNotIn("cta", summary)
        self.assertEqual(len(report.get("threat_tags") or []), 1)
        self.assertEqual(str((report.get("threat_tags") or [{}])[0].get("id")), "spam_marketing")

    def test_marketing_key_points_drop_tracking_obfuscation_and_dedupe_urgency(self) -> None:
        envelope = {
            "case_id": "case_654",
            "message_metadata": {
                "subject": "Time is running out for your Toyota offer",
                "from": {"address": "updates@dealer.example.com", "domain": "dealer.example.com"},
                "headers": {"list-unsubscribe": "<mailto:unsubscribe@example.com>"},
            },
            "mime_parts": {
                "body_extraction": {
                    "text_plain": "Hi Gabriel,\nTime is running out. View latest offers.\nUnsubscribe anytime.",
                }
            },
            "entities": {
                "urls": [{"normalized": "https://u999.ct.sendgrid.net/ls/click?upn=abc", "domain": "u999.ct.sendgrid.net"}],
                "domains": [{"domain": "dealer.example.com"}, {"domain": "u999.ct.sendgrid.net"}],
                "ips": [],
            },
            "attachments": [],
            "auth_summary": {
                "spf": {"result": "pass"},
                "dmarc": {"result": "pass", "aligned": True},
                "dkim": [{"result": "pass"}],
            },
        }
        result = {
            "case_id": "case_654",
            "final_score": {"verdict": "suspicious", "risk_score": 24, "confidence_score": 0.75},
            "final_signals": {
                "signals": {
                    "semantic.coercive_language": {
                        "kind": "non_deterministic",
                        "value": "true",
                        "rationale": "Subject uses urgency/pressure language.",
                        "evidence": ["message_metadata.subject"],
                    },
                    "url.long_obfuscated_string": {
                        "kind": "deterministic",
                        "value": "true",
                        "rationale": "Long wrapped tracking URL.",
                        "evidence": ["entities.urls"],
                    },
                }
            },
        }
        llm_payload = {
            "summary_sentences": [
                "This message appears suspicious and needs review.",
                "Some cues resemble marketing traffic while urgency language remains present.",
            ],
            "key_points": [
                "Many long obfuscated redirect/tracking URLs were observed in the message.",
                "Subject uses urgency/pressure language ('time is running out') which is coercive in tone.",
                "Urgent/coercive subject and hidden/obfuscated body content indicate elevated risk.",
            ],
            "sender_summary": "Sender identity was reviewed.",
            "subject_level": "yellow",
            "subject_analysis": "Subject uses urgency wording and should be reviewed.",
            "body_level": "green",
            "body_analysis": "Body appears promotional and not overtly malicious.",
            "urls_overview": "URLs were reviewed.",
            "domains_overview": "Domains were reviewed.",
            "ips_overview": "IPs were reviewed.",
            "attachments_overview": "Attachments were reviewed.",
        }

        report = build_web_report(envelope=envelope, result=result, llm=_LLMStub(llm_payload))
        self.assertTrue(all("obfuscated redirect/tracking" not in kp.lower() for kp in report["key_points"]))
        urgent_mentions = [x for x in report.get("evidence_highlights", []) if "urgent" in str(x.get("detail", "")).lower()]
        self.assertLessEqual(len(urgent_mentions), 1)


if __name__ == "__main__":
    unittest.main()
