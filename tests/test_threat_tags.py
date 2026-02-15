#!/usr/bin/env python3

from __future__ import annotations

import unittest

from Investigation_Agent.threat_tags import derive_threat_tags


def _base_envelope() -> dict:
    return {
        "auth_summary": {
            "spf": {"result": "pass"},
            "dmarc": {"result": "pass", "aligned": True},
            "dkim": [{"result": "pass", "domain": "example.com"}],
        },
        "message_metadata": {
            "headers": {
                "list-unsubscribe": ["<mailto:unsubscribe@example.com>"],
            }
        },
        "entities": {
            "urls": [{"domain": "u111.ct.sendgrid.net"}],
        },
        "mime_parts": {
            "body_extraction": {
                "text_plain": "Newsletter update. Unsubscribe any time.",
            }
        },
    }


class ThreatTagTests(unittest.TestCase):
    def test_high_risk_signals_produce_high_severity_primary_tag(self) -> None:
        envelope = _base_envelope()
        signals_doc = {
            "signals": {
                "semantic.credential_theft_intent": {"value": "true"},
                "content.payment_or_invoice_lure": {"value": "true"},
                "auth.dmarc_fail": {"value": "false"},
            }
        }
        score_doc = {"verdict": "phish", "risk_score": 95, "confidence_score": 0.94}

        doc = derive_threat_tags(envelope=envelope, signals_doc=signals_doc, score_doc=score_doc)
        self.assertIn(doc.get("primary_threat_tag"), {"credential_harvest", "payment_diversion", "bec_invoice_fraud"})
        ids = [row.get("id") for row in doc.get("threat_tags", [])]
        self.assertIn("credential_harvest", ids)

    def test_authenticated_marketing_low_risk_gets_graymail_tag(self) -> None:
        envelope = _base_envelope()
        signals_doc = {"signals": {"semantic.coercive_language": {"value": "false"}}}
        score_doc = {"verdict": "benign", "risk_score": 9, "confidence_score": 0.91}

        doc = derive_threat_tags(envelope=envelope, signals_doc=signals_doc, score_doc=score_doc)
        ids = [row.get("id") for row in doc.get("threat_tags", [])]
        self.assertIn("graymail_promotional", ids)
        self.assertIn(doc.get("primary_threat_tag"), ids)

    def test_auth_failures_promote_spoof_auth_failure_tag(self) -> None:
        envelope = _base_envelope()
        envelope["auth_summary"] = {
            "spf": {"result": "fail"},
            "dmarc": {"result": "fail", "aligned": False},
            "dkim": [{"result": "fail", "domain": "evil.example"}],
        }
        signals_doc = {
            "signals": {
                "auth.spf_fail": {"value": "true"},
                "auth.dmarc_fail": {"value": "true"},
                "identity.lookalike_domain_confirmed": {"value": "true"},
            }
        }
        score_doc = {"verdict": "phish", "risk_score": 88, "confidence_score": 0.89}

        doc = derive_threat_tags(envelope=envelope, signals_doc=signals_doc, score_doc=score_doc)
        ids = [row.get("id") for row in doc.get("threat_tags", [])]
        self.assertIn("spoof_auth_failure", ids)
        self.assertIn("brand_impersonation", ids)


if __name__ == "__main__":
    unittest.main()
