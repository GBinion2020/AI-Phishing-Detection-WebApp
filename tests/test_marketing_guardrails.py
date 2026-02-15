#!/usr/bin/env python3

from __future__ import annotations

import unittest

from Investigation_Agent.investigation_pipeline import _mock_is_brand_lookalike
from Signal_Engine.signal_engine import content_hidden_text_or_css, url_long_obfuscated_string


class MarketingGuardrailTests(unittest.TestCase):
    def test_mock_brand_lookalike_does_not_flag_normal_hyphenated_marketing_subdomain(self) -> None:
        legit = "bigtwotoyota-conq.phoenixvalleytoyotadealers.com"
        suspicious = "paypa1-secure-login.com"
        self.assertFalse(_mock_is_brand_lookalike(legit))
        self.assertTrue(_mock_is_brand_lookalike(suspicious))

    def test_marketing_hidden_css_and_long_tracking_path_are_not_flagged(self) -> None:
        long_tail = "A" * 180
        envelope = {
            "message_metadata": {
                "from": {"domain": "phoenixvalleytoyotadealers.com"},
                "return_path": "bounce@bigtwotoyota-conq.phoenixvalleytoyotadealers.com",
                "headers": {
                    "list-unsubscribe": ["<mailto:unsubscribe@example.com>"],
                    "list-id": ["<dealer-list.example.com>"],
                },
            },
            "auth_summary": {
                "spf": {"result": "pass"},
                "dmarc": {"result": "pass", "aligned": True},
                "dkim": [{"result": "pass", "domain": "bigtwotoyota-conq.phoenixvalleytoyotadealers.com"}],
            },
            "entities": {
                "urls": [
                    {
                        "normalized": f"http://email.bigtwotoyota-conq.phoenixvalleytoyotadealers.com/c/{long_tail}",
                        "url": f"http://email.bigtwotoyota-conq.phoenixvalleytoyotadealers.com/c/{long_tail}",
                        "domain": "email.bigtwotoyota-conq.phoenixvalleytoyotadealers.com",
                        "path": f"/c/{long_tail}",
                        "evidence_id": "ev_url_001",
                    }
                ],
                "domains": [{"domain": "phoenixvalleytoyotadealers.com", "punycode": "phoenixvalleytoyotadealers.com"}],
                "ips": [],
            },
            "mime_parts": {
                "body_extraction": {
                    "text_plain": "Limited-time offer. Unsubscribe any time.",
                    "text_html": (
                        "<html><body>"
                        "<span style='display:none;visibility:hidden;opacity:0;font-size:0'>preview</span>"
                        "<a href='http://email.bigtwotoyota-conq.phoenixvalleytoyotadealers.com/c/test'>View offer</a>"
                        "</body></html>"
                    ),
                }
            },
            "attachments": [],
        }

        hidden = content_hidden_text_or_css(envelope)
        long_url = url_long_obfuscated_string(envelope)

        self.assertEqual(hidden.get("value"), "false")
        self.assertEqual(long_url.get("value"), "false")


if __name__ == "__main__":
    unittest.main()
