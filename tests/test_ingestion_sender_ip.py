#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from src.Ingestion.intake import build_envelope


class IngestionSenderIpTests(unittest.TestCase):
    def test_extracts_sender_ip_from_received_and_mailgun_headers(self) -> None:
        eml = textwrap.dedent(
            """\
            Return-Path: <bounce@example-sender.com>
            From: Big Two Toyota <bigtwotoyota@phoenixvalleytoyotadealers.com>
            To: analyst@example.com
            Subject: STEVEN, time is running out.
            Date: Sun, 27 Jul 2025 02:42:54 +0000
            Message-ID: <1234@example-sender.com>
            Received: from m43-6.mailgun.net (m43-6.mailgun.net [69.72.43.6]) by mx.example.net with ESMTPS id ABC123; Sun, 27 Jul 2025 02:42:54 +0000
            X-Mailgun-Sending-Ip: 69.72.43.6
            Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=bounce@example-sender.com; dkim=pass header.d=example-sender.com; dmarc=pass header.from=phoenixvalleytoyotadealers.com
            Content-Type: text/plain; charset=utf-8

            Limited-time offer for your vehicle. Unsubscribe anytime.
            """
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            eml_path = Path(tmpdir) / "sample.eml"
            eml_path.write_text(eml, encoding="utf-8")
            envelope = build_envelope(str(eml_path), case_id="case_sender_ip_test")

        ips = {str(item.get("ip") or "").strip() for item in (envelope.get("entities", {}) or {}).get("ips", [])}
        self.assertIn("69.72.43.6", ips)


if __name__ == "__main__":
    unittest.main()
