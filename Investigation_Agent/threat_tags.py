#!/usr/bin/env python3
"""Deterministic threat-tag derivation for analyst-facing triage output."""

from __future__ import annotations

from typing import Any


KNOWN_TRACKING_HOST_SUFFIXES = (
    ".ct.sendgrid.net",
    ".sendgrid.net",
    ".mailchi.mp",
    ".list-manage.com",
    ".hubspotemail.net",
)

TAG_CATALOG: dict[str, dict[str, str]] = {
    "credential_harvest": {"label": "Credential Harvest", "severity": "critical"},
    "brand_impersonation": {"label": "Brand Impersonation", "severity": "high"},
    "bec_invoice_fraud": {"label": "BEC / Invoice Fraud", "severity": "critical"},
    "payment_diversion": {"label": "Payment Diversion", "severity": "critical"},
    "malware_delivery": {"label": "Malware Delivery", "severity": "critical"},
    "attachment_weaponized": {"label": "Weaponized Attachment", "severity": "high"},
    "account_takeover": {"label": "Account Takeover", "severity": "high"},
    "spoof_auth_failure": {"label": "Spoofing / Auth Failure", "severity": "high"},
    "social_engineering_urgency": {"label": "Social Engineering Urgency", "severity": "medium"},
    "spam_marketing": {"label": "Spam / Marketing", "severity": "low"},
    "graymail_promotional": {"label": "Graymail Promotional", "severity": "info"},
    "recon_or_test_message": {"label": "Recon / Test Message", "severity": "low"},
    "data_exfiltration_lure": {"label": "Data Exfiltration Lure", "severity": "high"},
}

SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

CLASS_TAG_PREFERENCE: dict[str, list[str]] = {
    "phish": [
        "credential_harvest",
        "payment_diversion",
        "malware_delivery",
        "bec_invoice_fraud",
        "brand_impersonation",
        "spoof_auth_failure",
        "attachment_weaponized",
        "account_takeover",
        "data_exfiltration_lure",
        "social_engineering_urgency",
    ],
    "suspicious": [
        "social_engineering_urgency",
        "brand_impersonation",
        "spoof_auth_failure",
        "account_takeover",
        "data_exfiltration_lure",
        "attachment_weaponized",
        "credential_harvest",
        "payment_diversion",
    ],
    "benign": [
        "spam_marketing",
        "graymail_promotional",
        "recon_or_test_message",
        "social_engineering_urgency",
    ],
}


def _signal_true(signals_doc: dict[str, Any], signal_id: str) -> bool:
    payload = ((signals_doc.get("signals") or {}).get(signal_id) or {})
    return str(payload.get("value") or "").lower() == "true"


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _auth_all_pass(envelope: dict[str, Any]) -> bool:
    auth = envelope.get("auth_summary", {}) or {}
    spf_result = _norm((auth.get("spf") or {}).get("result"))
    dmarc = auth.get("dmarc") or {}
    dmarc_result = _norm(dmarc.get("result"))
    aligned = dmarc.get("aligned")

    dkim_rows = auth.get("dkim") or []
    dkim_results = [_norm((row or {}).get("result")) for row in dkim_rows if isinstance(row, dict)]
    dkim_pass = bool(dkim_results) and "fail" not in dkim_results and any(r == "pass" for r in dkim_results)

    if aligned in {None, "unknown"}:
        aligned_ok = dmarc_result == "pass"
    else:
        aligned_ok = bool(aligned)
    return spf_result == "pass" and dmarc_result == "pass" and dkim_pass and aligned_ok


def _marketing_context(envelope: dict[str, Any]) -> bool:
    headers = (envelope.get("message_metadata", {}) or {}).get("headers", {}) or {}
    if any(headers.get(h) for h in ("list-unsubscribe", "list-unsubscribe-post", "list-id")):
        return True
    urls = ((envelope.get("entities") or {}).get("urls") or [])[:30]
    for item in urls:
        host = _norm(item.get("domain"))
        if host and any(host.endswith(suffix) for suffix in KNOWN_TRACKING_HOST_SUFFIXES):
            return True
    plain = _norm(((envelope.get("mime_parts") or {}).get("body_extraction") or {}).get("text_plain"))
    return "unsubscribe" in plain or "manage preferences" in plain or "newsletter" in plain or "job alert" in plain


def derive_threat_tags(
    envelope: dict[str, Any],
    signals_doc: dict[str, Any],
    score_doc: dict[str, Any],
) -> dict[str, Any]:
    verdict = _norm(score_doc.get("verdict"))
    risk_score = float(score_doc.get("risk_score") or 0.0)
    marketing_context = _marketing_context(envelope)
    auth_pass = _auth_all_pass(envelope)

    tags: dict[str, dict[str, Any]] = {}

    def add(tag_id: str, confidence: str, reason: str) -> None:
        if tag_id not in TAG_CATALOG:
            return
        current = tags.get(tag_id)
        if current is None:
            tags[tag_id] = {
                "id": tag_id,
                "label": TAG_CATALOG[tag_id]["label"],
                "severity": TAG_CATALOG[tag_id]["severity"],
                "confidence": confidence,
                "reasons": [reason],
            }
            return
        reasons = list(current.get("reasons") or [])
        if reason not in reasons:
            reasons.append(reason)
        current["reasons"] = reasons[:4]
        if confidence == "high":
            current["confidence"] = "high"

    if _signal_true(signals_doc, "semantic.credential_theft_intent") or _signal_true(
        signals_doc, "content.credential_harvest_language"
    ):
        add("credential_harvest", "high", "Credential-theft intent/language detected")

    if _signal_true(signals_doc, "semantic.payment_diversion_intent") or _signal_true(
        signals_doc, "content.payment_or_invoice_lure"
    ):
        add("payment_diversion", "high", "Payment-diversion or invoice-lure behavior detected")
        add("bec_invoice_fraud", "medium", "Business-email payment language requires verification")

    if _signal_true(signals_doc, "content.account_suspension_threat"):
        add("account_takeover", "medium", "Account suspension pressure pattern detected")

    if _signal_true(signals_doc, "attachment.hash_known_malicious") or _signal_true(
        signals_doc, "attachment.sandbox_behavior_malicious"
    ):
        add("malware_delivery", "high", "Attachment malware evidence detected")

    if _signal_true(signals_doc, "attachment.suspicious_file_type") or _signal_true(
        signals_doc, "attachment.contains_macro_indicator"
    ):
        add("attachment_weaponized", "medium", "Attachment file traits indicate elevated risk")

    if _signal_true(signals_doc, "semantic.impersonation_narrative") or _signal_true(
        signals_doc, "identity.lookalike_domain_confirmed"
    ) or _signal_true(signals_doc, "content.brand_impersonation"):
        add("brand_impersonation", "high", "Impersonation or lookalike evidence detected")

    if _signal_true(signals_doc, "auth.spf_fail") or _signal_true(
        signals_doc, "auth.dkim_fail"
    ) or _signal_true(signals_doc, "auth.dmarc_fail") or _signal_true(signals_doc, "auth.alignment_fail"):
        add("spoof_auth_failure", "high", "Authentication failure suggests spoofing risk")

    if _signal_true(signals_doc, "semantic.coercive_language") or _signal_true(
        signals_doc, "content.urgency_language"
    ) or _signal_true(signals_doc, "semantic.social_engineering_intent"):
        add("social_engineering_urgency", "medium", "Urgency/coercion language detected")

    if _signal_true(signals_doc, "evasion.zero_width_characters") or _signal_true(
        signals_doc, "evasion.homoglyph_substitution"
    ):
        add("data_exfiltration_lure", "medium", "Obfuscation/evasion patterns detected")

    high_risk_driver = any(
        tag_id in tags
        for tag_id in (
            "credential_harvest",
            "payment_diversion",
            "malware_delivery",
            "brand_impersonation",
            "spoof_auth_failure",
        )
    )

    if marketing_context and auth_pass and risk_score <= 30 and not high_risk_driver:
        add("graymail_promotional", "high", "Authenticated marketing/newsletter delivery pattern observed")
        add("spam_marketing", "medium", "Bulk promotional context detected")
    elif marketing_context and risk_score <= 45 and not high_risk_driver:
        add("spam_marketing", "medium", "Promotional or recruiting message profile detected")

    if verdict == "benign" and risk_score <= 15 and not tags:
        add("spam_marketing", "medium", "No high-risk indicators; message resembles low-risk bulk mail")

    ranked = list(tags.values())
    if ranked:
        pref_list = CLASS_TAG_PREFERENCE.get(verdict, CLASS_TAG_PREFERENCE.get("suspicious", []))
        pref_rank = {tag_id: idx for idx, tag_id in enumerate(pref_list)}
        ranked.sort(
            key=lambda row: (
                pref_rank.get(str(row.get("id") or ""), 10_000),
                -SEVERITY_RANK.get(str(row.get("severity") or "info"), 0),
                0 if str(row.get("confidence") or "") == "high" else 1,
                str(row.get("id") or ""),
            )
        )
        primary_row = ranked[0]
    else:
        # Keep output schema stable with one deterministic fallback tag aligned to verdict.
        if verdict == "benign":
            fallback_id = "spam_marketing"
        elif verdict == "phish":
            fallback_id = "credential_harvest"
        else:
            fallback_id = "social_engineering_urgency"
        primary_row = {
            "id": fallback_id,
            "label": TAG_CATALOG[fallback_id]["label"],
            "severity": TAG_CATALOG[fallback_id]["severity"],
            "confidence": "medium",
            "reasons": [],
        }
    primary = primary_row["id"]
    return {
        "primary_threat_tag": primary,
        "threat_tags": [primary_row],
    }
