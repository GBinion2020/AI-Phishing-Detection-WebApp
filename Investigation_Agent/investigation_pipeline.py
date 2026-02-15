#!/usr/bin/env python3
"""End-to-end phishing investigation pipeline with adaptive deterministic enrichment.

Pipeline:
1) Ingest and normalize envelope
2) Baseline deterministic signals and score
3) Baseline TI enrichment (bounded)
4) Semantic assessment with TI-grounded controlled evidence
5) Adaptive deterministic enrichment loop (no playbooks)
6) Final deterministic score + analyst report
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "MCP_Adapters") not in sys.path:
    sys.path.insert(0, str(ROOT / "MCP_Adapters"))

from src.Ingestion.intake import build_envelope
from Signal_Engine.signal_engine import run_signal_engine
from Signal_Engine.semantic_signal_assessor import (
    assess_semantic_signals,
    build_controlled_evidence_envelope,
    semantic_assessments_to_updates,
)
from Scoring_Engine.scoring_engine import score_signals
from MCP_Adapters.ioc_cache import IOCCache
from MCP_Adapters.mcp_router import route_tool_call, seed_cache
from MCP_Adapters.mock_enrichment import synthesize_mock_output

from Investigation_Agent.contracts import REPORT_SCHEMA, validate_report
from Investigation_Agent.audit_chain import build_audit_chain, to_markdown
from Investigation_Agent.env_utils import env_int, load_dotenv
from Investigation_Agent.llm_client import LLMClient
from Investigation_Agent.prompt_templates import (
    REPORT_SYSTEM_PROMPT,
    report_user_prompt,
)
from Investigation_Agent.threat_tags import derive_threat_tags


TOOL_ALIAS_TO_MCP: dict[str, list[str]] = {
    "url_reputation": ["virustotal_url", "urlscan_lookup", "urlhaus_lookup"],
    # Cuckoo detonation is intentionally disabled until local sandbox infra is ready.
    "url_detonation": ["urlscan_detonate"],
    "whois_domain_age": ["icann_rdap_domain"],
    "hash_intel_lookup": ["virustotal_hash", "alienvault_otx"],
    "ip_reputation": ["abuseipdb_check", "virustotal_ip"],
    "mx_reputation": ["crtsh_lookup"],
}

INTERNAL_TRUSTED_DOMAINS = {
    "microsoft.com",
    "google.com",
    "amazon.com",
    "apple.com",
    "docusign.net",
    "paypal.com",
    "outlook.com",
    "office.com",
    "valero.com",
}

MOCK_LOOKALIKE_BRANDS = {
    "microsoft",
    "google",
    "paypal",
    "amazon",
    "apple",
    "docusign",
    "toyota",
    "chase",
    "wellsfargo",
}

MOCK_CONFUSABLE_TRANSLATION = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "9": "g",
        "@": "a",
        "$": "s",
    }
)

TOOL_ALIAS_TO_SIGNAL_IDS: dict[str, list[str]] = {
    "org_domain_inventory": ["identity.domain_not_owned_by_org"],
    "whois_domain_age": ["identity.newly_registered_sender_domain", "url.domain_newly_registered"],
    "brand_lookalike_detector": ["identity.lookalike_domain_confirmed"],
    "dns_txt_lookup": ["auth.missing_spf_record", "auth.missing_dmarc_record"],
    "url_reputation": ["url.reputation_malicious"],
    "url_detonation": ["url.reputation_malicious", "url.redirect_chain_detected"],
    "url_redirect_resolver": ["url.redirect_chain_detected"],
    "hosting_provider_intel": ["url.hosting_on_free_provider", "infra.bulletproof_hosting_detected"],
    "campaign_similarity": ["content.similarity_to_known_campaign"],
    "nlp_anomaly_model": ["content.nlp_anomaly_score_high"],
    "hash_intel_lookup": ["attachment.hash_known_malicious"],
    "attachment_sandbox": ["attachment.sandbox_behavior_malicious"],
    "ip_reputation": ["infra.sending_ip_reputation_bad"],
    "dns_mx_lookup": ["infra.malicious_mx_records"],
    "mx_reputation": ["infra.malicious_mx_records", "infra.bulletproof_hosting_detected"],
    "mailbox_history": ["behavior.user_not_previous_correspondent"],
    "campaign_clustering": ["behavior.multiple_similar_messages_detected"],
    "dns_history": ["evasion.domain_fast_flux_behavior"],
    "cdn_fronting_detector": ["evasion.cdn_abuse_detected"],
}

ENRICHMENT_ALIAS_PRIORITY = [
    "url_reputation",
    "ip_reputation",
    "hash_intel_lookup",
    "whois_domain_age",
    "brand_lookalike_detector",
    "url_redirect_resolver",
    "url_detonation",
    "dns_txt_lookup",
    "dns_mx_lookup",
    "mx_reputation",
    "hosting_provider_intel",
    "attachment_sandbox",
    "campaign_similarity",
    "nlp_anomaly_model",
    "campaign_clustering",
    "mailbox_history",
    "dns_history",
    "cdn_fronting_detector",
    "org_domain_inventory",
]

BASELINE_TI_PRIORITY = [
    "url_reputation",
    "ip_reputation",
    "hash_intel_lookup",
    "whois_domain_age",
    "brand_lookalike_detector",
]


@dataclass
class Budget:
    max_enrichment_steps: int
    max_tool_calls: int


EventHook = Callable[[str, dict[str, Any]], None]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _emit(event_hook: EventHook | None, event: str, payload: dict[str, Any]) -> None:
    if event_hook is None:
        return
    try:
        event_hook(event, payload)
    except Exception:
        # Event handlers are best-effort and should not break the pipeline.
        return


def _load_json_or_yaml(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore

            parsed = yaml.safe_load(text)
        except ModuleNotFoundError as exc:
            raise RuntimeError(f"Cannot parse {path}. Use JSON-compatible YAML or install PyYAML.") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"Expected mapping in {path}")
    return parsed


def _extract_primary_domain(envelope: dict[str, Any]) -> str | None:
    return ((envelope.get("message_metadata", {}).get("from") or {}).get("domain") or None)


def _org_domain(domain: str | None) -> str | None:
    if not domain:
        return None
    parts = domain.lower().strip(".").split(".")
    if len(parts) < 2:
        return domain.lower().strip(".")
    return ".".join(parts[-2:])


def _mock_is_brand_lookalike(domain_value: str) -> bool:
    domain = str(domain_value or "").strip().lower().strip(".")
    if not domain:
        return False
    if domain.startswith("xn--") or any(ord(ch) > 127 for ch in domain):
        return True

    labels = [lbl for lbl in re.split(r"[.-]", domain) if lbl]
    for label in labels:
        if len(label) < 4:
            continue
        mapped = label.translate(MOCK_CONFUSABLE_TRANSLATION)
        for brand in MOCK_LOOKALIKE_BRANDS:
            # Require a confusable transformation signal (not plain substring presence).
            if mapped == brand and label != brand:
                return True
    return False


def _configured_org_domains() -> set[str]:
    raw = os.getenv("ORG_TRUSTED_DOMAINS", "")
    values = {v.strip().lower() for v in raw.split(",") if v.strip()}
    return values


def _extract_urls(envelope: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for row in envelope.get("entities", {}).get("urls", []) or []:
        value = str(row.get("normalized") or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _extract_domains(envelope: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for row in envelope.get("entities", {}).get("domains", []) or []:
        value = str(row.get("domain") or "").strip().lower()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    primary = _extract_primary_domain(envelope)
    if primary and primary not in seen:
        out.append(primary)
    return out


def _extract_ips(envelope: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for row in envelope.get("entities", {}).get("ips", []) or []:
        value = str(row.get("ip") or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _extract_hashes(envelope: dict[str, Any]) -> list[str]:
    hashes: list[str] = []
    seen: set[str] = set()
    for att in envelope.get("attachments", []) or []:
        sha = str((att.get("hashes") or {}).get("sha256") or "").strip().lower()
        if not sha or sha in seen:
            continue
        seen.add(sha)
        hashes.append(sha)
    return hashes


def _build_tool_payloads(tool_alias: str, envelope: dict[str, Any]) -> list[dict[str, str]]:
    urls = _extract_urls(envelope)
    domains = _extract_domains(envelope)
    ips = _extract_ips(envelope)
    hashes = _extract_hashes(envelope)

    if tool_alias in {"url_reputation", "url_detonation", "url_redirect_resolver"}:
        return [{"ioc_type": "url", "value": u} for u in urls[:3]]
    if tool_alias in {
        "whois_domain_age",
        "brand_lookalike_detector",
        "dns_txt_lookup",
        "dns_mx_lookup",
        "dns_history",
        "cdn_fronting_detector",
        "hosting_provider_intel",
        "mx_reputation",
        "org_domain_inventory",
    }:
        return [{"ioc_type": "domain", "value": d} for d in domains[:3]]
    if tool_alias in {"ip_reputation"}:
        return [{"ioc_type": "ip", "value": ip} for ip in ips[:3]]
    if tool_alias in {"hash_intel_lookup", "attachment_sandbox"}:
        return [{"ioc_type": "hash", "value": h} for h in hashes[:2]]

    # Internal text/history tools still return one domain context payload.
    if domains:
        return [{"ioc_type": "domain", "value": domains[0]}]
    return []


def _execute_internal_tool(tool_alias: str, payload: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
    value = str(payload.get("value", "")).lower()

    if tool_alias == "org_domain_inventory":
        configured = _configured_org_domains()
        if not configured:
            return {"status": "deferred", "reason": "ORG_TRUSTED_DOMAINS not configured", "confidence": 0.0}
        org_set = INTERNAL_TRUSTED_DOMAINS.union(configured)
        owned = (
            value in org_set
            or _org_domain(value) in org_set
            or value.endswith(".edu")
            or value.endswith(".gov")
        )
        return {"status": "ok", "owned": owned, "confidence": 0.8 if owned else 0.7}

    if tool_alias == "brand_lookalike_detector":
        lookalike = _mock_is_brand_lookalike(value)
        return {"status": "ok", "is_lookalike": lookalike, "confidence": 0.8 if lookalike else 0.35}

    if tool_alias == "dns_txt_lookup":
        suspicious = "secure" in value or "verify" in value
        return {"status": "ok", "spf_exists": not suspicious, "dmarc_exists": not suspicious, "confidence": 0.7}

    if tool_alias == "dns_mx_lookup":
        malicious = "mail" in value and "secure" in value
        return {"status": "ok", "malicious": malicious, "confidence": 0.6}

    if tool_alias == "url_redirect_resolver":
        redirect_chain = any(tok in value for tok in ("redirect", "target=", "next=", "url="))
        return {"status": "ok", "redirect_chain": redirect_chain, "confidence": 0.7}

    if tool_alias == "campaign_similarity":
        text = (envelope.get("mime_parts", {}).get("body_extraction", {}).get("text_plain", "") or "").lower()
        matched = any(t in text for t in ("verify", "urgent", "password", "invoice"))
        return {"status": "ok", "matched": matched, "confidence": 0.65}

    if tool_alias == "nlp_anomaly_model":
        text = (envelope.get("mime_parts", {}).get("body_extraction", {}).get("text_plain", "") or "")
        anomaly = len(text) > 120 and ("http" in text.lower() or "urgent" in text.lower())
        return {"status": "ok", "score": 0.82 if anomaly else 0.18, "threshold": 0.7, "confidence": 0.6}

    if tool_alias == "attachment_sandbox":
        # Static mock until live sandbox exists.
        hashes = _extract_hashes(envelope)
        malicious = any(h.startswith("deadbeef") for h in hashes)
        return {"status": "ok", "malicious_behavior": malicious, "confidence": 0.75 if malicious else 0.2}

    if tool_alias == "mailbox_history":
        # Do not assert "new correspondent" without real mailbox telemetry.
        return {"status": "deferred", "reason": "mailbox history provider not configured", "confidence": 0.0}

    if tool_alias == "campaign_clustering":
        subject = (envelope.get("message_metadata", {}).get("subject") or "").lower()
        clustered = any(k in subject for k in ("urgent", "invoice", "verify", "password"))
        return {"status": "ok", "clustered": clustered, "cluster_size": 4 if clustered else 1, "confidence": 0.6}

    if tool_alias == "dns_history":
        fast_flux = any(tok in value for tok in ("secure", "verify", "update"))
        return {"status": "ok", "fast_flux": fast_flux, "confidence": 0.65}

    if tool_alias == "cdn_fronting_detector":
        abuse = any(tok in value for tok in ("cdn", "front"))
        return {"status": "ok", "abuse_detected": abuse, "confidence": 0.55}

    if tool_alias == "hosting_provider_intel":
        free = any(tok in value for tok in ("blogspot", "weebly", "wixsite", "000webhost"))
        bulletproof = any(tok in value for tok in ("offshore", "secure")) and free
        return {"status": "ok", "is_free_hosting": free, "is_bulletproof": bulletproof, "confidence": 0.5}

    return {"status": "deferred", "confidence": 0.0}


def _map_tool_result_to_signal_updates(
    tool_alias: str,
    payload: dict[str, Any],
    result: dict[str, Any],
    evidence_id: str,
) -> list[dict[str, Any]]:
    output = result.get("output", result)
    updates: list[dict[str, Any]] = []
    if not isinstance(output, dict):
        return updates
    if str(output.get("status", "ok")).lower() != "ok":
        return updates

    def add(signal_id: str, value: str, rationale: str) -> None:
        updates.append(
            {
                "signal_id": signal_id,
                "value": value,
                "evidence": [evidence_id],
                "rationale": rationale,
            }
        )

    if tool_alias == "org_domain_inventory":
        owned = output.get("owned")
        if isinstance(owned, bool):
            add("identity.domain_not_owned_by_org", "false" if owned else "true", f"domain ownership check owned={owned}")

    elif tool_alias == "whois_domain_age":
        registered = output.get("registered")
        age_days = output.get("age_days")
        if isinstance(age_days, int):
            if registered is False or age_days <= 0:
                value = "unknown"
                rationale = f"domain registration age unavailable (registered={registered}, age_days={age_days})"
            else:
                value = "true" if age_days < 30 else "false"
                rationale = f"domain age days={age_days}"
            add("identity.newly_registered_sender_domain", value, rationale)
            add("url.domain_newly_registered", value, rationale)

    elif tool_alias == "brand_lookalike_detector":
        lookalike = output.get("is_lookalike")
        if isinstance(lookalike, bool):
            add("identity.lookalike_domain_confirmed", "true" if lookalike else "false", f"lookalike result={lookalike}")

    elif tool_alias == "dns_txt_lookup":
        spf_exists = output.get("spf_exists")
        dmarc_exists = output.get("dmarc_exists")
        if isinstance(spf_exists, bool):
            add("auth.missing_spf_record", "false" if spf_exists else "true", f"spf_exists={spf_exists}")
        if isinstance(dmarc_exists, bool):
            add("auth.missing_dmarc_record", "false" if dmarc_exists else "true", f"dmarc_exists={dmarc_exists}")

    elif tool_alias == "url_reputation":
        mal = output.get("malicious")
        if isinstance(mal, bool):
            add("url.reputation_malicious", "true" if mal else "false", f"url reputation malicious={mal}")

    elif tool_alias == "url_detonation":
        mal = output.get("malicious")
        redirects = output.get("redirects")
        if isinstance(mal, bool):
            add("url.reputation_malicious", "true" if mal else "false", f"url detonation malicious={mal}")
        if isinstance(redirects, int):
            add("url.redirect_chain_detected", "true" if redirects > 1 else "false", f"url detonation redirects={redirects}")

    elif tool_alias == "url_redirect_resolver":
        chain = output.get("redirect_chain")
        if isinstance(chain, bool):
            add("url.redirect_chain_detected", "true" if chain else "false", f"redirect_chain={chain}")

    elif tool_alias == "hosting_provider_intel":
        free = output.get("is_free_hosting")
        bullet = output.get("is_bulletproof")
        if isinstance(free, bool):
            add("url.hosting_on_free_provider", "true" if free else "false", f"is_free_hosting={free}")
        if isinstance(bullet, bool):
            add("infra.bulletproof_hosting_detected", "true" if bullet else "false", f"is_bulletproof={bullet}")

    elif tool_alias == "campaign_similarity":
        matched = output.get("matched")
        if isinstance(matched, bool):
            add("content.similarity_to_known_campaign", "true" if matched else "false", f"campaign matched={matched}")

    elif tool_alias == "nlp_anomaly_model":
        score = output.get("score")
        threshold = output.get("threshold")
        if isinstance(score, (int, float)) and isinstance(threshold, (int, float)):
            high = score >= threshold
            add("content.nlp_anomaly_score_high", "true" if high else "false", f"score={score}, threshold={threshold}")

    elif tool_alias == "hash_intel_lookup":
        mal = output.get("malicious")
        if isinstance(mal, bool):
            add("attachment.hash_known_malicious", "true" if mal else "false", f"hash malicious={mal}")

    elif tool_alias == "attachment_sandbox":
        mal = output.get("malicious_behavior")
        if isinstance(mal, bool):
            add("attachment.sandbox_behavior_malicious", "true" if mal else "false", f"sandbox malicious_behavior={mal}")

    elif tool_alias == "ip_reputation":
        mal = output.get("malicious")
        if isinstance(mal, bool):
            add("infra.sending_ip_reputation_bad", "true" if mal else "false", f"ip malicious={mal}")

    elif tool_alias in {"dns_mx_lookup", "mx_reputation"}:
        mal = output.get("malicious")
        if isinstance(mal, bool):
            add("infra.malicious_mx_records", "true" if mal else "false", f"mx malicious={mal}")

    elif tool_alias == "mailbox_history":
        prev = output.get("previous_contact")
        if isinstance(prev, bool):
            add("behavior.user_not_previous_correspondent", "false" if prev else "true", f"previous_contact={prev}")

    elif tool_alias == "campaign_clustering":
        clustered = output.get("clustered")
        if isinstance(clustered, bool):
            add("behavior.multiple_similar_messages_detected", "true" if clustered else "false", f"clustered={clustered}")

    elif tool_alias == "dns_history":
        ff = output.get("fast_flux")
        if isinstance(ff, bool):
            add("evasion.domain_fast_flux_behavior", "true" if ff else "false", f"fast_flux={ff}")

    elif tool_alias == "cdn_fronting_detector":
        abuse = output.get("abuse_detected")
        if isinstance(abuse, bool):
            add("evasion.cdn_abuse_detected", "true" if abuse else "false", f"abuse_detected={abuse}")

    return updates


def _dedupe_updates(updates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    rank = {"true": 3, "false": 2, "unknown": 1}
    for up in updates:
        sid = up["signal_id"]
        prev = latest.get(sid)
        if prev is None:
            latest[sid] = up
            continue
        prev_rank = rank.get(str(prev.get("value", "unknown")), 0)
        new_rank = rank.get(str(up.get("value", "unknown")), 0)
        if new_rank >= prev_rank:
            latest[sid] = up
    return list(latest.values())


def _apply_signal_updates(signals_doc: dict[str, Any], updates: list[dict[str, Any]]) -> None:
    for up in updates:
        sid = up["signal_id"]
        if sid not in signals_doc.get("signals", {}):
            continue
        payload = signals_doc["signals"][sid]
        if payload.get("kind") != "non_deterministic":
            continue
        payload["value"] = up["value"]
        payload["evidence"] = up["evidence"]
        payload["rationale"] = up["rationale"]


def _llm_report(
    llm: LLMClient,
    envelope: dict[str, Any],
    signals_doc: dict[str, Any],
    score_doc: dict[str, Any],
    iterations: list[dict[str, Any]],
) -> dict[str, Any]:
    def _fallback_report(note: str) -> dict[str, Any]:
        return {
            "executive_summary": (
                f"Case {envelope.get('case_id')}: verdict={score_doc.get('verdict')} "
                f"risk={score_doc.get('risk_score')} confidence={score_doc.get('confidence_score')} "
                f"({note})"
            ),
            "key_indicators": [r.get("signal_id") for r in score_doc.get("reasons", [])[:6]],
            "recommended_actions": [
                "Block sender domain if policy allows",
                "Search mailbox for similar IOCs",
                "Escalate to SOC analyst if confidence remains low",
            ],
            "unknowns": [
                sid
                for sid, payload in signals_doc.get("signals", {}).items()
                if payload.get("value") == "unknown"
            ],
        }

    if not llm.enabled:
        return _fallback_report("LLM disabled")

    user_prompt = report_user_prompt(envelope, signals_doc, score_doc, iterations)
    try:
        out = llm.call_json(
            system_prompt=REPORT_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            json_schema=REPORT_SCHEMA,
            schema_name="investigation_report",
            temperature=0.0,
        )
        validate_report(out)
        return out
    except Exception as exc:
        return _fallback_report(f"LLM report fallback due to error: {exc}")


def _execute_enrichment_tool(
    tool_alias: str,
    envelope: dict[str, Any],
    registry: dict[str, Any],
    cache: IOCCache,
    mode: str,
    tool_call_budget_remaining: int,
    evidence_counter_start: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    evidence: list[dict[str, Any]] = []
    updates: list[dict[str, Any]] = []
    tool_calls_used = 0
    ev_idx = evidence_counter_start

    payloads = _build_tool_payloads(tool_alias, envelope)
    if not payloads:
        return evidence, updates, tool_calls_used

    payloads = payloads[:3]

    for payload in payloads:
        if tool_calls_used >= tool_call_budget_remaining:
            break

        if tool_alias in TOOL_ALIAS_TO_MCP:
            mcp_tools = TOOL_ALIAS_TO_MCP[tool_alias]
            for mcp_tool in mcp_tools:
                if tool_calls_used >= tool_call_budget_remaining:
                    break

                if mode == "mock":
                    mock_output = synthesize_mock_output(mcp_tool, payload)
                    seed_cache(mcp_tool, payload, mock_output, registry, cache)

                routed = route_tool_call(mcp_tool, payload, registry, cache, live_call=(mode == "live"))
                ev_idx += 1
                evidence_id = f"ev_mcp_{ev_idx:04d}"
                ev = {
                    "evidence_id": evidence_id,
                    "tool_alias": tool_alias,
                    "tool_id": mcp_tool,
                    "payload": payload,
                    "result": routed,
                }
                evidence.append(ev)
                mapped_updates = _map_tool_result_to_signal_updates(tool_alias, payload, routed, evidence_id)
                updates.extend(mapped_updates)
                tool_calls_used += 1
                output = routed.get("output", {}) if isinstance(routed, dict) else {}
                status = str((output or {}).get("status") or "").lower()
                confidence = float((output or {}).get("confidence") or 0.0)
                # Fallback chain behavior:
                # stop on first provider that produced concrete updates or sufficiently confident "ok" output.
                if status == "ok" and (mapped_updates or confidence >= 0.35):
                    break
        else:
            internal = _execute_internal_tool(tool_alias, payload, envelope)
            ev_idx += 1
            evidence_id = f"ev_internal_{ev_idx:04d}"
            ev = {
                "evidence_id": evidence_id,
                "tool_alias": tool_alias,
                "tool_id": f"internal.{tool_alias}",
                "payload": payload,
                "result": internal,
            }
            evidence.append(ev)
            updates.extend(_map_tool_result_to_signal_updates(tool_alias, payload, internal, evidence_id))
            tool_calls_used += 1

    return evidence, _dedupe_updates(updates), tool_calls_used


def _build_enrichment_plan(
    signals_doc: dict[str, Any],
    nondet_rules: dict[str, Any],
) -> dict[str, Any]:
    unknown_nondet = [
        sid
        for sid, payload in signals_doc.get("signals", {}).items()
        if payload.get("kind") == "non_deterministic"
        and payload.get("value") == "unknown"
        and not sid.startswith("semantic.")
    ]

    rule_map: dict[str, list[str]] = {}
    for row in nondet_rules.get("non_deterministic_rules", []) or []:
        sid = str(row.get("id") or "")
        req = [str(x) for x in (row.get("required_tools") or []) if str(x)]
        if sid:
            rule_map[sid] = req

    tool_set: set[str] = set()
    for sid in unknown_nondet:
        for alias in rule_map.get(sid, []):
            if alias == "llm_semantic_assessor":
                continue
            tool_set.add(alias)

    priority = {alias: idx for idx, alias in enumerate(ENRICHMENT_ALIAS_PRIORITY)}
    ordered = sorted(tool_set, key=lambda alias: (priority.get(alias, 10_000), alias))

    notes = [
        "Deterministic enrichment plan from unknown non-deterministic signals.",
        "Playbook planner is deprecated; tool execution is direct and bounded.",
    ]
    if not ordered:
        notes.append("No enrichment tools were required after baseline scoring.")

    return {
        "tool_order": ordered,
        "unknown_nondeterministic_signals": unknown_nondet,
        "notes": notes,
    }


def _unknown_nondeterministic_signals(signals_doc: dict[str, Any]) -> list[str]:
    return [
        sid
        for sid, payload in signals_doc.get("signals", {}).items()
        if payload.get("kind") == "non_deterministic"
        and payload.get("value") == "unknown"
        and not sid.startswith("semantic.")
    ]


def _required_tools_for_unknown_signals(
    unknown_signals: list[str],
    nondet_rules: dict[str, Any],
) -> set[str]:
    rule_map: dict[str, list[str]] = {}
    for row in nondet_rules.get("non_deterministic_rules", []) or []:
        sid = str(row.get("id") or "")
        req = [str(x) for x in (row.get("required_tools") or []) if str(x)]
        if sid:
            rule_map[sid] = req
    tool_set: set[str] = set()
    for sid in unknown_signals:
        for alias in rule_map.get(sid, []):
            if alias != "llm_semantic_assessor":
                tool_set.add(alias)
    return tool_set


def _tool_priority_index(tool_alias: str) -> int:
    try:
        return ENRICHMENT_ALIAS_PRIORITY.index(tool_alias)
    except ValueError:
        return 10_000


def _signal_weight_lookup(scoring_cfg: dict[str, Any], signal_id: str) -> float:
    overrides = ((scoring_cfg.get("risk") or {}).get("signal_overrides") or {})
    if signal_id in overrides and "true_weight" in (overrides.get(signal_id) or {}):
        return float((overrides.get(signal_id) or {}).get("true_weight") or 0.0)
    category = signal_id.split(".", 1)[0]
    cat_defaults = ((scoring_cfg.get("risk") or {}).get("category_defaults") or {}).get(category) or {}
    return float(cat_defaults.get("non_deterministic") or cat_defaults.get("deterministic") or 0.0)


def _tool_expected_gain(
    tool_alias: str,
    signals_doc: dict[str, Any],
    scoring_cfg: dict[str, Any],
) -> float:
    score = 0.0
    for signal_id in TOOL_ALIAS_TO_SIGNAL_IDS.get(tool_alias, []):
        payload = (signals_doc.get("signals", {}) or {}).get(signal_id, {})
        if payload.get("value") != "unknown":
            continue
        weight = _signal_weight_lookup(scoring_cfg, signal_id)
        score += max(1.0, weight)
    return score


def _select_next_tool_alias(
    candidate_tools: set[str],
    completed_tools: set[str],
    envelope: dict[str, Any],
    signals_doc: dict[str, Any],
    scoring_cfg: dict[str, Any],
    presemantic_phase: bool = False,
) -> str | None:
    ranked: list[tuple[float, str]] = []
    for alias in candidate_tools:
        if alias in completed_tools:
            continue
        payload_count = len(_build_tool_payloads(alias, envelope))
        if payload_count <= 0:
            continue
        expected_gain = _tool_expected_gain(alias, signals_doc, scoring_cfg)
        priority_bonus = max(0, 20 - _tool_priority_index(alias))
        presemantic_bonus = 10.0 if presemantic_phase and alias in BASELINE_TI_PRIORITY else 0.0
        score = (expected_gain * 1.7) + (payload_count * 0.9) + priority_bonus + presemantic_bonus
        ranked.append((score, alias))
    if not ranked:
        return None
    ranked.sort(key=lambda row: (-row[0], _tool_priority_index(row[1]), row[1]))
    return ranked[0][1]


def _build_semantic_ti_context(
    envelope: dict[str, Any],
    signals_doc: dict[str, Any],
    scoring_cfg: dict[str, Any],
) -> dict[str, Any]:
    entities = envelope.get("entities", {}) or {}
    urls = entities.get("urls", []) or []
    domains = entities.get("domains", []) or []
    ips = entities.get("ips", []) or []

    true_signals = [
        sid
        for sid, payload in (signals_doc.get("signals") or {}).items()
        if str(payload.get("value") or "").lower() == "true"
    ]
    high_impact = set(((scoring_cfg.get("risk") or {}).get("high_impact_signals") or []))
    high_risk_true = [sid for sid in true_signals if sid in high_impact]

    malicious_urls: list[str] = []
    malicious_domains: list[str] = []
    malicious_ips: list[str] = []

    if str(((signals_doc.get("signals") or {}).get("url.reputation_malicious") or {}).get("value") or "").lower() == "true":
        malicious_urls = [str(item.get("normalized") or item.get("url") or "") for item in urls[:20] if item]
    if str(((signals_doc.get("signals") or {}).get("identity.lookalike_domain_confirmed") or {}).get("value") or "").lower() == "true":
        malicious_domains = [str(item.get("domain") or "") for item in domains[:20] if item]
    if str(((signals_doc.get("signals") or {}).get("infra.sending_ip_reputation_bad") or {}).get("value") or "").lower() == "true":
        malicious_ips = [str(item.get("ip") or "") for item in ips[:20] if item]

    return {
        "malicious_urls": [u for u in malicious_urls if u],
        "malicious_domains": [d for d in malicious_domains if d],
        "malicious_ips": [ip for ip in malicious_ips if ip],
        "high_risk_signals_true": high_risk_true[:30],
        "notes": (
            "Threat-intel context is derived from deterministic + tool-backed signals. "
            "Use this context to reduce false positives on authenticated marketing traffic."
        ),
    }


def _should_stop_early(
    current_score: dict[str, Any],
    score_history: list[dict[str, Any]],
) -> tuple[bool, str | None]:
    risk = float(current_score.get("risk_score") or 0.0)
    conf = float(current_score.get("confidence_score") or 0.0)

    if risk >= 85 and conf >= 0.85:
        return True, "definitive_phish"
    if risk <= 20 and conf >= 0.85:
        return True, "definitive_benign"

    if len(score_history) >= 4:
        recent = score_history[-4:]
        gains = []
        for idx in range(1, len(recent)):
            prev = float(recent[idx - 1].get("confidence_score") or 0.0)
            curr = float(recent[idx].get("confidence_score") or 0.0)
            gains.append(curr - prev)
        if gains and all(gain < 0.02 for gain in gains):
            return True, "confidence_plateau"
    return False, None


def run_pipeline(
    eml_path: str,
    out_dir: str,
    mode: str = "mock",
    event_hook: EventHook | None = None,
) -> dict[str, Any]:
    load_dotenv(str(ROOT / ".env"))

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    _emit(event_hook, "pipeline_started", {"eml_path": eml_path, "out_dir": str(out), "mode": mode})

    # Core configs
    _emit(event_hook, "stage_started", {"stage": "load_configs"})
    signal_taxonomy = _load_json_or_yaml(ROOT / "Signal_Engine" / "signal_taxonomy.yaml")
    signal_det_rules = _load_json_or_yaml(ROOT / "Signal_Engine" / "signal_rules_deterministic.yaml")
    signal_nondet_rules = _load_json_or_yaml(ROOT / "Signal_Engine" / "signal_rules_nondeterministic.yaml")
    scoring_cfg = _load_json_or_yaml(ROOT / "Scoring_Engine" / "scoring_weights.yaml")

    mcp_registry_path = Path(os.getenv("MCP_TOOL_REGISTRY", "MCP_Adapters/mcp_tool_registry.yaml"))
    if not mcp_registry_path.is_absolute():
        mcp_registry_path = ROOT / mcp_registry_path
    mcp_registry = _load_json_or_yaml(mcp_registry_path)

    cache_path = os.getenv("MCP_CACHE_PATH", "MCP_Adapters/ioc_cache.json")
    cache_abs = Path(cache_path) if Path(cache_path).is_absolute() else ROOT / cache_path
    cache = IOCCache(path=str(cache_abs))

    budget = Budget(
        max_enrichment_steps=env_int(
            "INVESTIGATION_MAX_ENRICHMENT_STEPS",
            env_int("INVESTIGATION_MAX_PLAYBOOKS", 8),
        ),
        max_tool_calls=env_int("INVESTIGATION_MAX_TOOL_CALLS", 30),
    )

    llm = LLMClient(timeout_seconds=env_int("OPENAI_TIMEOUT_SECONDS", 60))
    _emit(event_hook, "stage_completed", {"stage": "load_configs"})

    # 1) Envelope
    _emit(event_hook, "stage_started", {"stage": "normalize_envelope"})
    envelope = build_envelope(eml_path=eml_path, source="local_file")
    (out / "envelope.json").write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    _emit(
        event_hook,
        "stage_completed",
        {
            "stage": "normalize_envelope",
            "case_id": envelope.get("case_id"),
            "sender": (envelope.get("message_metadata", {}).get("from") or {}).get("address"),
            "subject": envelope.get("message_metadata", {}).get("subject"),
        },
    )

    # 2) Baseline deterministic signals + scoring (semantic deferred until TI context exists)
    _emit(event_hook, "stage_started", {"stage": "baseline_scoring"})
    signals_doc = run_signal_engine(
        envelope=envelope,
        taxonomy=signal_taxonomy,
        deterministic_rules=signal_det_rules,
        nondeterministic_rules=signal_nondet_rules,
        tool_results=None,
    )

    baseline_signals = copy.deepcopy(signals_doc)
    score_doc = score_signals(signals_doc, scoring_cfg)
    baseline_score = copy.deepcopy(score_doc)

    semantic_doc: dict[str, Any] = {
        "assessments": [],
        "prompt_injection_detected": False,
        "prompt_injection_indicators": [],
        "notes": "Semantic stage deferred until baseline TI enrichment context is available.",
    }
    controlled_evidence: dict[str, Any] = {
        "case_id": envelope.get("case_id"),
        "security_note": "Semantic stage deferred until baseline TI enrichment context is available.",
    }

    (out / "signals.baseline.json").write_text(json.dumps(signals_doc, indent=2) + "\n", encoding="utf-8")
    (out / "score.baseline.json").write_text(json.dumps(score_doc, indent=2) + "\n", encoding="utf-8")
    _emit(
        event_hook,
        "stage_completed",
        {
            "stage": "baseline_scoring",
            "risk_score": score_doc.get("risk_score"),
            "confidence_score": score_doc.get("confidence_score"),
            "verdict": score_doc.get("verdict"),
            "invoke_agent": score_doc.get("agent_gate", {}).get("invoke_agent"),
        },
    )

    current_signals = copy.deepcopy(signals_doc)
    current_score = copy.deepcopy(score_doc)
    iterations: list[dict[str, Any]] = []
    total_tool_calls = 0
    score_history: list[dict[str, Any]] = [
        {
            "risk_score": current_score.get("risk_score"),
            "confidence_score": current_score.get("confidence_score"),
        }
    ]

    # 3) Adaptive deterministic enrichment
    enrichment_plan = _build_enrichment_plan(current_signals, signal_nondet_rules)
    (out / "enrichment.plan.json").write_text(json.dumps(enrichment_plan, indent=2) + "\n", encoding="utf-8")

    def _execute_enrichment_iteration(tool_alias: str, phase: str, evidence_counter: int) -> tuple[int, bool]:
        nonlocal total_tool_calls, current_score
        _emit(
            event_hook,
            "enrichment_started",
            {
                "tool_alias": tool_alias,
                "index": len(iterations) + 1,
                "remaining_tool_budget": budget.max_tool_calls - total_tool_calls,
                "phase": phase,
            },
        )

        evidence, deterministic_updates, calls_used = _execute_enrichment_tool(
            tool_alias=tool_alias,
            envelope=envelope,
            registry=mcp_registry,
            cache=cache,
            mode=mode,
            tool_call_budget_remaining=(budget.max_tool_calls - total_tool_calls),
            evidence_counter_start=evidence_counter,
        )
        total_tool_calls += calls_used
        updates = _dedupe_updates(deterministic_updates)
        _apply_signal_updates(current_signals, updates)
        current_score = score_signals(current_signals, scoring_cfg)
        score_history.append(
            {
                "risk_score": current_score.get("risk_score"),
                "confidence_score": current_score.get("confidence_score"),
            }
        )

        iteration = {
            "index": len(iterations) + 1,
            "phase": phase,
            "tool_alias": tool_alias,
            "tool_calls_used": calls_used,
            "evidence_count": len(evidence),
            "evidence": evidence,
            "signal_updates": updates,
            "score_after": {
                "risk_score": current_score.get("risk_score"),
                "confidence_score": current_score.get("confidence_score"),
                "verdict": current_score.get("verdict"),
                "agent_gate": current_score.get("agent_gate"),
            },
        }
        iterations.append(iteration)

        _emit(
            event_hook,
            "enrichment_completed",
            {
                "tool_alias": tool_alias,
                "tool_calls_used": calls_used,
                "risk_score": current_score.get("risk_score"),
                "confidence_score": current_score.get("confidence_score"),
                "verdict": current_score.get("verdict"),
                "phase": phase,
            },
        )
        return len(evidence), bool(updates)

    if not current_score.get("agent_gate", {}).get("invoke_agent", True):
        stop_reason = "risk_gate_satisfied_after_baseline"
    else:
        _emit(event_hook, "stage_started", {"stage": "enrich_signals"})
        stop_reason = "enrichment_completed"
        evidence_counter = 0
        completed_tools: set[str] = set()
        initial_candidates = set(enrichment_plan.get("tool_order", []))

        # Phase A: baseline TI pre-enrichment before semantic assessment.
        presemantic_rounds = min(3, budget.max_enrichment_steps)
        for _ in range(presemantic_rounds):
            if len(iterations) >= budget.max_enrichment_steps:
                stop_reason = "max_enrichment_steps_reached"
                break
            if total_tool_calls >= budget.max_tool_calls:
                stop_reason = "tool_call_budget_reached"
                break
            next_tool = _select_next_tool_alias(
                candidate_tools=initial_candidates,
                completed_tools=completed_tools,
                envelope=envelope,
                signals_doc=current_signals,
                scoring_cfg=scoring_cfg,
                presemantic_phase=True,
            )
            if not next_tool:
                break
            evidence_count, _has_updates = _execute_enrichment_iteration(
                tool_alias=next_tool,
                phase="baseline_ti_enrichment",
                evidence_counter=evidence_counter,
            )
            evidence_counter += evidence_count
            completed_tools.add(next_tool)

            stop, stop_hint = _should_stop_early(current_score, score_history)
            if stop:
                stop_reason = str(stop_hint or "early_stop")
                break
            if not current_score.get("agent_gate", {}).get("invoke_agent", True):
                stop_reason = "confidence_gate_satisfied"
                break

        # Phase B: semantic assessment with TI context when still needed.
        if (
            stop_reason == "enrichment_completed"
            and len(iterations) < budget.max_enrichment_steps
            and current_score.get("agent_gate", {}).get("invoke_agent", True)
        ):
            ti_context = _build_semantic_ti_context(envelope, current_signals, scoring_cfg)
            controlled_evidence = build_controlled_evidence_envelope(envelope, ti_context=ti_context)
            semantic_doc = assess_semantic_signals(controlled_evidence, llm=llm)
            semantic_updates = semantic_assessments_to_updates(semantic_doc)
            _apply_signal_updates(current_signals, semantic_updates)
            current_score = score_signals(current_signals, scoring_cfg)
            score_history.append(
                {
                    "risk_score": current_score.get("risk_score"),
                    "confidence_score": current_score.get("confidence_score"),
                }
            )
            iterations.append(
                {
                    "index": len(iterations) + 1,
                    "phase": "semantic_assessment",
                    "tool_alias": "llm_semantic_assessor",
                    "tool_calls_used": 0,
                    "evidence_count": 0,
                    "evidence": [],
                    "signal_updates": semantic_updates,
                    "score_after": {
                        "risk_score": current_score.get("risk_score"),
                        "confidence_score": current_score.get("confidence_score"),
                        "verdict": current_score.get("verdict"),
                        "agent_gate": current_score.get("agent_gate"),
                    },
                }
            )

            stop, stop_hint = _should_stop_early(current_score, score_history)
            if stop:
                stop_reason = str(stop_hint or "early_stop")
            elif not current_score.get("agent_gate", {}).get("invoke_agent", True):
                stop_reason = "confidence_gate_satisfied"

        # Phase C: adaptive deterministic enrichment after semantic context.
        while stop_reason == "enrichment_completed":
            if len(iterations) >= budget.max_enrichment_steps:
                stop_reason = "max_enrichment_steps_reached"
                break
            if total_tool_calls >= budget.max_tool_calls:
                stop_reason = "tool_call_budget_reached"
                break
            if not current_score.get("agent_gate", {}).get("invoke_agent", True):
                stop_reason = "confidence_gate_satisfied"
                break

            unknown_signals = _unknown_nondeterministic_signals(current_signals)
            candidate_tools = _required_tools_for_unknown_signals(unknown_signals, signal_nondet_rules)
            if not candidate_tools:
                stop_reason = "no_enrichment_candidates"
                break

            next_tool = _select_next_tool_alias(
                candidate_tools=candidate_tools,
                completed_tools=completed_tools,
                envelope=envelope,
                signals_doc=current_signals,
                scoring_cfg=scoring_cfg,
                presemantic_phase=False,
            )
            if not next_tool:
                stop_reason = "no_enrichment_candidates"
                break

            evidence_count, _has_updates = _execute_enrichment_iteration(
                tool_alias=next_tool,
                phase="adaptive_enrichment",
                evidence_counter=evidence_counter,
            )
            evidence_counter += evidence_count
            completed_tools.add(next_tool)

            stop, stop_hint = _should_stop_early(current_score, score_history)
            if stop:
                stop_reason = str(stop_hint or "early_stop")
                break
            if not current_score.get("agent_gate", {}).get("invoke_agent", True):
                stop_reason = "confidence_gate_satisfied"
                break

    (out / "evidence.controlled.json").write_text(json.dumps(controlled_evidence, indent=2) + "\n", encoding="utf-8")
    (out / "semantic_assessment.json").write_text(json.dumps(semantic_doc, indent=2) + "\n", encoding="utf-8")
    _emit(
        event_hook,
        "stage_completed",
        {
            "stage": "enrich_signals",
            "stop_reason": stop_reason,
            "used_enrichment_steps": len(iterations),
            "used_tool_calls": total_tool_calls,
        },
    )

    threat_tag_doc = derive_threat_tags(envelope=envelope, signals_doc=current_signals, score_doc=current_score)
    current_score = {
        **current_score,
        "primary_threat_tag": threat_tag_doc.get("primary_threat_tag"),
        "threat_tags": threat_tag_doc.get("threat_tags", []),
    }

    # 4) Final report
    _emit(event_hook, "stage_started", {"stage": "final_report"})
    final_report = _llm_report(llm, envelope, current_signals, current_score, iterations)

    result = {
        "schema_version": "1.0",
        "case_id": envelope.get("case_id"),
        "generated_at": _now_iso(),
        "mode": mode,
        "agent_invoked": bool(iterations),
        "stop_reason": stop_reason,
        "budgets": {
            "max_enrichment_steps": budget.max_enrichment_steps,
            "max_tool_calls": budget.max_tool_calls,
            "used_enrichment_steps": len(iterations),
            "used_tool_calls": total_tool_calls,
        },
        "enrichment_plan": enrichment_plan,
        "iterations": iterations,
        "final_signals": current_signals,
        "final_score": current_score,
        "final_report": final_report,
    }

    (out / "signals.final.json").write_text(json.dumps(current_signals, indent=2) + "\n", encoding="utf-8")
    (out / "score.final.json").write_text(json.dumps(current_score, indent=2) + "\n", encoding="utf-8")
    (out / "report.final.json").write_text(json.dumps(final_report, indent=2) + "\n", encoding="utf-8")
    (out / "investigation_result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    audit = build_audit_chain(
        eml_path=eml_path,
        envelope=envelope,
        baseline_signals=baseline_signals,
        semantic_doc=semantic_doc,
        baseline_score=baseline_score,
        enrichment_plan=enrichment_plan,
        result=result,
    )
    (out / "audit_chain.json").write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
    (out / "audit_chain.md").write_text(to_markdown(audit), encoding="utf-8")

    _emit(
        event_hook,
        "stage_completed",
        {
            "stage": "final_report",
            "risk_score": current_score.get("risk_score"),
            "confidence_score": current_score.get("confidence_score"),
            "verdict": current_score.get("verdict"),
        },
    )
    _emit(
        event_hook,
        "pipeline_completed",
        {
            "case_id": result.get("case_id"),
            "agent_invoked": result.get("agent_invoked"),
            "stop_reason": result.get("stop_reason"),
            "risk_score": current_score.get("risk_score"),
            "confidence_score": current_score.get("confidence_score"),
            "verdict": current_score.get("verdict"),
            "used_enrichment_steps": result.get("budgets", {}).get("used_enrichment_steps"),
        },
    )

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Run full phishing investigation pipeline with deterministic enrichment loop.")
    parser.add_argument("--eml", required=True, help="Path to .eml input")
    parser.add_argument("--out-dir", required=True, help="Directory for generated artifacts")
    parser.add_argument("--mode", default=os.getenv("INVESTIGATION_MODE", "mock"), choices=["mock", "live"], help="Investigation mode")
    args = parser.parse_args()

    result = run_pipeline(eml_path=args.eml, out_dir=args.out_dir, mode=args.mode)
    print(json.dumps({
        "case_id": result.get("case_id"),
        "agent_invoked": result.get("agent_invoked"),
        "stop_reason": result.get("stop_reason"),
        "risk_score": result.get("final_score", {}).get("risk_score"),
        "confidence_score": result.get("final_score", {}).get("confidence_score"),
        "verdict": result.get("final_score", {}).get("verdict"),
        "used_enrichment_steps": result.get("budgets", {}).get("used_enrichment_steps"),
    }, indent=2))


if __name__ == "__main__":
    main()
