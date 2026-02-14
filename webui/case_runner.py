#!/usr/bin/env python3
"""Background execution runner for investigation cases."""

from __future__ import annotations

import json
import threading
import uuid
from pathlib import Path
from typing import Any

from Investigation_Agent.env_utils import env_int, load_dotenv
from Investigation_Agent.investigation_pipeline import run_pipeline
from Investigation_Agent.llm_client import LLMClient

from webui.case_store import CaseStore
from webui.event_stream import EventHub
from webui.report_builder import build_web_report


class CaseRunner:
    """Runs full investigations asynchronously and updates case state."""

    def __init__(self, root_dir: str | Path, store: CaseStore, event_hub: EventHub) -> None:
        self.root_dir = Path(root_dir)
        self.store = store
        self.event_hub = event_hub

    def start_case(self, eml_path: str, filename: str, mode: str) -> str:
        case_id = f"case_{uuid.uuid4().hex[:12]}"
        self.store.create_case(case_id=case_id, filename=filename, eml_path=eml_path, run_mode=mode)

        thread = threading.Thread(
            target=self._run_case,
            args=(case_id, eml_path, mode),
            daemon=True,
            name=f"investigation-{case_id}",
        )
        thread.start()
        return case_id

    def _run_case(self, case_id: str, eml_path: str, mode: str) -> None:
        out_dir = self.root_dir / "webui" / "data" / "cases" / case_id
        out_dir.mkdir(parents=True, exist_ok=True)

        self.store.mark_running(case_id)

        def event_hook(event: str, payload: dict[str, Any]) -> None:
            self.store.add_event(case_id, event, payload)
            self.event_hub.publish(case_id=case_id, event=event, payload=payload)
            if event == "pipeline_started":
                self.store.add_runtime_message(case_id, f"Pipeline started ({payload.get('mode')}).")
                return

            if event == "stage_started":
                stage = str(payload.get("stage") or "")
                if stage:
                    self.store.update_stage_state(case_id, stage=stage, state="running", message=f"{stage} started")
                return

            if event == "stage_completed":
                stage = str(payload.get("stage") or "")
                detail = ""
                if stage == "normalize_envelope":
                    subject = str(payload.get("subject") or "").strip()
                    if subject:
                        self.store.set_subject_line(case_id, subject)
                if stage == "baseline_scoring":
                    detail = (
                        f"risk={payload.get('risk_score')} confidence={payload.get('confidence_score')} "
                        f"verdict={payload.get('verdict')}"
                    )
                if stage == "enrich_signals":
                    detail = (
                        f"stop={payload.get('stop_reason')} "
                        f"steps={payload.get('used_enrichment_steps')} tool_calls={payload.get('used_tool_calls')}"
                    )
                message = f"{stage} completed" + (f" ({detail})" if detail else "")
                if stage:
                    self.store.update_stage_state(case_id, stage=stage, state="done", message=message)
                return

            if event == "enrichment_started":
                alias = payload.get("tool_alias") or "unknown_tool"
                self.store.add_runtime_message(case_id, f"Enrichment started: {alias}")
                return

            if event == "enrichment_completed":
                alias = payload.get("tool_alias") or "unknown_tool"
                self.store.add_runtime_message(
                    case_id,
                    f"Enrichment completed: {alias} (verdict={payload.get('verdict')}, risk={payload.get('risk_score')})",
                )
                return

            if event == "pipeline_completed":
                self.store.add_runtime_message(case_id, "Pipeline completed.")

        try:
            load_dotenv(str(self.root_dir / ".env"))
            result = run_pipeline(
                eml_path=eml_path,
                out_dir=str(out_dir),
                mode=mode,
                event_hook=event_hook,
            )

            envelope_path = out_dir / "envelope.json"
            if not envelope_path.exists():
                raise RuntimeError("Expected envelope artifact not found")
            envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
            if not isinstance(envelope, dict):
                raise RuntimeError("Envelope artifact is not a JSON object")
            subject_from_envelope = str((envelope.get("message_metadata", {}) or {}).get("subject") or "").strip()
            if subject_from_envelope:
                self.store.set_subject_line(case_id, subject_from_envelope)

            llm = LLMClient(timeout_seconds=env_int("OPENAI_TIMEOUT_SECONDS", 60))
            web_report = build_web_report(envelope=envelope, result=result, llm=llm)
            self.store.mark_complete(
                case_id=case_id,
                artifacts_dir=str(out_dir),
                result_doc=result,
                web_report_doc=web_report,
            )
            completion_payload = {
                "status": "complete",
                "case_id": case_id,
                "verdict": (result.get("final_score") or {}).get("verdict"),
                "risk_score": (result.get("final_score") or {}).get("risk_score"),
                "confidence_score": (result.get("final_score") or {}).get("confidence_score"),
            }
            self.store.add_event(case_id, "case_completed", completion_payload)
            self.event_hub.publish(case_id=case_id, event="case_completed", payload=completion_payload)
        except Exception as exc:
            self.store.mark_failed(case_id=case_id, error=str(exc))
            failure_payload = {"status": "failed", "case_id": case_id, "error": str(exc)}
            self.store.add_event(case_id, "case_failed", failure_payload)
            self.event_hub.publish(case_id=case_id, event="case_failed", payload=failure_payload)
