#!/usr/bin/env python3
"""Persistent SQLite store for Web UI investigation cases."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STAGE_ORDER = [
    ("load_configs", "Load configuration"),
    ("normalize_envelope", "Normalize envelope"),
    ("baseline_scoring", "Baseline scoring"),
    ("enrich_signals", "Deterministic enrichment"),
    ("final_report", "Final report"),
]

ALLOWED_ANALYST_DECISIONS = {"undecided", "benign", "suspicious", "escalate"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class CaseStore:
    """SQLite-backed storage for case queue, runtime state, and final artifacts."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                  case_id TEXT PRIMARY KEY,
                  filename TEXT NOT NULL,
                  subject_line TEXT,
                  eml_path TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  status TEXT NOT NULL,
                  run_mode TEXT NOT NULL,
                  stage TEXT,
                  runtime_json TEXT NOT NULL,
                  artifacts_dir TEXT,
                  stop_reason TEXT,
                  verdict TEXT,
                  risk_score REAL,
                  confidence_score REAL,
                  analyst_decision TEXT,
                  analyst_note TEXT,
                  analyst_updated_at TEXT,
                  error TEXT,
                  result_json TEXT,
                  web_report_json TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS case_events (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  case_id TEXT NOT NULL,
                  timestamp TEXT NOT NULL,
                  event TEXT NOT NULL,
                  payload_json TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_case ON case_events(case_id, id DESC)")
            self._ensure_columns(conn)

    def _ensure_columns(self, conn: sqlite3.Connection) -> None:
        columns = {str(r["name"]) for r in conn.execute("PRAGMA table_info(cases)").fetchall()}
        if "subject_line" not in columns:
            conn.execute("ALTER TABLE cases ADD COLUMN subject_line TEXT")
        if "analyst_decision" not in columns:
            conn.execute("ALTER TABLE cases ADD COLUMN analyst_decision TEXT")
        if "analyst_note" not in columns:
            conn.execute("ALTER TABLE cases ADD COLUMN analyst_note TEXT")
        if "analyst_updated_at" not in columns:
            conn.execute("ALTER TABLE cases ADD COLUMN analyst_updated_at TEXT")

    @staticmethod
    def default_runtime() -> dict[str, Any]:
        return {
            "stages": [
                {"id": stage_id, "label": label, "state": "pending"}
                for stage_id, label in STAGE_ORDER
            ],
            "messages": [],
            "current_stage": None,
            "started_at": _now_iso(),
            "completed_at": None,
        }

    def create_case(self, case_id: str, filename: str, eml_path: str, run_mode: str) -> None:
        now = _now_iso()
        runtime = self.default_runtime()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO cases (
                  case_id, filename, eml_path, created_at, updated_at, status,
                  run_mode, stage, runtime_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    filename,
                    eml_path,
                    now,
                    now,
                    "queued",
                    run_mode,
                    None,
                    json.dumps(runtime),
                ),
            )

    def add_event(self, case_id: str, event: str, payload: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO case_events(case_id, timestamp, event, payload_json) VALUES (?, ?, ?, ?)",
                (case_id, _now_iso(), event, json.dumps(payload)),
            )

    def set_subject_line(self, case_id: str, subject_line: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE cases SET subject_line=?, updated_at=? WHERE case_id=?",
                (subject_line.strip()[:240], _now_iso(), case_id),
            )

    def set_analyst_decision(self, case_id: str, decision: str, note: str | None = None) -> None:
        choice = str(decision or "").strip().lower()
        if choice not in ALLOWED_ANALYST_DECISIONS:
            raise ValueError(f"Invalid analyst decision: {decision}")
        now = _now_iso()
        cleaned_note = str(note or "").strip()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE cases
                SET analyst_decision=?, analyst_note=?, analyst_updated_at=?, updated_at=?
                WHERE case_id=?
                """,
                (choice, cleaned_note[:600], now, now, case_id),
            )

    def _fetch_runtime(self, conn: sqlite3.Connection, case_id: str) -> dict[str, Any]:
        row = conn.execute("SELECT runtime_json FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if not row:
            raise KeyError(f"Unknown case_id: {case_id}")
        try:
            parsed = json.loads(row["runtime_json"])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
        return self.default_runtime()

    def mark_running(self, case_id: str) -> None:
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                "UPDATE cases SET status=?, updated_at=? WHERE case_id=?",
                ("running", now, case_id),
            )

    def update_stage_state(
        self,
        case_id: str,
        stage: str,
        state: str,
        message: str | None = None,
    ) -> None:
        now = _now_iso()
        with self._connect() as conn:
            runtime = self._fetch_runtime(conn, case_id)
            stages = runtime.get("stages", [])
            for item in stages:
                if item.get("id") == stage:
                    item["state"] = state
                    break
            runtime["stages"] = stages
            runtime["current_stage"] = stage if state == "running" else runtime.get("current_stage")
            if message:
                messages = runtime.get("messages", [])
                messages.append({"timestamp": now, "text": message})
                runtime["messages"] = messages[-40:]

            conn.execute(
                "UPDATE cases SET stage=?, runtime_json=?, updated_at=? WHERE case_id=?",
                (stage, json.dumps(runtime), now, case_id),
            )

    def add_runtime_message(self, case_id: str, message: str) -> None:
        now = _now_iso()
        with self._connect() as conn:
            runtime = self._fetch_runtime(conn, case_id)
            messages = runtime.get("messages", [])
            messages.append({"timestamp": now, "text": message})
            runtime["messages"] = messages[-40:]
            conn.execute(
                "UPDATE cases SET runtime_json=?, updated_at=? WHERE case_id=?",
                (json.dumps(runtime), now, case_id),
            )

    def mark_complete(
        self,
        case_id: str,
        artifacts_dir: str,
        result_doc: dict[str, Any],
        web_report_doc: dict[str, Any],
    ) -> None:
        now = _now_iso()
        final_score = result_doc.get("final_score", {})
        with self._connect() as conn:
            runtime = self._fetch_runtime(conn, case_id)
            runtime["completed_at"] = now
            for stage in runtime.get("stages", []):
                if stage.get("state") != "done":
                    stage["state"] = "done"
            conn.execute(
                """
                UPDATE cases
                SET status=?, updated_at=?, stage=?, runtime_json=?, artifacts_dir=?,
                    stop_reason=?, verdict=?, risk_score=?, confidence_score=?,
                    result_json=?, web_report_json=?
                WHERE case_id=?
                """,
                (
                    "complete",
                    now,
                    "final_report",
                    json.dumps(runtime),
                    artifacts_dir,
                    result_doc.get("stop_reason"),
                    final_score.get("verdict"),
                    final_score.get("risk_score"),
                    final_score.get("confidence_score"),
                    json.dumps(result_doc),
                    json.dumps(web_report_doc),
                    case_id,
                ),
            )

    def mark_failed(self, case_id: str, error: str) -> None:
        now = _now_iso()
        with self._connect() as conn:
            runtime = self._fetch_runtime(conn, case_id)
            runtime["completed_at"] = now
            messages = runtime.get("messages", [])
            messages.append({"timestamp": now, "text": f"Run failed: {error}"})
            runtime["messages"] = messages[-40:]
            conn.execute(
                "UPDATE cases SET status=?, updated_at=?, error=?, runtime_json=? WHERE case_id=?",
                ("failed", now, error, json.dumps(runtime), case_id),
            )

    @staticmethod
    def _as_summary(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "case_id": row["case_id"],
            "filename": row["filename"],
            "subject_line": row["subject_line"],
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "verdict": row["verdict"],
            "risk_score": row["risk_score"],
            "confidence_score": row["confidence_score"],
            "analyst_decision": row["analyst_decision"] or "undecided",
            "analyst_note": row["analyst_note"] or "",
            "analyst_updated_at": row["analyst_updated_at"],
            "stop_reason": row["stop_reason"],
            "error": row["error"],
        }

    def list_cases(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT case_id, filename, subject_line, status, created_at, updated_at,
                       verdict, risk_score, confidence_score,
                       analyst_decision, analyst_note, analyst_updated_at,
                       stop_reason, error
                FROM cases
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._as_summary(row) for row in rows]

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT case_id, filename, subject_line, eml_path, created_at, updated_at, status,
                       run_mode, stage, runtime_json, artifacts_dir, stop_reason,
                       verdict, risk_score, confidence_score,
                       analyst_decision, analyst_note, analyst_updated_at,
                       error, result_json, web_report_json
                FROM cases
                WHERE case_id=?
                """,
                (case_id,),
            ).fetchone()
            if not row:
                return None

            events = conn.execute(
                """
                SELECT timestamp, event, payload_json
                FROM case_events
                WHERE case_id=?
                ORDER BY id DESC
                LIMIT 60
                """,
                (case_id,),
            ).fetchall()

        runtime = self.default_runtime()
        try:
            runtime_parsed = json.loads(row["runtime_json"])
            if isinstance(runtime_parsed, dict):
                runtime = runtime_parsed
        except json.JSONDecodeError:
            pass

        result_doc: dict[str, Any] | None = None
        web_report_doc: dict[str, Any] | None = None
        if row["result_json"]:
            try:
                parsed = json.loads(row["result_json"])
                if isinstance(parsed, dict):
                    result_doc = parsed
            except json.JSONDecodeError:
                result_doc = None
        if row["web_report_json"]:
            try:
                parsed = json.loads(row["web_report_json"])
                if isinstance(parsed, dict):
                    web_report_doc = parsed
            except json.JSONDecodeError:
                web_report_doc = None

        event_list = []
        for ev in events:
            payload: dict[str, Any] = {}
            try:
                parsed_payload = json.loads(ev["payload_json"])
                if isinstance(parsed_payload, dict):
                    payload = parsed_payload
            except json.JSONDecodeError:
                payload = {}
            event_list.append(
                {
                    "timestamp": ev["timestamp"],
                    "event": ev["event"],
                    "payload": payload,
                }
            )

        return {
            "case_id": row["case_id"],
            "filename": row["filename"],
            "subject_line": row["subject_line"],
            "eml_path": row["eml_path"],
            "status": row["status"],
            "run_mode": row["run_mode"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "stage": row["stage"],
            "runtime": runtime,
            "artifacts_dir": row["artifacts_dir"],
            "stop_reason": row["stop_reason"],
            "verdict": row["verdict"],
            "risk_score": row["risk_score"],
            "confidence_score": row["confidence_score"],
            "analyst_decision": row["analyst_decision"] or "undecided",
            "analyst_note": row["analyst_note"] or "",
            "analyst_updated_at": row["analyst_updated_at"],
            "error": row["error"],
            "result": result_doc,
            "web_report": web_report_doc,
            "events": event_list,
        }
