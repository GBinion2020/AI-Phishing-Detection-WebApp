#!/usr/bin/env python3
"""Local Web UI for phishing investigations."""

from __future__ import annotations

import asyncio
import json
import os
import re
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from webui.case_runner import CaseRunner
from webui.event_stream import EventHub
from webui.case_store import CaseStore


ROOT = Path(__file__).resolve().parents[1]
WEBUI_DIR = ROOT / "webui"
FRONTEND_DIST = WEBUI_DIR / "frontend" / "dist"
DATA_DIR = WEBUI_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
CASES_DIR = DATA_DIR / "cases"
DB_PATH = DATA_DIR / "cases.db"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
CASES_DIR.mkdir(parents=True, exist_ok=True)

store = CaseStore(DB_PATH)
event_hub = EventHub()
runner = CaseRunner(root_dir=ROOT, store=store, event_hub=event_hub)

app = FastAPI(title="Phishing Triage Local Web UI", version="1.0")
if (FRONTEND_DIST / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")


SAFE_FILE_RE = re.compile(r"[^a-zA-Z0-9._-]+")
MAX_UPLOAD_BYTES = int(os.getenv("WEBUI_MAX_UPLOAD_MB", "30")) * 1024 * 1024
DEFAULT_MODE = os.getenv("INVESTIGATION_MODE", "mock")


class AnalystDecisionRequest(BaseModel):
    decision: str = Field(min_length=3, max_length=24)
    note: str = Field(default="", max_length=600)


def _safe_filename(raw_name: str) -> str:
    cleaned = SAFE_FILE_RE.sub("_", raw_name).strip("._")
    if not cleaned:
        cleaned = "message.eml"
    if not cleaned.lower().endswith(".eml"):
        cleaned += ".eml"
    return cleaned[:120]


def _format_sse(data: dict, event: str | None = None) -> str:
    lines: list[str] = []
    if event:
        lines.append(f"event: {event}")
    lines.append(f"data: {json.dumps(data)}")
    return "\n".join(lines) + "\n\n"


@app.on_event("startup")
async def on_startup() -> None:
    event_hub.set_loop(asyncio.get_running_loop())


@app.get("/", response_class=HTMLResponse)
async def index() -> Response:
    index_file = FRONTEND_DIST / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse(
        "<h1>Frontend build not found</h1>"
        "<p>Build React UI with: <code>cd webui/frontend && npm install && npm run build</code>.</p>",
        status_code=503,
    )


@app.get("/api/config")
def get_config() -> JSONResponse:
    return JSONResponse(
        {
            "app_name": "Phishing Triage",
            "default_mode": DEFAULT_MODE,
            "max_upload_mb": int(MAX_UPLOAD_BYTES / (1024 * 1024)),
        }
    )


@app.get("/api/cases")
def list_cases() -> JSONResponse:
    return JSONResponse({"cases": store.list_cases(limit=200)})


@app.get("/api/cases/{case_id}")
def get_case(case_id: str) -> JSONResponse:
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return JSONResponse(case)


@app.post("/api/cases/{case_id}/analyst-decision")
def set_analyst_decision(case_id: str, payload: AnalystDecisionRequest) -> JSONResponse:
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")

    try:
        store.set_analyst_decision(case_id=case_id, decision=payload.decision, note=payload.note)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    updated = store.get_case(case_id)
    if updated is None:
        raise HTTPException(status_code=404, detail="Case not found")

    event_payload = {
        "case_id": case_id,
        "analyst_decision": updated.get("analyst_decision"),
        "analyst_note": updated.get("analyst_note"),
        "analyst_updated_at": updated.get("analyst_updated_at"),
    }
    store.add_event(case_id=case_id, event="analyst_decision_updated", payload=event_payload)
    event_hub.publish(case_id=case_id, event="analyst_decision_updated", payload=event_payload)
    return JSONResponse({"ok": True, "case": updated})


@app.get("/api/cases/{case_id}/events")
async def stream_case_events(case_id: str) -> StreamingResponse:
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")

    queue = event_hub.subscribe(case_id)

    async def generator():
        try:
            # Initial state snapshot allows instant render without waiting for new events.
            snapshot = store.get_case(case_id)
            if snapshot is not None:
                yield _format_sse({"case": snapshot}, event="snapshot")

            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=25.0)
                    yield _format_sse(msg, event="case_event")
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            event_hub.unsubscribe(case_id, queue)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/cases")
async def create_case(
    file: UploadFile = File(...),
    mode: str = Form(DEFAULT_MODE),
) -> JSONResponse:
    filename = file.filename or "message.eml"
    if not filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted")

    selected_mode = mode if mode in {"mock", "live"} else DEFAULT_MODE
    safe_name = _safe_filename(filename)
    upload_name = f"{uuid.uuid4().hex[:10]}_{safe_name}"
    upload_path = UPLOAD_DIR / upload_name

    total_bytes = 0
    try:
        with upload_path.open("wb") as out_f:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds max upload size ({int(MAX_UPLOAD_BYTES / (1024 * 1024))} MB)",
                    )
                out_f.write(chunk)
    except HTTPException:
        upload_path.unlink(missing_ok=True)
        raise
    except Exception as exc:
        upload_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Failed to save upload: {exc}") from exc
    finally:
        await file.close()

    case_id = runner.start_case(eml_path=str(upload_path), filename=safe_name, mode=selected_mode)
    return JSONResponse(
        {
            "case_id": case_id,
            "status": "queued",
            "filename": safe_name,
            "mode": selected_mode,
        },
        status_code=202,
    )


@app.get("/{full_path:path}")
async def frontend_spa_fallback(full_path: str) -> Response:
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Not found")

    requested = FRONTEND_DIST / full_path
    if requested.exists() and requested.is_file():
        return FileResponse(requested)

    index_file = FRONTEND_DIST / "index.html"
    if index_file.exists():
        return FileResponse(index_file)

    return HTMLResponse("Frontend build not found", status_code=503)
