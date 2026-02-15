# Local Web UI Pipeline (Docker)

## Purpose
Provide a local, Dockerized phishing triage UI with:
- `.eml` drag/drop intake,
- live investigation stage streaming,
- concise analyst report,
- persistent case queue.

Primary files:
- `webui/app.py`
- `webui/case_store.py`
- `webui/case_runner.py`
- `webui/event_stream.py`
- `webui/report_builder.py`
- `webui/frontend/src/App.jsx`
- `webui/frontend/src/main.jsx`
- `webui/frontend/src/index.css`
- `webui/frontend/vite.config.js`
- `webui/frontend/package.json`
- `Dockerfile`
- `docker-compose.yml`

## Inputs
- Upload: `.eml` only.
- Mode: `mock` or `live`.
- Environment:
  - `OPENAI_API_KEY` (optional but recommended)
  - `OPENAI_MODEL` (optional)
  - `INVESTIGATION_MODE`
  - `WEBUI_MAX_UPLOAD_MB` (default `30`)

## Outputs
Persisted:
- SQLite case DB: `webui/data/cases.db`
- uploads: `webui/data/uploads/*.eml`
- per-case artifacts: `webui/data/cases/<case_id>/...`

Runtime/UI:
- live stage updates over SSE,
- case queue items labeled by parsed email subject,
- React JSX SPA served by FastAPI from `webui/frontend/dist`,
- production-style split layout:
  - header with persistent `New Analysis` action,
  - left content area for upload/progress/report,
  - right sticky case queue panel,
- upload/progress views:
  - premium `.eml` dropzone and browse action,
  - investigation mode selector (`mock` / `live`),
  - animated progress card with stage rows + runtime log stream,
- report sections:
  - report hero with animated risk ring, sender/date/confidence metadata row, timestamp, verdict badge, and threat-tag chips,
  - 2-sentence AI summary and 3 key findings,
  - subject and body assessment cards with green/yellow/red overlays,
  - suspicious snippet preview block (shown only when suspicious/malicious text excerpts are actually detected),
  - optional `View Detailed Review` popup with semantic findings + snippet evidence sandbox blocks,
  - `Indicators of Compromise` card grid,
  - grouped IOC modal drill-down (sender/legitimate/suspicious domain groupings when available),
  - `Evidence Drivers` list (key findings + semantic drivers),
  - analyst decision controls (`benign`, `suspicious`, `escalate`) + optional note.

## Execution Flow
1. User uploads `.eml`.
2. `POST /api/cases` saves file and creates queued case.
3. Background runner executes full pipeline with event hook.
4. `CaseStore` tracks stage state and runtime messages.
5. On completion, report builder generates UI report JSON.
6. Frontend subscribes to SSE (`/api/cases/{case_id}/events`) for live updates.
7. Completed/failed cases remain in queue for replay.

## API Surface
- `GET /api/config`
- `GET /api/cases`
- `GET /api/cases/{case_id}`
- `GET /api/cases/{case_id}/events`
- `POST /api/cases`
- `POST /api/cases/{case_id}/analyst-decision`

## Stage Model
Tracked stages:
- `load_configs`
- `normalize_envelope`
- `baseline_scoring`
- `enrich_signals`
- `final_report`

Per-tool enrichment runtime messages are emitted from:
- `enrichment_started`
- `enrichment_completed`

## Report Data Contract (UI)
`web_report` includes:
- `classification`, `result_heading`, `analyst_summary`, `key_points`
- `primary_threat_tag`, `threat_tags[]` (single primary-tag record for UI badge rendering)
- `ioc_items`, `urls_clean_note`
- `subject_line`, `sender_address`, `sender_domain`
- `subject_level`, `subject_analysis`
- `body_level`, `body_analysis`, `body_preview`, `body_plain`
- `analysis_details[]` for subject/body semantic review modal
- `analysis_snippets[]` for suspicious snippet rendering
- `evidence_highlights[]` for concise evidence drivers
- `indicator_panels[]` (URLs/Domains/IPs/Attachments), each with:
  - `id`, `label`, `title`, `level`, `summary`
  - `items[]` (`value`, `display_value`, `outcome`, `description`, `semantic_override`)
  - optional `groups[]` (`id`, `title`, `summary`, `items[]`) for grouped modal rendering
  - `empty_note`

Indicator panel levels:
- `red` = malicious evidence present,
- `yellow` = suspicious/review evidence,
- `green` = appears benign,
- `neutral` = empty attachment state (`No attachments found`).
- Domain panel level is derived from rendered domain item outcomes (to prevent parent-card severity from contradicting child IOC outcomes).

Semantic override rule in Web UI report generation:
- Semantic overrides are targeted (for example sender-domain deception and URL-intent mismatch) instead of blanket elevation across all IOCs.
- Clean IOCs remain clean unless a specific semantic/context signal applies to that IOC.

Subject/body rendering guardrails:
- `subject_analysis` is constrained to subject-line wording only (no IOC/domain/header spillover).
- `body_analysis` is constrained to body-language assessment only (no IOC/domain/header spillover).
- For authenticated marketing patterns (auth pass + mailing-list/ESP context), report copy prefers benign-language defaults unless stronger phishing evidence exists.
- In authenticated marketing contexts, key-point generation suppresses obfuscated tracking-link phrasing and de-duplicates overlapping findings (for example, urgency wording repeated between key findings and semantic highlights).
- LLM summary/key-point lines that conflict with deterministic evidence (for example unwarranted lookalike/hidden-CSS claims, or “no sending IP” when IPs were extracted) are replaced by deterministic fallback copy.
- IP panel summary is deterministic and tied to extracted sender-IP evidence to prevent contradictory messaging.

Case records also include:
- `analyst_decision` (`undecided|benign|suspicious|escalate`)
- `analyst_note`
- `analyst_updated_at`

## Operational Limits
- only `.eml` uploads
- max upload defaults to 30MB
- single-process threaded execution
- SSE fanout is in-memory (single-container scope)
- if LLM unavailable, deterministic fallback report copy is used

## Docker
Run:
```bash
docker compose up --build
```

Build behavior:
- Docker multi-stage build compiles React frontend (`webui/frontend`) with Node,
- FastAPI serves compiled assets from `webui/frontend/dist`.

Open:
- `http://localhost:8080`

Stop:
```bash
docker compose down
```
