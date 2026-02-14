# Near-Edge Gmail Flow (Option 3) Implementation Plan

## Scope
Design and stage implementation for a near-edge phishing triage flow:
1. Run deterministic QUICK scoring at email-open time.
2. If QUICK is borderline (Yellow), call a small Tier 1.5 remote classifier with minimal payload.
3. Escalate to existing FULL pipeline only when Red (or explicit user action).
4. Cache aggressively to avoid recomputation on repeated opens.

This document is implementation-first and codebase-specific. It does not change the existing FULL pipeline behavior.

## Current Pipeline Mapping (Repository Discovery)
### CLI and orchestration entrypoints
- CLI entrypoint: `cli/phishscan.py`
- CLI service wrapper: `Investigation_Agent/pipeline_service.py`
- Full pipeline orchestrator: `Investigation_Agent/investigation_pipeline.py`

### Existing internal artifacts
- Envelope creation:
  - Builder: `src/Ingestion/intake.py::build_envelope(...)`
  - Artifact: `envelope.json`
- Signals creation:
  - Engine: `Signal_Engine/signal_engine.py::run_signal_engine(...)`
  - Artifacts: `signals.baseline.json`, `signals.final.json`
- Deterministic scoring/verdict:
  - Engine: `Scoring_Engine/scoring_engine.py::score_signals(...)`
  - Artifacts: `score.baseline.json`, `score.final.json`
- Final run output:
  - Artifact: `investigation_result.json` with `final_signals`, `final_score`, `final_report`, `stop_reason`

### Stable input object for near-edge QUICK mode
Use existing normalized envelope object from `build_envelope(...)` as QUICK input:
- `message_metadata` (From/Reply-To/Return-Path/Subject/Date/Message-ID/headers/received_chain)
- `auth_summary` (SPF/DKIM/DMARC extraction)
- `entities` (URLs/domains/emails/IPs)
- `attachments` and `mime_parts.body_extraction`

No external tools are required for this object.

## Target Architecture (New Modules)
Add a new package tree at repo root:

```text
NearEdge/
  adapters/
    interfaces.py
    cli_adapter.py
  quick_score/
    engine.py
    config_loader.py
    models.py
    quick_score_config.yaml
  edge_classifier/
    models.py
    payload_builder.py
    client.py
    transport_http.py
  caching/
    interfaces.py
    keys.py
    sqlite_cache.py
    policy.py
  orchestrator.py
```

Design intent by module:
- `quick_score/`: deterministic-only feature extraction + weighted scoring + capped categories + diminishing returns.
- `edge_classifier/`: minimal payload schema + client interface + timeout/retry/offline behavior + response schema validation.
- `caching/`: message/thread/entity cache interfaces and local SQLite backend, with versioned keys and TTL policies.
- `adapters/`: neutral interfaces so same orchestration can run from CLI now and API/MCP later.
- `orchestrator.py`: near-edge decision flow and stop-reason logging.

## Data Contracts
All outputs are JSON-serializable dicts with explicit `schema_version`.

### A) QUICK score output schema
```json
{
  "schema_version": "1.0",
  "pipeline_version": "near_edge_v1",
  "case_id": "uuid-or-message-id",
  "generated_at": "ISO-8601",
  "quick_score": 0,
  "quick_verdict": "green",
  "top_reasons": [
    {
      "signal_id": "auth.dmarc_fail",
      "weight": 20.0,
      "category": "auth",
      "reason": "DMARC fail present in Authentication-Results"
    }
  ],
  "evidence_refs": ["auth_summary.dmarc.evidence_id"],
  "metrics": {
    "triggered_signals": 0,
    "category_totals": {
      "identity": 0.0,
      "auth": 0.0,
      "url": 0.0,
      "attachment": 0.0,
      "header": 0.0,
      "content": 0.0
    }
  }
}
```

### B) Tier 1.5 payload schema (minimal by design)
```json
{
  "schema_version": "1.0",
  "pipeline_version": "near_edge_v1",
  "message_context": {
    "user_id": "opaque-user-id",
    "message_id": "<...>",
    "thread_id": "optional",
    "timestamp": "ISO-8601"
  },
  "headers": {
    "from": "...",
    "reply_to": "...",
    "return_path": "...",
    "subject": "...",
    "date": "...",
    "message_id": "...",
    "authentication_results": "...",
    "received_summary": ["hop summary 1", "hop summary 2"]
  },
  "urls": [
    {
      "normalized": "https://example.com/path",
      "domain": "example.com"
    }
  ],
  "attachments": [
    {
      "filename": "invoice.html",
      "content_type": "text/html",
      "size_bytes": 1024,
      "hashes": {
        "sha256": "..."
      }
    }
  ],
  "snippet": {
    "text": "first N chars, redacted",
    "redaction_applied": true
  }
}
```

Rules:
- URL list deduplicated and capped at 10.
- No full body by default.
- Snippet optional, capped, and redacted.
- Attachments include metadata only.

### C) Tier 1.5 response schema
```json
{
  "schema_version": "1.0",
  "provider": "tier15_classifier",
  "model": "small-safe-classifier",
  "generated_at": "ISO-8601",
  "refined_score": 0,
  "refined_verdict": "green",
  "top_reasons": [
    {
      "code": "reply_to_discrepancy",
      "reason": "From/Reply-To pattern resembles known phishing clusters"
    }
  ]
}
```

## QUICK Scoring Semantics
QUICK score remains deterministic and local:
- Input: existing envelope only.
- Output bands (default):
  - Green: `0-29`
  - Yellow: `30-64`
  - Red: `65-100`

### Category caps and diminishing returns
- Category caps (initial defaults):
  - `identity`: 20
  - `auth`: 30
  - `url`: 25
  - `attachment`: 20
  - `header`: 15
  - `content`: 10
- Diminishing returns:
  - Highest-weight signal in category = 100% weight.
  - Second = 60%.
  - Third+ = 35%.
- Hard clamp final score to `[0, 100]`.

This prevents inflation when many correlated signals fire.

### Tunable config file
Create `NearEdge/quick_score/quick_score_config.yaml` with:
- thresholds
- per-signal base weights
- category caps
- diminishing factors
- allowlist/denylist toggles

No code change required to tune weights.

## Cache Architecture
Introduce backend-agnostic cache interfaces, then implement SQLite first.

### Key strategy
- Message cache key:
  - `msg:{user_id}:{message_id}:{pipeline_version}`
- Thread cache key (optional):
  - `thr:{user_id}:{thread_id}:{pipeline_version}`
- Entity cache key:
  - `ent:{entity_type}:{normalized_value}:{pipeline_version}`

### Cache records
Common fields:
- `key`
- `value_json`
- `status` (`ok` | `negative` | `error`)
- `expires_at`
- `created_at`
- `updated_at`

### TTL recommendations
- QUICK score result: 24h
- Tier 1.5 classifier result: 6h
- Thread rollup: 1h
- Entity lookups: 24h
- Negative cache for remote failure/timeouts: 10m

### Versioning and invalidation
- Include `pipeline_version` in all keys.
- Bump version on scoring config/schema changes.
- Keep backward compatibility by reading only exact key matches.

## Near-Edge Orchestration Flow
`NearEdge/orchestrator.py` should support Gmail-open simulation with explicit stop reasons.

### Decision path
1. Check message cache.
2. Build envelope (or use supplied parsed envelope).
3. Run QUICK deterministic scorer.
4. If QUICK Green: stop (`stop_reason=quick_green`).
5. If QUICK Yellow:
   - If Tier 1.5 disabled/offline: stop (`stop_reason=yellow_no_classifier`).
   - Else call classifier with minimal payload.
   - If classifier Green/Yellow: stop (`stop_reason=classifier_non_red`).
   - If classifier Red: escalate to FULL (`stop_reason=escalated_full_after_classifier_red`).
6. If QUICK Red: escalate to FULL (`stop_reason=quick_red_escalate`).
7. If user forces full scan: escalate regardless (`stop_reason=user_forced_full`).

### Budget and telemetry fields
Emit a structured decision artifact, example:
```json
{
  "schema_version": "1.0",
  "pipeline_version": "near_edge_v1",
  "message_id": "<...>",
  "cache": {"message_hit": false, "thread_hit": false},
  "budget": {
    "quick_ms": 0,
    "classifier_ms": 0,
    "full_scan_ms": 0,
    "remote_calls": 0
  },
  "stages": {
    "quick": {"verdict": "yellow", "score": 41},
    "classifier": {"verdict": "red", "score": 71},
    "full": {"invoked": true}
  },
  "stop_reason": "escalated_full_after_classifier_red"
}
```

## Adapters (CLI now, API/MCP later)
Define small interfaces:
- `EnvelopeProvider`: resolve/build envelope from event input.
- `FullPipelineRunner`: invoke existing `PipelineService.execute(...)`.
- `EdgeClassifierClient`: invoke Tier 1.5 provider.
- `CacheStore`: get/set/delete with TTL and status.

CLI adapter uses local file paths and current pipeline service.
Future API/MCP adapter maps request payloads to same contracts.

## CLI Additions (Design Only)
Add a near-edge command/mode without removing current behavior.

Proposed options:
- `--open-event`: run near-edge orchestration.
- `--flow quick`: quick only.
- `--flow quick-plus`: quick + Tier 1.5 when yellow.
- `--flow escalate`: run full escalation logic.
- `--force-full`: bypass gating and call full pipeline.
- `--offline-classifier`: do not call remote classifier.

Expected emitted artifacts for open-event mode:
- `near_edge.quick.json`
- `near_edge.classifier.json` (only if called)
- `near_edge.decision.json`
- `investigation_result.json` (only if escalated full)

## Test Plan
### Unit tests: QUICK scoring
- Reply-To mismatch fires and impacts score.
- DMARC fail in parsed auth headers increases score.
- Suspicious URL patterns score and cap correctly.
- Suspicious attachment extensions score correctly.
- Category caps enforce upper bound.
- Diminishing returns reduce impact of additional same-category signals.

### Unit tests: cache behavior
- message key hit/miss behavior.
- version bump invalidates old key space.
- negative caching prevents repeated remote calls within TTL.

### Contract tests: Tier 1.5 payload
- payload includes only allowed fields.
- URL dedup + max-10 cap enforced.
- snippet redaction and max-length constraints enforced.
- response schema validation rejects malformed classifier output.

## Incremental Implementation Sequence
1. Add `NearEdge/` package skeleton and data models.
2. Implement QUICK scorer + config loader + tests.
3. Implement cache interfaces + SQLite backend + tests.
4. Implement Tier 1.5 payload builder + client interface + contract tests.
5. Implement orchestrator and stop-reason telemetry artifact.
6. Add CLI near-edge mode.
7. Validate demo run paths and document examples.

## Demo Run Examples (Target Behavior)
### QUICK only
```bash
python3 cli/phishscan.py --eml /abs/path/mail.eml --open-event --flow quick
```
Expected:
- `near_edge.quick.json` generated
- `near_edge.decision.json.stop_reason = "quick_green"` or `"quick_yellow_no_classifier"`
- no full pipeline run

### QUICK + Tier 1.5
```bash
python3 cli/phishscan.py --eml /abs/path/mail.eml --open-event --flow quick-plus
```
Expected:
- classifier called only when quick verdict is yellow
- `near_edge.classifier.json` present only for yellow cases
- stop reason reflects classifier outcome

### Escalation path
```bash
python3 cli/phishscan.py --eml /abs/path/mail.eml --open-event --flow escalate
```
Expected:
- full pipeline invoked only for quick red, classifier red, or force-full
- existing `investigation_result.json` unchanged in schema

