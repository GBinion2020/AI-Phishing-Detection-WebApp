# Investigation Agent Pipeline

## Purpose
Run bounded phishing investigation after normalization and baseline scoring, without playbooks.

Implementation files:
- `/Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Investigation_Agent/investigation_pipeline.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Investigation_Agent/llm_client.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Investigation_Agent/audit_chain.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Investigation_Agent/prompt_templates.py`

## Pipeline Stages
1. Build envelope from `.eml`.
2. Generate baseline deterministic and semantic signals (`signals.baseline.json`).
3. Score baseline risk/confidence (`score.baseline.json`).
4. Build deterministic enrichment plan from unknown non-deterministic signals (`enrichment.plan.json`).
5. Execute bounded enrichment-tool loop.
6. Recompute score after each enrichment iteration.
7. Produce final signals, score, report, and audit chain.

## Playbook Deprecation
Playbook planning and adaptive playbook selection are deprecated in orchestration.

Current orchestration behavior:
- no candidate-playbook stage,
- no LLM planner,
- no LLM signal-update stage,
- direct deterministic execution of enrichment tools mapped to unresolved non-deterministic signals.

## Deterministic Enrichment Strategy
Enrichment tools are selected from non-deterministic rule requirements:
- take only signals with `kind=non_deterministic` and `value=unknown`,
- skip `semantic.*` LLM-assessor-only signals,
- map required tools into an ordered allowlist,
- execute with bounded budgets.

Budgets:
- `INVESTIGATION_MAX_ENRICHMENT_STEPS` (fallback to legacy `INVESTIGATION_MAX_PLAYBOOKS`)
- `INVESTIGATION_MAX_TOOL_CALLS`

## Stop Conditions
The enrichment loop stops when first condition is met:
- confidence gate satisfied (`agent_gate.invoke_agent == false`),
- max enrichment steps reached,
- max tool-call budget reached,
- no enrichment candidates.

## LLM Responsibilities
LLM is constrained to:
- semantic signal assessment over controlled evidence envelope,
- concise final narrative generation.

LLM is not allowed to:
- execute tools,
- alter deterministic signal outputs directly,
- set final verdict directly.

Deterministic scorer remains verdict authority.

## Artifacts
Generated under run directory (`--out-dir`):
- `envelope.json`
- `evidence.controlled.json`
- `semantic_assessment.json`
- `signals.baseline.json`
- `score.baseline.json`
- `enrichment.plan.json`
- `signals.final.json`
- `score.final.json`
- `report.final.json`
- `investigation_result.json`
- `audit_chain.json`
- `audit_chain.md`

## Event Hook Interface
`run_pipeline(...)` supports optional `event_hook(event_name, payload)` callback.

Emitted events:
- `pipeline_started`
- `stage_started`
- `stage_completed`
- `enrichment_started`
- `enrichment_completed`
- `pipeline_completed`

## Modes
- `mock`: seeds mock enrichment outputs and routes through cache-backed MCP router.
- `live`: performs live provider calls when configured in MCP router.

## CLI Example
```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Investigation_Agent/investigation_pipeline.py \
  --eml /Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Sample_Emails/Sample_Email.eml \
  --out-dir /Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Sample_Emails/Case_Run_001 \
  --mode mock
```
