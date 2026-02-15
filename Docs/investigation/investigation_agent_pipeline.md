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
2. Generate baseline deterministic + unresolved non-deterministic signals (`signals.baseline.json`).
3. Score baseline risk/confidence (`score.baseline.json`).
4. Build deterministic enrichment plan from unknown non-deterministic signals (`enrichment.plan.json`).
5. Execute **baseline TI enrichment** (bounded, adaptive selection from high-value tools first).
6. Build TI-grounded controlled evidence and run semantic assessor (`semantic_assessment.json`).
7. Continue **adaptive deterministic enrichment** for remaining unknown non-deterministic signals.
8. Recompute deterministic score after each enrichment/semantic iteration.
9. Derive deterministic analyst-facing threat tags.
10. Produce final signals, score, report, and audit chain.

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
- deduplicate IOC payloads (URLs/domains/IPs/hashes) before tool routing,
- apply adaptive ranking by unresolved signal weight + payload availability + priority hints,
- execute with bounded budgets.

Provider fallback behavior:
- each tool alias can map to multiple providers,
- providers are attempted in order until one returns `status=ok` plus usable updates/confidence,
- failed/deferred providers do not terminate the full investigation.

Budgets:
- `INVESTIGATION_MAX_ENRICHMENT_STEPS` (fallback to legacy `INVESTIGATION_MAX_PLAYBOOKS`)
- `INVESTIGATION_MAX_TOOL_CALLS`

## Stop Conditions
The investigation stops when first condition is met:
- confidence gate satisfied (`agent_gate.invoke_agent == false`),
- definitive phish (`risk >= 85` and `confidence >= 0.85`),
- definitive benign (`risk <= 20` and `confidence >= 0.85`),
- confidence plateau (minimal gain across recent iterations),
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

Semantic timing:
- semantic assessment runs after baseline TI enrichment so prompts include factual TI context (`threat_intel_context`) and reduce shallow-pattern false positives.

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

`score.final.json` now also includes deterministic threat-tag outputs:
- `primary_threat_tag`
- `threat_tags[]` (id, label, severity, confidence, reasons)

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
- `mock` brand-lookalike behavior is conservative: it flags only confusable/IDN-style patterns (for example `paypa1`/`xn--`), not normal hyphenated marketing subdomains.
- `live`: performs live provider calls when configured in MCP router.

## CLI Example
```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Investigation_Agent/investigation_pipeline.py \
  --eml /Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Sample_Emails/Sample_Email.eml \
  --out-dir /Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Sample_Emails/Case_Run_001 \
  --mode mock
```
