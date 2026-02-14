# Audit Chain

## Purpose
Provide stage-by-stage traceability for each case run so failures and regressions are diagnosable.

Implementation file:
- `/Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Investigation_Agent/audit_chain.py`

## Artifacts
Generated per run:
- `audit_chain.json`
- `audit_chain.md`

## Coverage
Audit chain records:
1. ingestion/normalization stage
2. baseline signal generation
3. semantic assessment stage
4. baseline scoring stage
5. deterministic enrichment planning
6. deterministic enrichment loop with per-iteration source/status counts
7. final decision stage

## Error Mapping
For each tool failure, audit captures:
- enrichment tool alias
- tool id
- provider reason

## Guardrail Attestation
Audit includes explicit guardrail flags:
- `llm_can_execute_tools=false`
- `llm_final_verdict_control=false`
- `deterministic_verdict_engine=true`
- `prompt_injection_system_guard=true`
- `playbooks_deprecated=true`
