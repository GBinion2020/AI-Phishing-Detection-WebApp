# Confidence Gate Logic

## Purpose
Control investigation depth adaptively in deterministic enrichment mode.

## Gate Inputs
From scoring output:
- `risk_score`
- `confidence_score`
- `agent_gate.invoke_agent`
- high-impact unknown metrics

## Gate Timing
Gate/stop checks are evaluated:
1. at baseline,
2. after baseline TI enrichment iterations,
3. after semantic reassessment,
4. after each adaptive enrichment iteration.

## Early Stop
Investigation stops early when any condition is met:
- gate indicates no further enrichment is needed (`agent_gate.invoke_agent=false`),
- definitive phish (`risk >= 85` and `confidence >= 0.85`),
- definitive benign (`risk <= 20` and `confidence >= 0.85`),
- confidence plateau (minimal confidence gain across recent iterations),
- enrichment step budget is exhausted,
- tool-call budget is exhausted,
- no enrichment candidates remain.

## Budget Controls
Configured limits:
- `INVESTIGATION_MAX_ENRICHMENT_STEPS`
- `INVESTIGATION_MAX_TOOL_CALLS`

## Practical Behavior
Ambiguous cases continue enrichment until confidence improves or budget stops are reached. Low-risk/high-confidence cases terminate at baseline without enrichment.
