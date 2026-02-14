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
Gate is evaluated:
1. at baseline,
2. after each enrichment-tool iteration.

## Early Stop
Investigation stops early when:
- gate indicates no further enrichment is needed,
- enrichment step budget is exhausted,
- tool-call budget is exhausted,
- no enrichment candidates remain.

## Budget Controls
Configured limits:
- `INVESTIGATION_MAX_ENRICHMENT_STEPS`
- `INVESTIGATION_MAX_TOOL_CALLS`

## Practical Behavior
Ambiguous cases continue enrichment until confidence improves or budget stops are reached. Low-risk/high-confidence cases terminate at baseline without enrichment.
