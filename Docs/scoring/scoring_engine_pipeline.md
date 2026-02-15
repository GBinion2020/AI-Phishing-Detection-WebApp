# Scoring Engine Pipeline

## Purpose
Convert bounded signal output into deterministic:
- `risk_score` (0-100)
- `confidence_score` (0-1)
- `verdict` (`benign|suspicious|phish`)
- `agent_gate` (`invoke_agent` true/false)

Implementation files:
- `Scoring_Engine/scoring_engine.py`
- `Scoring_Engine/scoring_weights.yaml`

## Input Contract
Each signal must include:
- `value`: `true|false|unknown`
- `kind`: `deterministic|non_deterministic`
- `evidence`: list
- `rationale`: string

Invalid payloads fail fast.

## Risk Model
For each signal with `value=true`:
1. resolve signal weight from override or category defaults,
2. add weight to risk total,
3. compute semantic blend boost from number of true `semantic.*` signals,
4. clamp final risk to configured min/max.

Important:
- The scoring engine remains additive/deterministic.
- False-positive control for authenticated ESP marketing patterns is handled upstream in the signal engine/semantic assessor by normalizing specific signals to `false` or `unknown` when evidence is benign-context only.

Verdict thresholds:
- `risk <= benign_max` -> `benign`
- `risk >= phish_min` -> `phish`
- otherwise -> `suspicious`

## Confidence Model
Confidence combines:
- known signal coverage,
- deterministic/non-deterministic coverage,
- evidence presence ratio,
- penalties for high-impact unknowns and unsupported true signals,
- semantic blend confidence boost.

Final confidence is clamped to `[0,1]`.

## Semantic Blend
Configured in `scoring_weights.yaml` under `semantic_blend`:
- `risk_boost_per_true_signal`
- `max_risk_boost`
- `confidence_boost_per_true_signal`
- `max_confidence_boost`

This creates a hybrid model where bounded LLM semantic conclusions materially influence final scoring while keeping deterministic control.

## Agent Gate
The gate decides if enrichment should continue.

Force invoke when:
- high-impact unknown count is above threshold,
- confidence below threshold,
- risk in ambiguous band.

Skip invoke when:
- high risk + high confidence (auto-phish),
- low risk + high confidence (auto-benign).

Gate runs at:
- baseline,
- after each deterministic enrichment iteration,
- final decision stage.

## Output Fields
- `risk_score`
- `confidence_score`
- `verdict`
- `agent_gate`
- `metrics` (including semantic boost metrics)
- `reasons`
- `weighted_signals`

## CLI Usage
```bash
python3 Scoring_Engine/scoring_engine.py \
  --signals Sample_Emails/Sample_Email.signals.json \
  --weights Scoring_Engine/scoring_weights.yaml \
  --out Sample_Emails/Sample_Email.score.json
```
