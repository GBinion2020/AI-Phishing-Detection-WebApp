# Command-Line Tool

## Purpose
Provide an operator-friendly CLI wrapper for investigation runs with:
- strict `.eml` validation,
- live stage/enrichment progress,
- repeat-run workflow,
- runtime memory scrubbing.

Implementation files:
- `/Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/cli/phishscan.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Investigation_Agent/pipeline_service.py`
- `/Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Investigation_Agent/investigation_pipeline.py`

## Runtime Flow
1. Accept `.eml` path (interactive or `--eml`).
2. Validate file and extension.
3. Execute pipeline via `PipelineService.execute(...)`.
4. Stream events:
   - stage started/completed,
   - enrichment started/completed,
   - score/confidence updates.
5. Print final summary.
6. Scrub in-memory runtime state.
7. Optional artifact deletion with `--scrub-artifacts`.

## Event Model
`run_pipeline(...)` emits:
- `pipeline_started`
- `stage_started`
- `stage_completed`
- `enrichment_started`
- `enrichment_completed`
- `pipeline_completed`

## Commands
Interactive:
```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/cli/phishscan.py
```

One-shot:
```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/cli/phishscan.py \
  --eml /absolute/path/to/email.eml \
  --mode live
```

Scrub artifacts:
```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/cli/phishscan.py --scrub-artifacts
```
