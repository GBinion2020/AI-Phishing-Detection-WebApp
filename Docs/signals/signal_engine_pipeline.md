# Signal Engine Pipeline

## Purpose
Convert normalized envelope data into bounded triage signals (`true|false|unknown`) for scoring and deterministic enrichment routing.

## Inputs
- Envelope JSON from normalization:
  - `schema_version`, `case_id`, `message_metadata`, `auth_summary`, `entities`, `mime_parts`, `attachments`, `warnings`
- Signal registry/rule files in `/Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Signal_Engine`
- Optional external tool results for non-deterministic signals

## Configuration Files
- `/Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Signal_Engine/signal_taxonomy.yaml`
- `/Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Signal_Engine/signal_rules_deterministic.yaml`
- `/Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Signal_Engine/signal_rules_nondeterministic.yaml`
- `/Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Signal_Engine/tool_requirements.yaml`
- `/Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Signal_Engine/signal_output_schema.yaml`

## Execution Stages
1. Load taxonomy and rule mappings.
2. Evaluate deterministic signals using envelope-only logic.
3. Evaluate non-deterministic signals from tool results when available.
4. Default unresolved non-deterministic signals to `unknown`.
5. Run semantic assessor on controlled evidence envelope.
6. Merge semantic outputs into non-deterministic `semantic.*` signals.
7. Emit strict signal map for scoring and enrichment planning.

## Semantic Signal Coverage
Current semantic signals:
- `semantic.credential_theft_intent`
- `semantic.coercive_language`
- `semantic.payment_diversion_intent`
- `semantic.impersonation_narrative`
- `semantic.sender_name_deceptive`
- `semantic.body_url_intent_mismatch`
- `semantic.url_subject_context_mismatch`
- `semantic.social_engineering_intent`
- `semantic.prompt_injection_attempt`

These signals emphasize:
- sender-name/address deception,
- URL obfuscation/redirect behavior,
- mismatch between message topic and URL destinations,
- phishing pressure language and social engineering cues,
- prompt-injection attempts embedded in email text.

## Deterministic Evaluation Areas
- `message_metadata` for identity/header checks
- `auth_summary` for SPF/DKIM/DMARC/alignment
- `entities.urls/domains/emails/ips` for URL and infrastructure signals
- `mime_parts.body_extraction` for wording/evasion checks
- `attachments` for file-type and static indicators

## Non-Deterministic Evaluation
Non-deterministic signals are resolved by enrichment tools (when available), including:
- URL/IP/hash reputation
- domain registration/WHOIS
- DNS/MX context
- attachment intel/sandbox context
- campaign/history context

If connectors are unavailable, signals remain `unknown` with rationale.

## Output Contract
Output includes:
- `schema_version`
- `case_id`
- `generated_at`
- `signals` map keyed by signal ID

Each signal entry includes:
- `value` (`true|false|unknown`)
- `kind` (`deterministic|non_deterministic`)
- `evidence`
- `rationale`
- `tool_requirements`

## CLI Usage
```bash
python3 /Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Signal_Engine/signal_engine.py \
  --envelope /Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Sample_Emails/Sample_Email.envelope.json \
  --out /Users/gabe/Documents/Phishing_Triage_Agent_Mailbbox_Plug- in/Sample_Emails/Sample_Email.signals.json
```

## Maintenance Notes
When adding/changing signals:
1. Update taxonomy and nondeterministic rules if needed.
2. Update scoring weights and high-impact list.
3. Update semantic assessor contracts if semantic IDs changed.
4. Update this document in the same change set.
