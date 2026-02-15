# Signal Engine Pipeline

## Purpose
Convert normalized envelope data into bounded triage signals (`true|false|unknown`) for scoring and deterministic enrichment routing.

## Inputs
- Envelope JSON from normalization:
  - `schema_version`, `case_id`, `message_metadata`, `auth_summary`, `entities`, `mime_parts`, `attachments`, `warnings`
- Signal registry/rule files in `Signal_Engine`
- Optional external tool results for non-deterministic signals

## Configuration Files
- `Signal_Engine/signal_taxonomy.yaml`
- `Signal_Engine/signal_rules_deterministic.yaml`
- `Signal_Engine/signal_rules_nondeterministic.yaml`
- `Signal_Engine/tool_requirements.yaml`
- `Signal_Engine/signal_output_schema.yaml`

## Execution Stages
1. Load taxonomy and rule mappings.
2. Evaluate deterministic signals using envelope-only logic.
3. Evaluate non-deterministic signals from tool results when available.
4. Default unresolved non-deterministic signals to `unknown`.
5. Run semantic assessor on controlled evidence envelope (when `enable_semantic=true`).
6. Merge semantic outputs into non-deterministic `semantic.*` signals (when semantic stage is enabled).
7. Emit strict signal map for scoring and enrichment planning.

Deterministic and semantic stages now include authenticated-marketing guardrails to reduce false positives from normal ESP infrastructure.

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

Guardrail behavior:
- If SPF/DKIM/DMARC+alignment pass and mailing-list/ESP tracking context is present, semantic sender/URL mismatch signals are not allowed to turn `true` based on tracking wrappers alone.
- In the same authenticated marketing context, isolated urgency language (`semantic.coercive_language`) is treated as non-phishing unless stronger credential/payment/deception cues are present.
- Guardrails do not suppress true high-risk body language (credential theft, account takeover, payment diversion cues).

## Deterministic Evaluation Areas
- `message_metadata` for identity/header checks
- `auth_summary` for SPF/DKIM/DMARC/alignment
- `entities.urls/domains/emails/ips` for URL and infrastructure signals
- `mime_parts.body_extraction` for wording/evasion checks
- `attachments` for file-type and static indicators

URL/header guardrail details:
- Header-domain mismatch now ignores non-FQDN `Message-ID` host fragments (for example internal relay hostnames).
- URL mismatch/redirect/obfuscation checks suppress known ESP tracking wrappers (for example `*.ct.sendgrid.net`) unless stronger mismatch evidence is present.
- Long encoded URL-path checks also suppress authenticated sender-related marketing tracking hosts (for example organizational click-wrapper subdomains).
- Hidden CSS/preheader markers (`display:none`, `opacity:0`, etc.) are treated as benign template behavior in authenticated marketing context unless paired with stronger suspicious overlays/forms/scripts.
- Base64-in-HTML evasion detection is stricter and can return `unknown` (instead of `true`) for authenticated mailing-template context.

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
python3 Signal_Engine/signal_engine.py \
  --envelope Sample_Emails/Sample_Email.envelope.json \
  --out Sample_Emails/Sample_Email.signals.json
```

## Maintenance Notes
When adding/changing signals:
1. Update taxonomy and nondeterministic rules if needed.
2. Update scoring weights and high-impact list.
3. Update semantic assessor contracts if semantic IDs changed.
4. Update this document in the same change set.
