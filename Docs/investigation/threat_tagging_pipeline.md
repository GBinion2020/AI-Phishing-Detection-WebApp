# Threat Tagging Pipeline

## Purpose
Derive deterministic analyst-facing threat tags from final investigation signals and score outputs.

Implementation file:
- `Investigation_Agent/threat_tags.py`

## Inputs
- Final normalized envelope (`envelope` object in pipeline memory)
- Final resolved signals document (`signals.final.json` payload)
- Final score document (`score.final.json` payload)

## Outputs
Threat-tag derivation emits:
- `primary_threat_tag` (single tag id)
- `threat_tags[]` (single-item array containing the primary tag) with:
  - `id`
  - `label`
  - `severity` (`critical|high|medium|low|info`)
  - `confidence` (`high|medium|low`)
  - `reasons[]` (short deterministic rationale snippets)

These fields are attached to:
- `score.final.json`
- `report.final.json` (for Web UI rendering)

## Execution Steps
1. Load final verdict/risk and relevant auth + marketing context from envelope.
2. Evaluate deterministic tag conditions from final true signals (for example:
   `semantic.credential_theft_intent`, `auth.dmarc_fail`, `attachment.hash_known_malicious`).
3. Apply authenticated-marketing guardrails:
   - when auth passes and message context is promotional, avoid escalating to high-severity phishing tags unless strong high-risk drivers are present.
4. Add low-severity informational tags for graymail/promotional context when appropriate.
5. Select the single highest-likelihood tag aligned to final verdict class (`phish|suspicious|benign`), then publish only that tag.

## Current Tag Catalog
- `credential_harvest`
- `brand_impersonation`
- `bec_invoice_fraud`
- `payment_diversion`
- `malware_delivery`
- `attachment_weaponized`
- `account_takeover`
- `spoof_auth_failure`
- `social_engineering_urgency`
- `spam_marketing`
- `graymail_promotional`
- `recon_or_test_message`
- `data_exfiltration_lure`

## Operational Limits
- Threat tags are deterministic metadata; they do not override final verdict scoring.
- Tags depend on available final signals and can only be as precise as upstream evidence.
- Marketing guardrails reduce false positives but do not suppress true high-risk evidence.

## Maintenance Notes
When adding/changing tags:
1. Update `TAG_CATALOG` and severity rank in `threat_tags.py`.
2. Add/adjust deterministic mapping conditions.
3. Update Web UI report mapping (if display fields change).
4. Update this document and README docs list in the same change set.
