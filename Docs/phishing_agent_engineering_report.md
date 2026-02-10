# AI Phishing Triage Agent — Engineering Implementation Report (CLI → API/MCP)

> This document turns the baseline workflow (Normalize → LLM Signals → Playbooks → Investigation Agent → Verdict Core → LLM Analyst → CLI output) into a production-grade, agentic architecture and implementation plan.  
> Baseline reference stages: normalization/envelope, LLM signal generation + playbook assignment, investigation agent using MCP tools with deterministic confidence scoring, verdict core, strict LLM analyst, CLI outputs. (See PDF lines L11–L108.)

---

## 0. Goals, Non‑Goals, and Principles

### Goals
- **Production-grade phishing triage** from a single `.eml` input, producing:
  - **Deterministic verdict** (`risk_score`, `verdict`, `reasons[]`) and **auditable evidence**.
  - **LLM analyst report** constrained to evidence only.
  - **CLI-first UX**, designed to be **packaged as REST API** or **MCP server** with minimal refactor.
- **Agentic investigation loop**:
  - Plan → tool calls → evidence capture → scoring update → stop on thresholds/budget.
- **Safety & robustness**:
  - No risky interaction with content (no credential submission, no “clicking through” flows, no executing attachments).
  - Egress and tool permissions controlled by policy.
- **Evaluation and regression**:
  - Labeled corpus, test harness, and metrics tracking to prevent drift.

### Non‑Goals (initial versions)
- Full mailbox ingestion (IMAP/Gmail) — v1 starts with `.eml` on disk.
- Dynamic detonation of attachments in a live environment (optional later, behind a sandbox boundary).
- Auto-remediation actions (quarantine, blocking) — produce **recommendations** first.

### Design Principles
1. **Evidence-first**: every conclusion must map to concrete evidence.
2. **Deterministic core**: verdict comes from rule/score engine + validated tool outputs, not from “LLM vibe”.
3. **Bounded agency**: agent can only call approved tools, with strict budgets.
4. **Composable adapters**: CLI/API/MCP share the same core services.
5. **Structured I/O**: JSON schemas everywhere (envelope, signals, evidence, verdict, report).

---

## 1. System Overview

### High-level stages (baseline → expanded)
1. **Parsing & Normalization**
   - Parse `.eml`, decode MIME, canonicalize headers, normalize charset.
   - Produce **Normalized Envelope JSON**.
2. **Signal Generation (LLM + deterministic template)**
   - LLM fills a predefined threat-signal template with `true/false/unknown` and short evidence pointers.
3. **Playbook Assignment**
   - Deterministic mapping from “true” signals to one or more playbooks (YAML).
4. **Case Packaging**
   - Create a case folder containing envelope, signals, playbooks, and evidence log.
5. **Investigation Agent (Agentic loop)**
   - LLM planner chooses from whitelisted tools; tool router executes; evidence appended.
   - Deterministic confidence scoring; early stop when threshold reached.
6. **Verdict Core**
   - Compute final `risk_score`, `verdict`, `reasons[]` mapped to evidence.
7. **LLM Analyst (strict)**
   - Create final report constrained to evidence only.
8. **Output**
   - CLI: one-line verdict + JSON artifacts.

---

## 2. Architecture

### 2.1 Components
**Core Services**
- `EmailParser`: `.eml` → MIME tree + decoded bodies + attachment metadata.
- `Normalizer`: canonicalized headers + entity extraction + schema validation → `Envelope`.
- `SignalGenerator`: LLM constrained to fill `SignalTemplate`.
- `PlaybookSelector`: rules mapping signals → playbook set.
- `CaseManager`: case directory layout + artifact writing + evidence append-only log.
- `ToolRouter`: executes approved tools (DNS, WHOIS, URL rep, attachment static scan, etc.) with policy guardrails.
- `InvestigationController`: agent loop manager (budgets, stop criteria, scoring updates).
- `VerdictEngine`: deterministic scoring + reasons.
- `AnalystReporter`: strict LLM summarizer and action recommender.
- `Adapters`: CLI adapter now; API adapter and MCP adapter later.

**Data Stores (local first)**
- Case folder on disk.
- Optional embedded DB (SQLite/DuckDB) for corpora + caching + metrics.

### 2.2 Case folder layout
```
cases/
  2026-02-10T12-30-05Z_<case_id>/
    input/
      message.eml
    artifacts/
      envelope.json
      signals.json
      playbooks/
        identity_spoof.yml
        url_redirect_chain.yml
      investigation_plan.md
      evidence_log.jsonl
      verdict.json
      analyst_report.json
      analyst_report.md
      iocs.json
      hunt_queries.kql
    logs/
      pipeline.log
      timings.json
```

### 2.3 Determinism & auditability
- **Every tool call** writes:
  - tool name, args (sanitized), timestamp, raw output, normalized output, and hash.
- Evidence is **append-only** (`evidence_log.jsonl`) and referenced by ID.
- `reasons[]` in verdict references evidence IDs.

---

## 3. Data Model & Schemas

### 3.1 Normalized Envelope (`Envelope`)
A stable JSON schema used across CLI/API/MCP.

**Top-level**
- `schema_version`: `"1.0"`
- `case_id`
- `ingest`: { `source`, `received_at`, `hashes` }
- `message_metadata`: parsed + canonicalized header set
- `auth_summary`: SPF/DKIM/DMARC extracted results + alignment notes
- `entities`: deduped extracted entities (urls/domains/ips/emails)
- `mime_parts`: tree summary + body extraction results
- `attachments[]`: metadata + hashes + extracted strings/urls (static)
- `warnings[]`: parser/decoder anomalies, missing headers, malformed MIME

**message_metadata fields (recommended)**
- `from`: { `display_name`, `address`, `domain` }
- `reply_to`: { ... } or null
- `return_path`
- `to[]`, `cc[]`
- `subject`
- `date`
- `message_id`
- `received_chain[]`: parsed Received hops (best-effort)

**auth_summary fields**
- `spf`: { `result`, `domain`, `ip`, `evidence_id` }
- `dkim[]`: list of signatures with `result`, `d=` domain, selector, canonicalization hints
- `dmarc`: { `result`, `policy`, `aligned`, `evidence_id` }
- `auth_results_raw`: original header text (for audit)

**entities fields**
- `urls[]`: { `url`, `normalized`, `domain`, `path`, `params`, `evidence_id` }
- `domains[]`: { `domain`, `punycode`, `is_lookalike_of[]` }
- `emails[]`: { `address`, `domain` }
- `ips[]`: { `ip`, `version` }

### 3.2 Signal template (`Signals`)
Signals are **bounded** and must be `true/false/unknown`.

Example:
- `identity.reply_to_mismatch`
- `identity.display_name_spoof`
- `auth.dmarc_fail`
- `auth.spf_fail`
- `auth.dkim_fail`
- `url.shortener_used`
- `url.redirect_chain_present`
- `url.lookalike_domain`
- `content.credential_harvest_language`
- `attachment.suspicious_type`
- `attachment.contains_macros`
- `header.received_chain_anomaly`

Each signal entry:
- `value`: `true|false|unknown`
- `evidence`: `[evidence_id...]`
- `rationale`: optional short string (<= 240 chars)

### 3.3 Playbooks (YAML)
Playbooks are deterministic recipes for investigation steps.

Example fields:
- `id`, `name`, `description`
- `preconditions`: signals that must be true
- `steps[]`:
  - `tool`: tool name
  - `args_template`: Jinja-like placeholders referencing envelope/entities
  - `cost`: expected cost weight
  - `stop_if`: scoring thresholds or evidence conditions
- `expected_outputs`: normalized evidence keys
- `scoring_impacts`: weights applied if evidence confirms

### 3.4 Evidence record (`EvidenceLog` line)
JSONL per tool call.
- `evidence_id`
- `timestamp`
- `tool_name`
- `args_redacted`
- `raw_output_ref` (path or embedded)
- `normalized_output`
- `hash_sha256`
- `errors[]`

### 3.5 Verdict (`Verdict`)
- `risk_score`: 0–100
- `verdict`: `benign|suspicious|phish`
- `reasons[]`: { `code`, `title`, `evidence_ids[]`, `weight`, `summary` }
- `budgets`: { `tool_calls_used`, `time_ms`, `tokens_used` }
- `version`: engine version

### 3.6 Analyst report (`AnalystReport`)
Must reference evidence IDs and avoid unsupported claims.
- `executive_summary[]`
- `most_suspicious_indicators[]`: ranked list with evidence IDs
- `likely_attack_type`
- `recommended_next_actions[]`
- `confidence`: 0–1
- `evidence_needed[]`

---

## 4. Implementation Plan (Phased)

### Phase 1 — CLI MVP (deterministic + constrained LLM)
1. **Parser/Normalizer**
   - Parse `.eml` robustly, decode MIME, extract headers, Authentication-Results.
   - Canonicalize header casing, unfold header lines, handle encoded-words.
   - Extract entities from bodies + attachments (static string extraction).
2. **Schema validation**
   - Validate envelope via JSON Schema (fail closed: mark unknown fields, log warnings).
3. **Signals**
   - LLM fills a strict signal template (`true/false/unknown`) using only envelope evidence.
4. **Playbooks**
   - Deterministic mapping (rules engine) to choose playbooks.
5. **Investigation loop**
   - Implement tool router for 2–4 tools (DNS resolve, WHOIS age via provider, URL normalization/redirect expansion offline).
   - Evidence log + scoring + early stop.
6. **Verdict core**
   - Weighted scoring; generate reasons referencing evidence IDs.
7. **LLM analyst output**
   - Strict JSON report + optional markdown rendering.
8. **CLI packaging**
   - `phishscan analyze --eml file.eml --case-dir cases/ --output json`

### Phase 2 — Enrichment connectors + caching
- URL reputation (commercial-safe provider)
- Domain intel (age/registrar) + caching
- Attachment static analyzers (PDF/Office URL extraction, macro indicators)
- IOC bundle export + hunt queries

### Phase 3 — API & MCP adapters
- Wrap core pipeline in:
  - REST `POST /analyze` returning `Verdict` + artifacts
  - MCP `analyze_email` tool returning same

---

## 5. Technology Stack (recommended)
- Language: **Python** (fastest for parsing and SOC tooling ecosystem)
- CLI: `typer` or `click`
- Schemas: `pydantic` + JSON Schema export
- Storage: filesystem + optional SQLite
- Logging: `structlog` or stdlib `logging` with JSON formatter
- LLM: provider-agnostic interface (`LLMClient`) for OpenAI/Anthropic/local
- Sandbox boundary: containerized microservice for any risky enrichment

---

## 6. Core Module Breakdown

### 6.1 `email_parser/`
Responsibilities:
- Read `.eml` bytes
- Parse headers (unfolding, decoding)
- Build MIME tree
- Extract text bodies and HTML
- Extract attachment bytes metadata (do not execute)

Key outputs:
- `ParsedEmail` object containing:
  - `headers_raw`, `headers_decoded`
  - `received_chain_raw`
  - `auth_results_raw`
  - `bodies`: `{text, html}`
  - `attachments`: list of `{filename, content_type, size, sha256, bytes_ref}`

### 6.2 `normalization/`
Responsibilities:
- Header canonicalization & normalization
- Charset normalization
- Entity extraction + dedup
- Received chain parsing (best effort)
- Envelope schema validation

Entity extraction rules:
- URLs: robust regex + HTML href parsing + deobfuscation (e.g., `hxxp://`)
- Domains: derived from URLs/emails + punycode decode
- IPs: parse IPv4/IPv6 from bodies and headers

### 6.3 `signals/`
Responsibilities:
- Maintain `SignalTemplate` enum taxonomy
- LLM prompt + response validation
- Ensure outputs are limited to template keys
- Evidence pointer extraction: LLM must cite evidence fields or evidence IDs

### 6.4 `playbooks/`
Responsibilities:
- Playbook YAML loading and validation
- Deterministic selection rules (signals → playbooks)
- Step compilation to tool calls

### 6.5 `tools/` (Tool Router + tool implementations)
Tool interface:
- Inputs: structured args (validated)
- Outputs: raw + normalized output
- Policies:
  - Allowed hosts/domains
  - Timeout, retries, rate limits
  - Redaction rules
  - Offline mode

### 6.6 `investigation/`
Responsibilities:
- Agent controller loop
- Budgets and stop criteria
- Evidence append-only writing
- Scoring updates (incremental)

Loop skeleton:
1. Start with baseline score from signals + envelope heuristics.
2. Choose next step: from playbooks + planner.
3. Execute tool via ToolRouter.
4. Normalize evidence, update score.
5. Stop if:
   - score >= `PHISH_THRESHOLD`
   - score <= `BENIGN_THRESHOLD`
   - budgets exhausted
6. Produce final verdict.

### 6.7 `verdict/`
Responsibilities:
- Deterministic risk scoring
- Reason generation mapped to evidence IDs
- Versioned scoring weights

### 6.8 `reporting/`
Responsibilities:
- Strict LLM report generation
- Markdown rendering templates
- Export IOC bundle + hunt queries

---

## 7. Prompting & Constraint Design

### 7.1 Signal generator prompt (must be “bounded”)
Rules:
- Output must be valid JSON.
- Only keys in template.
- Values in `{true,false,unknown}`.
- Evidence must reference envelope fields or evidence IDs.

Validation:
- Parse JSON
- Reject unknown keys
- Reject unrecognized values
- If invalid: retry once with error messages; else mark signals unknown.

### 7.2 Investigation planner prompt
Inputs:
- envelope + signals + selected playbooks + current score + remaining budgets

Output:
- next `N` tool calls (max 1–2 per turn) with args from allowed schema
- brief rationale
- “stop recommendation” (optional)

Hard guardrails:
- Planner cannot invent tools.
- ToolRouter rejects disallowed args/domains.
- Strict timeouts.

### 7.3 Analyst reporter prompt (strict)
Rules:
- Only cite facts present in evidence log/envelope.
- If missing: say “unknown”.
- Must output JSON; optionally plus markdown.

---

## 8. Scoring (Verdict Core)

### 8.1 Baseline scoring inputs
- Signals (from LLM but bounded)
- Deterministic heuristics (from envelope)

Example weights (illustrative):
- DMARC fail + alignment fail: +20
- Reply-To mismatch +10
- Lookalike domain confirmed: +25
- URL reputation malicious: +30
- Attachment suspicious type: +15
- Credential-harvest language: +10

### 8.2 Score normalization
- Sum weights, clamp 0–100.
- Thresholds:
  - `>= 75` → `phish`
  - `<= 20` → `benign`
  - else `suspicious`

### 8.3 Reasons mapping
Each reason is triggered by a rule that points to evidence IDs:
- `AUTH_DMARC_FAIL`
- `IDENTITY_REPLY_TO_MISMATCH`
- `URL_MALICIOUS_REPUTATION`
- `DOMAIN_LOOKALIKE_CONFIRMED`
- `ATTACHMENT_SUSPICIOUS_TYPE`

---

## 9. Security Model (Production Guardrails)

### 9.1 Tool egress policy
- Default: offline mode
- Allowlist required for any outbound request
- DNS/WHOIS/URL reputation via dedicated connectors; never arbitrary HTTP fetches by LLM

### 9.2 Prompt injection resistance
- Treat email content as untrusted.
- Never allow email content to influence tool permissions.
- Maintain a “system policy” separate from evidence text.

### 9.3 Attachment handling
- Do not execute.
- Static extraction only unless behind a sandbox boundary.
- Store attachment bytes in case folder with content-hash naming; never auto-open.

### 9.4 PII handling
- Redact recipient addresses in logs by default.
- Configurable redaction rules for case exports.

---

## 10. Observability & Ops

### 10.1 Logging
- JSON logs with `case_id`, `stage`, `duration_ms`, `error_code`.
- `timings.json` per case for performance tuning.

### 10.2 Metrics
- Tool call counts, time per stage, LLM tokens, cache hit rate.
- Quality metrics from corpus runs: precision/recall, FP/FN breakdown by signal.

---

## 11. Evaluation Harness

### Corpus runner
- `phishscan eval --corpus ./corpus --labels labels.csv`
- Produces:
  - confusion matrix
  - per-signal contribution stats
  - top FP reasons

### Regression tests
- Unit tests for parser edge cases (MIME oddities, encoded headers, malformed Received)
- Golden-file tests for envelope schema and verdict outputs

---

## 12. API & MCP Transformation Plan

### 12.1 Shared core
`core.analyze(eml_bytes, config) -> AnalysisArtifacts`

### 12.2 REST API adapter
- `POST /analyze`
  - input: `.eml` bytes or base64
  - output: `Verdict` + `AnalystReport` + artifact links/inline

### 12.3 MCP adapter
Expose tools:
- `analyze_email`
- optional: `enrich_domain`, `enrich_url`, `scan_attachment_static`

**Important**: In MCP mode, keep tool boundaries identical and return the same schemas.

---

## 13. Mermaid — Technical Workflow Diagram

```mermaid
flowchart TD
  %% =========================
  %% ENTRY / ADAPTERS
  %% =========================
  subgraph ADAPTERS[Adapters]
    CLI[CLI: phishscan analyze]
    API[REST API: POST /analyze]
    MCP[MCP Tool: analyze_email]
  end

  CLI --> INGEST
  API --> INGEST
  MCP --> INGEST

  %% =========================
  %% INGEST + CASE MGMT
  %% =========================
  subgraph INGEST[Ingest & Case Management]
    I1[Read input .eml bytes]
    I2[CaseManager: create case_id + folders]
    I3[Write input/message.eml]
    I4[Telemetry: start trace + budgets]
  end

  %% =========================
  %% PARSE / NORMALIZE
  %% =========================
  subgraph PARSE[Parse & Normalize]
    P1[EmailParser: headers + MIME tree]
    P2[Robust MIME decode + charset normalize]
    P3[Header canonicalization + Received parsing]
    P4[Entity extraction: urls/domains/ips/emails]
    P5[Entity dedup + contextual linking]
    P6[Attachment metadata + hashes + static strings/urls]
    P7[Schema validation: Envelope JSON]
    P8[Write artifacts/envelope.json]
  end

  %% =========================
  %% SIGNALS + PLAYBOOKS
  %% =========================
  subgraph SIGNALS[Signals & Playbooks]
    S1[LLM Signal Generator\nbounded template true/false/unknown]
    S2[Validate signals.json against template schema]
    S3[PlaybookSelector\nrules: signals -> playbooks]
    S4[Write artifacts/signals.json + playbooks/]
  end

  %% =========================
  %% INVESTIGATION (AGENTIC)
  %% =========================
  subgraph INVEST[Investigation Controller (Agentic Loop)]
    A1[Baseline Score: heuristics + signals]
    A2[Planner LLM\nselect next tool steps]
    A3[Policy Gate\nallowlist + budgets + redaction]
    A4[ToolRouter executes tool]
    A5[EvidenceStore append-only evidence_log.jsonl]
    A6[Score Update + Stop Check]
  end

  %% Tools
  subgraph TOOLS[Whitelisted Tools]
    T1[DNS Resolve / MX / TXT]
    T2[Domain Intel / Age / Registrar]
    T3[URL Normalize + Redirect Expansion (safe)]
    T4[URL Reputation Connector]
    T5[Attachment Static Analysis\n(PDF/Office URL extract, macro flags)]
    T6[Lookalike / Homoglyph Detector]
  end

  %% =========================
  %% VERDICT + REPORT
  %% =========================
  subgraph DECIDE[Verdict & Reporting]
    V1[VerdictEngine\nrisk_score + verdict + reasons[evidence_ids]]
    V2[Write artifacts/verdict.json]
    R1[Strict LLM Analyst\nreport from evidence only]
    R2[Write analyst_report.json + analyst_report.md]
    R3[Export iocs.json + hunt queries]
  end

  %% =========================
  %% OUTPUT
  %% =========================
  subgraph OUT[Outputs]
    O1[CLI: one-line verdict]
    O2[CLI: JSON artifacts for automation]
    O3[API/MCP: return Verdict + Report + artifact refs]
  end

  INGEST --> PARSE
  PARSE --> SIGNALS
  SIGNALS --> INVEST
  INVEST -->|tool calls| TOOLS
  TOOLS --> INVEST
  INVEST --> DECIDE
  DECIDE --> OUT
```

---

## 14. Concrete CLI UX

### Commands
- `phishscan analyze --eml PATH --case-dir cases/ --output json|text --offline`
- `phishscan eval --corpus PATH --labels labels.csv`
- `phishscan render --case CASE_ID --format md|json`

### Exit codes
- `0`: benign
- `10`: suspicious
- `20`: phish
- `30`: error

---

## 15. Next Steps Checklist
- [ ] Implement `Envelope` schema + validator.
- [ ] Build parser edge-case tests (MIME, encoded headers).
- [ ] Implement 10–20 deterministic heuristics and reason mapping.
- [ ] Add bounded `SignalGenerator` with strict JSON validation.
- [ ] Implement 3–5 whitelisted tools + evidence store.
- [ ] Build investigation loop + budgets.
- [ ] Add strict analyst report generator.
- [ ] Create corpus harness + metrics.

---

## Appendix A — Recommended Repository Layout
```
phishscan/
  phishscan/
    __init__.py
    cli.py
    core.py
    config.py
    email_parser/
    normalization/
    schemas/
    signals/
    playbooks/
    tools/
    investigation/
    verdict/
    reporting/
    eval/
  playbook_library/
  corpus/
  tests/
  pyproject.toml
```

## Appendix B — Configuration (example)
- thresholds, tool allowlists, budgets
- offline vs online enrichments
- redaction rules
- cache settings

---
