# Read-Only Audit Prompt — Prompts, Scan Modules, Runtime Routing & Artifacts

**Repository:** `allsmog/Kuzushi`

You are analyzing this repository as a Rust workspace with supporting docs, prompt assets, scripts, and generated artifacts. Your task is a **read-only architecture and audit report** — nothing more.

---

## 0. Ground Rules

**This is an audit-only task.**

- ❌ Do **not** modify files, patch code, or create commits.
- ❌ Do **not** run formatters that rewrite files.
- ❌ Do **not** delete, rename, normalize, or rewrite prompts.
- ❌ Do **not** claim the repository is fixed or correct.
- ❌ Do **not** provide a remediation plan (unless explicitly asked in a later task).
- ❌ Do **not** expose secrets, credentials, tokens, or private environment values.
- ✅ **Do** inspect and document exactly what exists, using precise source paths.

Your job is to inspect and document:

1. Every prompt or prompt-like template used by the system.
2. How prompts are selected, composed, overridden, routed, and logged.
3. How scan modules are registered, configured, executed, and serialized.
4. How prompt-driven runtime paths interact with scan modules, local state, artifacts, and background execution.

---

## 1. Audit Objectives

The final report should be **descriptive and evidential**, answering:

- What prompts exist in the repository?
- Which prompts are actually used at runtime vs. only examples, docs, tests, generated bundles, or design artifacts?
- How are prompts selected, composed, overridden, and sent into runtime calls?
- What data is injected into prompts?
- What output format does each prompt expect?
- Where are prompt outputs parsed into structured state?
- How are scan modules registered and executed?
- How do scan/module outputs become artifacts, run summaries, traces, cached state, or later prompt inputs?
- What architectural risks exist around prompt drift, stale artifacts, schema mismatch, event routing, or persistence?

---

## 2. Repository Areas to Inspect

### 2.1 Prompt Surfaces

**Where to look:**

```text
prompts/
docs/all-prompts.txt
docs/
AGENTS.md
README.md
scripts/
design/
tests/
crates/<core-crate>/src/**/*
crates/<runtime-or-provider-crate>/src/**/*
crates/<cli-crate>/src/**/*
crates/<ui-crate>/src/**/*
```

**What to find:**

- Static prompt files and Markdown prompt templates.
- Generated prompt bundles.
- Embedded Rust string prompts and `include_str!` imports.
- System/user prompt builders and system/user prompt pairs.
- Module-specific prompt overrides.
- Prompt hashing / fingerprinting.
- Prompt selection by model / tier / profile.
- Prompt inputs assembled from context, scan outputs, snapshots, findings, artifacts, or prior run state.
- Prompt outputs parsed into JSON, markdown, reports, findings, recommendations, or runtime state.
- Prompt logs, traces, summaries, and audit metadata.

**Searches:**

```bash
rg -n "prompt|system_prompt|user_prompt|template|instructions|house_rules|override|prompt_hash|promptHash|model|tier|thinking|reasoning|include_str|format!" .
rg -n "AgentQueryRequest|AgentToolLoopRequest|query_blocking|next_step|spawn_subagent|prompt_pair_hash|model_for_tier" crates
rg -n "all-prompts|prompts/|prompt_overrides|house_rules|thinking_level|structured" .
```

### 2.2 Scan & Module Surfaces

**Where to look:**

```text
crates/<core-crate>/src/modules/
crates/<core-crate>/src/modules/builtins/
crates/<core-crate>/src/modules/sast_run/
crates/<core-crate>/src/modules/native_scanners/
crates/<core-crate>/src/scan/
crates/<core-crate>/src/scanners/
crates/<core-crate>/src/run_artifacts/
crates/<ui-crate>/src/app/scan/
crates/<ui-crate>/src/app/tool_runner/
```

**What to find:**

- Module registry definitions and built-in module loading.
- Dynamic module loading (if present).
- Scan module descriptors, input schemas, output schemas.
- Scanner subprocess launchers and native scanner modules.
- Scan workers, event enums, result normalization.
- Artifact publication, run summaries, trace/frame generation, cached output updates.

**Searches:**

```bash
rg -n "ModuleRegistry|ToolExecutionContext|ToolDefinition|module_id|dag_nodes|builtins|native_scanners|scan_worker|ScanEvent|record_tool_run|RunArtifact|completed_output_result" crates
rg -n "semgrep|codeql|iac|secret|sbom|license|scanner|findings|sarif|jsonl|artifact|import" crates
rg -n "thread::spawn|tokio::spawn|mpsc::channel|try_recv|Finished|Failed|Stage|running|completed|interrupted|cancel|abort" crates
```

### 2.3 Runtime, State & Artifact Surfaces

**Where to look:**

```text
crates/<core-crate>/src/runtime/
crates/<core-crate>/src/run_artifacts/
crates/<core-crate>/src/run_trace.rs
crates/<core-crate>/src/fs_atomic.rs
crates/<core-crate>/src/options/
crates/<core-crate>/src/attachments/
crates/<core-crate>/src/context.rs
crates/<core-crate>/src/capabilities/*/persistence/
crates/<ui-crate>/src/app/background_events/
crates/<ui-crate>/src/app/runtime/
crates/<ui-crate>/src/app/view_state/
```

**What to find:**

- Background worker lifecycle and event drain lifecycle.
- Immutable execution frame creation.
- Append-only trace logs, run summary writes, artifact manifests.
- Snapshot cache updates, option/config stores, persistence boundaries.
- Places where prompt outputs or scan outputs become local state.

**Searches:**

```bash
rg -n "RunTraceStep|TraceSink|TraceHandle|append_run_trace_step|write_run_summary|artifact_manifest|write_run_artifact|cache_tool_snapshot|snapshot|fs::write|write_atomic|OpenOptions" crates
rg -n "ActivitySession|DagTaskRow|TerminalLoopState|drain_background_events|apply_.*event|start_background|run_shell" crates
```

---

## 3. Classification Rules

**Classify each prompt surface as one of:**
runtime prompt · static prompt file · embedded prompt string · generated prompt bundle · module-specific prompt · overrideable prompt · test prompt · demo prompt · documentation-only prompt · stale/possibly-unused prompt.

**Classify each module/scan surface as one of:**
native Rust module · subprocess-backed scanner · external-command adapter · runtime-composed module · importer/parser · report/artifact generator · background worker · UI/event-routing bridge · test/demo-only module.

---

## 4. Required Report Sections

### 4.1 Executive Summary
Summarize the architecture around: prompt assets, prompt construction, prompt overrides, runtime prompt routing, scan module registration, scan execution, event routing, artifact persistence, and prompt-to-scan coupling. Keep it factual; do not claim correctness.

### 4.2 Prompt Inventory

| Prompt Surface | Location | Form | Runtime Consumer | Inputs | Expected Output | Status / Notes |
|---|---|---|---|---|---|---|

For each asset, identify: where it lives; whether it appears executed; whether it is static/generated/embedded/test-only/documentation-only; what code consumes it; what variables are interpolated; whether it expects text/JSON/markdown/structured output; whether output is parsed into program state; whether it is logged, hashed, traced, saved, or fingerprinted.

### 4.3 Prompt Construction Pipeline

Describe the lifecycle:

```text
Configuration / module request
  -> prompt source selection
  -> context or artifact injection
  -> final prompt assembly
  -> runtime request object
  -> runtime call
  -> response parsing
  -> local state update
  -> trace / summary / artifact write
```

Identify code responsible for: selecting prompts; composing prompts; injecting repository context; injecting scan outputs; injecting artifacts/snapshots; selecting model/tier/profile; hashing/fingerprinting; tracing request metadata; parsing responses; handling malformed output.

### 4.4 Prompt Override & Configuration Model

Inspect config files, option stores, CLI flags, workspace-local overrides, module-specific overrides, prompt override files, house-rule/policy files, model/tier selection, thinking/reasoning-level configuration, and environment-variable behavior.

| Override Mechanism | Location | Scope | Precedence | Runtime Consumer | Persistence Model |
|---|---|---|---|---|---|

Flag ambiguity where multiple override paths may affect the same prompt.

### 4.5 Prompt Data Dependencies

For every runtime-composed prompt, identify data sources (repository inventory, context snapshot, scan results, finding records, run artifacts, previous runtime frames, option store values, model configuration, user input, generated reports).

| Prompt Consumer | Data Sources | Serialization Format | Freshness Assumption | Failure Behavior |
|---|---|---|---|---|

Flag places that may depend on stale, missing, partially written, or silently defaulted data.

### 4.6 Structured Output & Parsing Audit

```bash
rg -n "serde_json::from_str|serde_json::from_value|structured|schema|json_schema|parse|extract|repair|fallback|malformed" crates
```

| Runtime Path | Expected Output | Parser | Validation | Fallback | State Impact |
|---|---|---|---|---|---|

Document: expected format; parser location; validation behavior; fallback behavior; parse-error handling; whether malformed output is persisted; whether partial output can advance runtime state.

### 4.7 Scan Module Inventory

| Module / Scanner | Registration Location | Execution Function | Input Schema | Output Schema | Artifacts | Runtime Mode |
|---|---|---|---|---|---|---|

For each module determine: native / subprocess / adapter / importer; sync vs. background thread vs. async; emits progress events?; emits immutable frames?; writes artifacts?; updates run summaries?; contributes to cached snapshots or UI state?

### 4.8 Module Registry & Dispatch Architecture

Explain: registry construction; built-in module loading; dynamic module loading (if present); module descriptors; module IDs; DAG node definitions; dependency ordering; input preparation; execution context; output normalization; error propagation. Include a **Mermaid diagram** using sanitized component names.

### 4.9 Scan Execution State Machines

Document three lifecycles.

**Full scan lifecycle:**
```text
idle -> queued -> running -> stage update -> persisting -> completed -> failed -> stopped/interrupted
```

**Single module lifecycle:**
```text
not started -> input prepared -> dispatched -> running -> progress emitted -> result normalized -> artifacts written -> completed / failed
```

**Background worker lifecycle:**
```text
spawn requested -> receiver attached -> worker started -> events emitted -> event drain -> state applied -> receiver cleared
```

For each: states; transition triggers; source files; durable side effects; in-memory side effects; terminal states; invariants.

### 4.10 Scan Event & Frame Routing

Explain how progress reaches the foreground state matrix: event enum definitions; producer channel creation; receiver storage; drain order; progress-stage mapping; frame conversion; activity row updates; terminal event handling; redraw triggering; receiver teardown. Include a **sequence diagram** adapted to the actual code.

### 4.11 Artifact & Persistence Audit

| Artifact / State File | Writer | Reader | Format | Atomicity Model | Producer | Consumer |
|---|---|---|---|---|---|---|

Cover: run summaries; append-only traces; event logs; artifact manifests; latest-run pointers; context snapshots; module outputs; option stores; attachment stores; local database-backed state; imported scanner outputs. Flag architectural risks only.

### 4.12 Prompt-to-Scan Coupling Map

| Prompt Runtime Path | Depends on Scan Output? | Scan Source | Artifact Source | State Source | Coupling Risk |
|---|---|---|---|---|---|

Look for: prompt uses latest scan output; prompt uses finding records; prompt uses context snapshots; prompt consumes module-generated artifacts; module output becomes prompt input in a later stage; structured prompt output feeds another module; cached artifacts assumed to exist before prompt construction.

### 4.13 Test Coverage Map

```bash
rg -n "#\[test\]|tokio::test|snapshot|fixture|golden|prompt|scan|module|trace|artifact|summary" crates tests scripts
```

| Area | Existing Tests | What They Cover | What They Do Not Prove |
|---|---|---|---|

Do not add tests — read-only.

### 4.14 Architecture Risk Register

Use neutral language: "requires verification," "architectural assumption," "possible inconsistency," "unclear from static inspection," "needs runtime confirmation." No patch instructions.

| Risk Area | Code Shape / Evidence | Why It Matters | Verification Needed |
|---|---|---|---|

Include categories: prompt drift; undocumented override precedence; prompt output parsed without strict validation; stale artifact injection; scan module output schema mismatch; event-to-frame mismatch; terminal state not reflected in durable metadata; append-only log numbering assumptions; direct filesystem writes for stateful artifacts; background receiver teardown assumptions; module registry vs. UI state disagreement; test/demo prompts accidentally used in runtime paths.

### 4.15 Diagrams

Include Mermaid diagrams for: prompt construction and execution; scan/module dispatch; background event routing; artifact persistence; prompt-to-scan dependency flow.

### 4.16 Open Questions

List questions requiring maintainer confirmation or runtime testing (no remediation steps). Examples: Which prompt files are canonical vs. legacy? Which generated prompt bundles are authoritative? Which scanner outputs are required by later prompt paths? Which artifacts are guaranteed fresh before prompt construction? Which module outputs are schema-stable? Which event/frame paths are single-writer by design?

---

## 5. Final Output Requirements

Return **only** the audit report, containing all sections above (executive summary through open questions) plus the required Mermaid diagrams.

- No code diffs.
- No repository modifications or commits.
- No claims of correctness or of anything being fixed.
- No remediation plan.
- No exposed secrets, credentials, tokens, or private environment values.

Use exact source paths where useful, but keep the report focused on architecture and audit findings.
