# Persistence, Observation Boundary, and Startup Authority — Kuzushi Security Research Control Plane

> **Status:** proposal for review
> **Date:** 2026-08-19
> **Plan index:** [security research control-plane productization](./README.md)
> **Roadmap constraint:** the current [ROADMAP](../../../ROADMAP.md) remains authoritative.

---

## 1. Event and persistence contract

### 1.1 Proposed semantic events

The exact names can change during implementation, but the domain coverage should remain.

```text
ResearchQuestionCreated
ResearchQuestionStatusChanged

ResearchHypothesisProposed
ResearchHypothesisAccepted
ResearchHypothesisRejected
ResearchHypothesisSuperseded

ExperimentPlanCreated
ExperimentPlanAuthorized
ExperimentPlanDenied
ExperimentAttemptLinked
ExperimentAttemptTerminal

ObservationBoundaryRecorded
ResearchObservationRecorded
EvaluatorReceiptRecorded
HypothesisDispositionRecorded
ResearchCascadeProposed
ResearchCascadeAccepted
ResearchCascadeRejected

ResearchQuestionResolved
ResearchQuestionClosed
```

Avoid one generic `ResearchUpdated` event. Explicit event types make replay, compatibility, and review safer.

### 1.2 Event payload principles

Each event should contain:

- event schema version;
- canonical IDs;
- target identity reference;
- authority principal;
- timestamp;
- bounded semantic fields;
- artifact/CAS references;
- policy and object digests;
- idempotency key where writes may be retried.

Events should not copy:

- complete tool input;
- full model output;
- raw traces;
- source files;
- screenshots;
- crash inputs;
- packet captures.

### 1.3 Source of truth

Use the existing V3 model:

- target-wide append-only event log is the semantic source of truth;
- CAS stores source snapshots and large evidence;
- per-run `items.jsonl` records run lifecycle and bounded research/evaluator references;
- SQLite is a rebuildable projection;
- reports and exports are derivatives;
- no `research.json` mutable side database.

### 1.4 Projection tables

Illustrative tables:

```text
research_questions
research_hypotheses
research_experiment_plans
research_attempts
research_observations
research_evaluator_receipts
research_dispositions
research_cascade_edges
research_finding_links
research_boundary_summaries
```

Projection schema can evolve without becoming a compatibility source. The event and exported schema require migration discipline.

### 1.5 Run integration

Each experiment attempt should add bounded typed lifecycle items:

```text
research-question-ref
hypothesis-ref
experiment-plan-ref
observation-boundary-ref
observation-ref
evaluator-receipt-ref
hypothesis-disposition-ref
```

The run should not embed the complete research tree. Replay of the run and replay of the target research projection remain related but distinct responsibilities.

### 1.6 Published schemas

Potential additive schemas:

```text
schemas/research.question.schema.json
schemas/research.hypothesis.schema.json
schemas/research.experiment.schema.json
schemas/research.observation-boundary.schema.json
schemas/research.evaluator-receipt.schema.json
schemas/research.export.schema.json
```

Do not publish all schemas in the first code PR. Publish only after Rust types and compatibility tests stabilize.

---

## 2. Observation boundary

### 2.1 Why this is P0

A security result can be technically correct and still misleading because the dangerous behavior was outside the system's context, index, runtime, network vantage point, or deployment view.

Kuzushi already records substantial provenance, but it needs one canonical answer to:

> **What could this experiment actually observe, and what was omitted or degraded?**

### 2.2 Proposed shape

```rust
pub struct ObservationBoundary {
    pub target: TargetIdentity,
    pub source: SourceObservationBoundary,
    pub build: BuildObservationBoundary,
    pub static_analysis: StaticAnalysisBoundary,
    pub runtime: RuntimeObservationBoundary,
    pub network: NetworkObservationBoundary,
    pub deployment: DeploymentObservationBoundary,
    pub external_services: Vec<ExternalServiceBoundary>,
    pub omissions: Vec<BoundaryOmission>,
    pub failures: Vec<BoundaryFailure>,
    pub completeness: BoundaryCompleteness,
    pub boundary_digest: Digest,
}
```

The first release may implement only target/source/static/runtime fields, but the envelope should be extensible.

### 2.3 Source boundary

Record:

- canonical target root or snapshot;
- Git commit/tree identity and dirty state;
- included path roots;
- excluded path roots and reasons;
- generated/vendor/submodule treatment;
- file count and byte count considered;
- language detection coverage;
- unreadable files;
- unsafe or escaped paths rejected;
- truncation and caps;
- snapshot digest.

### 2.4 Static-analysis boundary

Record per engine:

- engine identity and version/digest;
- supported languages;
- files accepted;
- files rejected;
- parser/index/CPG completeness;
- query/rule set identity;
- timeouts;
- engine errors;
- unsupported constructs;
- whether dependencies were resolved;
- whether generated code was included.

Do not collapse several engines into one optimistic boundary.

### 2.5 Runtime boundary

Record:

- harness identity;
- build identity;
- operating system/architecture;
- sandbox/executor identity;
- environment policy digest;
- network policy;
- process and resource limits;
- test inputs/corpus references;
- number of attempts;
- flaky/non-deterministic observations;
- which real entrypoints were or were not exercised;
- whether the result is local harness only.

### 2.6 Completeness

Do not use one percentage as proof of coverage.

```rust
pub struct BoundaryCompleteness {
    pub source_inventory: CompletenessState,
    pub parser_coverage: CompletenessState,
    pub dependency_resolution: CompletenessState,
    pub runtime_entrypoints: CompletenessState,
    pub network_vantage: CompletenessState,
    pub deployment_vantage: CompletenessState,
}
```

```rust
pub enum CompletenessState {
    Complete,
    Partial { reason: BoundedText },
    Unavailable { reason: BoundedText },
    NotApplicable,
    Unknown { reason: BoundedText },
}
```

### 2.7 Policy

Each evaluator declares required boundary dimensions.

Example:

```text
Evaluator: source-to-sink path exists
Required:
  source_inventory != unavailable
  parser_coverage != unavailable
  target_identity exact
Allowed:
  runtime_entrypoints = not_applicable
  deployment_vantage = not_applicable
```

A remote exploitability evaluator may require runtime entrypoint and deployment vantage. If those are missing, it cannot return satisfied.

### 2.8 Operator language

Reports must say:

- “No path was found within the indexed Rust and TypeScript source at commit X.”
- not “No path exists.”

They must say:

- “The crash reproduced in a local generated harness.”
- not “The application is exploitable.”

---

## 3. Startup authority manifest

### 3.1 Purpose

Security research about agents and tools repeatedly shows that dangerous authority may exist before the first model response:

- project configuration;
- environment variables;
- PATH resolution;
- startup hooks;
- dynamic modules;
- prompt or house-rule files;
- MCP servers;
- credentials;
- headless approval policy;
- inherited descriptors;
- mounted directories;
- runtime/model selection.

Kuzushi has controls across these surfaces, but reviewers need one persisted artifact.

### 3.2 Proposed shape

```rust
pub struct StartupAuthorityManifest {
    pub run_id: RunId,
    pub target: Option<TargetIdentity>,
    pub config_sources: Vec<AuthoritySource>,
    pub environment_influences: Vec<EnvironmentInfluence>,
    pub executable_resolutions: Vec<ExecutableResolution>,
    pub loaded_capabilities: Vec<LoadedCapability>,
    pub runtime_selection: Option<RuntimeSelectionReceipt>,
    pub prompt_influences: Vec<PromptInfluence>,
    pub credentials: Vec<CredentialAvailability>,
    pub grants: Vec<CapabilityGrantReceipt>,
    pub denials: Vec<CapabilityDenialReceipt>,
    pub unresolved: Vec<UnresolvedAuthoritySurface>,
    pub policy_digest: Digest,
    pub manifest_digest: Digest,
}
```

### 3.3 Trust classes

```rust
pub enum AuthoritySourceOwner {
    Operator,
    KuzushiDistribution,
    TargetRepository,
    ModuleAuthor,
    ExternalService,
    RuntimeProvider,
    OperatingSystem,
    Unknown,
}
```

Every source records:

- owner/trust class;
- canonical location or logical identity;
- digest;
- load phase;
- precedence;
- accepted/rejected/unresolved;
- possible influence: code execution, network, credentials, model, prompt, policy, filesystem, target mutation.

### 3.4 Invariants

- Target-controlled input cannot silently increase operator or runtime authority.
- A target-local config or prompt may influence analysis only within declared policy.
- Loaded executable/module/MCP identity must be digest- or version-bound.
- Environment influence is disclosed without exposing secret values.
- Unknown executable resolution is not silently treated as trusted.
- The manifest is durable before the first external or executable effect.
- A materially changed authority manifest invalidates stale experiment authorization.
- A degraded manifest appears in reports and evaluator policy.

### 3.5 Product surface

`kuzushi permissions` can eventually expose a concise projection:

```text
Authority for run run_...
  target-controlled config: 2 accepted, 1 rejected
  operator config: 3
  model: openai/gpt-... via codex runtime
  plugins: 1 digest-pinned
  MCP servers: 3 Rust built-ins
  filesystem: target read-only; state write
  network: model provider only
  repository execution: denied
  unresolved: PATH identity for semgrep
```

---
