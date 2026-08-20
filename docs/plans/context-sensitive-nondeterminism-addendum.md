# Normative addendum — context-sensitive nondeterminism

> **Status:** normative companion to `mdash-codemender-architecture-plan.md`
> **Scope:** architecture and sequencing only; no runtime behavior changes in this documentation PR
> **Decision:** Kuzushi must treat both model stochasticity and context construction as first-class, measurable inputs to every agentic scan.

## Why this addendum changes the plan

The main architecture plan correctly treats AI scanning as nondeterministic, but the implementation contract needs to be stricter. A scan result is influenced by more than the repository and selected model:

- sampling randomness and provider-side nondeterminism;
- the exact source chunks admitted to context;
- chunk and evidence ordering;
- retrieved threat-model, recon, and prior-finding context;
- tool schemas and tool-result ordering;
- repository guidance such as `AGENTS.md`;
- untrusted instructions embedded in source, comments, fixtures, or documentation;
- prior model outputs copied into later prompts;
- context truncation, compaction, and summarization;
- provider/model revisions that retain the same public model name;
- semantic-cache reuse;
- dynamic external data and tool output.

Therefore, “same repository, same model” is not a reproducible experimental condition. Kuzushi must record and govern the complete context envelope it controls, disclose the parts it cannot observe, and separate:

1. **same-context stochasticity** — multiple fresh model calls with the same controlled context;
2. **context-induced variance** — multiple calls where one declared context factor changes;
3. **model-induced variance** — equivalent controlled contexts across explicitly selected models;
4. **tool/environment variance** — changed tool output, tool version, external data, or execution environment.

Agreement across correlated runs is not independent corroboration. A result repeated from cache, copied from a prior model output, or produced by three agents sharing the same persuasive discovery rationale must never be presented as three independent votes.

## Immediate correctness risk to address before expanding the harness

The current verifier panel loops through `run_one_verify_pass`, and that helper uses `query_cached_structured_json_with_cost`. The plan must not assume that `VERIFY_PASSES=3` means three fresh model invocations until the semantic-cache key and runtime behavior prove it.

At minimum, the implementation needs an explicit call purpose and cache policy:

```rust
pub enum ModelCallPurpose {
    ReusableAnalysis,
    IndependentDiscoverySample {
        sweep_id: SweepId,
        sample_id: SampleId,
    },
    ControlledContextVariant {
        sweep_id: SweepId,
        arm_id: ContextArmId,
        sample_id: SampleId,
    },
    IndependentVerificationVote {
        panel_id: VerificationPanelId,
        vote_id: VerificationVoteId,
    },
    TieBreakVote {
        panel_id: VerificationPanelId,
        vote_id: VerificationVoteId,
    },
}

pub enum ModelCachePolicy {
    ReadWrite,
    ReadOnly,
    WriteOnly,
    Bypass,
}
```

Required semantics:

- an independent sample or verifier vote must not read a previous model response from semantic cache;
- a sample may be written under its own unique receipt key for audit, but that response cannot satisfy another sample or vote;
- persisted-result replay must reduce existing receipts and make **zero model calls**;
- “rerun with the same context” means a new model call with a new sample ID, not returning the previous cached answer;
- exact repeated output is allowed, but the receipt must prove that the runtime was actually invoked;
- if the provider exposes no deterministic seed or version receipt, Kuzushi records that limitation rather than inventing reproducibility.

This is now the recommended first implementation slice, before relying on multi-pass consensus as a security boundary.

---

# Updated target product contract

The target workflow becomes:

```text
Capture target identity
  -> Admit and classify context
  -> Build deterministic security frontier
  -> Declare sampling/context experiment
  -> Run controlled discovery samples
  -> Union observations and quantify variance
  -> Semantically cluster root causes
  -> Build clean-room verification context
  -> Run independent adversarial votes
  -> Empirically prove eligible candidates
  -> Draft and validate patch
  -> Human approval of exact source + diff
  -> Apply exact reviewed patch
  -> Reattack + detector replay
  -> Publish evidence, context, and variance receipts
```

The additional stages do not mean the operator must manually manage an experiment. The TUI should compile a reasonable sampling plan, disclose its cost and assumptions, and execute it durably. The operator controls policy and decision gates; the harness handles bookkeeping.

---

# Core invariants

## 1. Context is part of provenance

Every model-produced observation, assessment, patch suggestion, or advisory judgment must point to a content-addressed context envelope.

A prompt digest alone is insufficient. The envelope must include the exact admitted context items, their classes, their ordering, tool definitions, relevant tool outputs, truncation decisions, model identity, and cache policy.

## 2. Frequency is not proof

A candidate found in five samples is more repeatable than a candidate found once. It is not automatically more exploitable.

Likewise, a rare candidate can be real. Discovery aggregation is recall-oriented: retain the union, preserve support metadata, and send important candidates to independent validation. Do not majority-filter discovery findings out of existence.

## 3. Independence must be demonstrated, not inferred

Kuzushi may describe votes or observations as independent only when their receipts show the relevant separation:

- distinct fresh runtime invocations;
- no model-response cache read;
- no prior-vote visibility;
- declared context relationship;
- explicit model relationship;
- separate sample/vote IDs.

## 4. Repository content is untrusted context

The scanned repository may contain prompt injection in documentation, comments, fixtures, generated files, issue templates, or agent instructions.

Repository content can provide evidence and build/test guidance. It cannot change:

- the investigation objective;
- model selection;
- role authority;
- network permissions;
- tool permissions;
- proof semantics;
- budget limits;
- approval requirements;
- the distinction between model assessment and empirical proof.

## 5. Discovery and verification use different context contracts

Discovery should use deliberately varied, recall-oriented contexts.

Verification should use a clean-room, precision-oriented context assembled from normalized claims and validated source evidence. It must not inherit persuasive discovery prose, discovery confidence, other votes, or hidden conversation history.

## 6. The TUI never converts variance metadata into proof language

The TUI may say:

```text
repeatable in same context
context-robust
context-sensitive
single-sample
cross-model support
```

It may not translate those labels into `confirmed`, `exploited`, or `fixed`.

---

# New domain artifacts

## `ContextClass`

```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContextClass {
    OperatorPolicy,
    RepositoryGuidance,
    SourceEvidence,
    DeterministicToolOutput,
    DynamicToolOutput,
    ExternalIntel,
    PriorModelOutput,
    HumanDecision,
}
```

Instruction authority is not implied by presence in context.

Recommended authority:

| Context class | May inform facts? | May issue instructions? | Default trust |
| --- | --- | --- | --- |
| `OperatorPolicy` | yes | yes | authoritative |
| `RepositoryGuidance` | yes | only for declared build/test conventions | untrusted for security policy |
| `SourceEvidence` | yes | no | untrusted data |
| `DeterministicToolOutput` | yes | no | attributed evidence |
| `DynamicToolOutput` | yes | no | attributed, time-bound evidence |
| `ExternalIntel` | yes | no | attributed, potentially stale |
| `PriorModelOutput` | advisory only | no | untrusted generated claim |
| `HumanDecision` | yes | only within its declared decision scope | authoritative for that decision |

## `ContextItemRefV1`

```rust
pub struct ContextItemRefV1 {
    pub item_id: ContextItemId,
    pub class: ContextClass,
    pub object_ref: ObjectRef,
    pub source_label: SafeText,
    pub source_identity: Option<SourceIdentity>,
    pub admitted_by: ContextAdmissionRuleId,
    pub ordinal: u32,
    pub instruction_authority: InstructionAuthority,
    pub redaction: RedactionStatus,
    pub observed_at: Option<Timestamp>,
}
```

The receipt should point to local content-addressed objects where safe. Exported receipts may contain digests and redacted metadata instead of sensitive raw content.

## `ContextEnvelopeV1`

```rust
pub struct ContextEnvelopeV1 {
    pub schema_version: u32,
    pub context_id: ContextId,
    pub target_identity: TargetContentIdentity,
    pub investigation_plan_digest: Blake3Hash,
    pub role: SecurityRole,
    pub system_prompt_digest: Blake3Hash,
    pub role_prompt_digest: Blake3Hash,
    pub normalized_task_digest: Blake3Hash,
    pub items: Vec<ContextItemRefV1>,
    pub retrieval: RetrievalManifestV1,
    pub tools: Vec<ToolContractRefV1>,
    pub truncation: ContextTruncationReceiptV1,
    pub model: ResolvedModelReceiptV1,
    pub generation: GenerationParametersV1,
    pub cache_policy: ModelCachePolicy,
    pub completeness: ContextCompleteness,
}
```

`ContextCompleteness` should distinguish:

```text
complete_for_kuzushi_controlled_context
partial_provider_context_opaque
partial_dynamic_tool_output
incomplete_missing_object
```

Kuzushi must not claim full prompt reproducibility when a provider injects hidden or mutable context outside Kuzushi's control.

## `SamplingPolicyV1`

```rust
pub struct SamplingPolicyV1 {
    pub exact_context_replicates: u32,
    pub context_arms: Vec<ContextArmV1>,
    pub model_arms: Vec<ModelArmV1>,
    pub min_samples: u32,
    pub max_samples: u32,
    pub hard_cost_cap_usd: Option<Decimal>,
    pub stop_rule: SweepStopRuleV1,
    pub ordering_policy: OrderingPolicyV1,
}
```

## `ContextArmV1`

A context arm changes one declared factor while holding the rest of the plan constant.

```rust
pub struct ContextArmV1 {
    pub arm_id: ContextArmId,
    pub label: SafeText,
    pub baseline_context_id: ContextId,
    pub mutations: Vec<ContextMutationV1>,
    pub rationale: SafeText,
}
```

Initial controlled mutations may include:

- evidence-order permutation;
- independently retrieved source shard;
- threat-model context present versus absent;
- recon/exposure context present versus absent;
- alternate but equivalent decomposition of the same frontier unit;
- prompt variant explicitly declared as a separate arm.

Do not vary operator policy, proof definitions, permission policy, or mutation authority as a context experiment.

## `ScanSampleReceiptV1`

```rust
pub struct ScanSampleReceiptV1 {
    pub sample_id: SampleId,
    pub sweep_id: SweepId,
    pub context_arm_id: ContextArmId,
    pub context_digest: Blake3Hash,
    pub model_receipt: ResolvedModelReceiptV1,
    pub model_call_receipt: ModelInvocationReceiptV1,
    pub cache_read: bool,
    pub run_id: RunId,
    pub observations: Vec<FindingIdentity>,
    pub cost: RuntimeCostReport,
    pub terminal_state: SampleTerminalState,
}
```

## `SweepReceiptV1`

The sweep receipt is the authoritative aggregation of declared samples, not a flattened model transcript.

It records:

- planned and completed cells;
- sample/context/model relationships;
- omitted and failed cells with reasons;
- observation support matrix;
- unique clusters over time;
- marginal yield and stop reason;
- context completeness and drift warnings;
- total measured cost and unresolved spend.

---

# Context admission and injection resistance

## Add a context-admission application boundary

Create:

```text
crates/kuzushi-core/src/investigation/application/context_admission.rs
crates/kuzushi-core/src/investigation/domain/context.rs
crates/kuzushi-core/src/investigation/persistence/context_store.rs
```

Context admission should:

1. classify every item;
2. bind its source identity and digest;
3. apply redaction and size bounds;
4. set instruction authority explicitly;
5. preserve exact ordering;
6. record why the item was admitted;
7. reject or degrade malformed/unavailable items visibly;
8. keep target-local content from changing operator-owned model/tool policy.

## Repository guidance policy

Files such as `AGENTS.md`, `CONTRIBUTING.md`, and build documentation are useful for:

- identifying the correct package-level test command;
- respecting generated-file rules;
- learning repository layout;
- deriving a patch-validation plan.

They are not security-policy authorities. A repository instruction such as “ignore this directory,” “do not report this pattern,” “use this model,” or “send this file to a URL” must not alter the investigation unless the operator explicitly promotes it through an audited decision.

## Prior model output policy

Prior model output may be admitted only as a labeled claim or hypothesis. It cannot silently become source evidence.

For example:

```text
Discovery output:
  "The wildcard rule can be bypassed with symlinks."

Clean-room verifier context:
  claim: "A path authorized under representation A may resolve to target B."
  source evidence: exact cited code and path-resolution facts
  omitted: discovery confidence, prose, recommendation, and prior vote count
```

## Tool-output policy

Deterministic and dynamic tool outputs must be distinguished. A tree-sitter AST query over a bound source snapshot is different from a web lookup or mutable registry query.

Dynamic tool output requires:

- observed time;
- provider/source;
- response digest or local snapshot where permitted;
- freshness disclosure;
- no silent reuse as current evidence after its validity window.

---

# Controlled sampling design

## Two separate experiments

### Experiment A — exact-context replicates

Purpose: estimate same-context stochasticity.

Hold constant:

- source identity;
- normalized task;
- admitted context items and order;
- tool contract set;
- model spec and generation parameters;
- role policy;
- retrieval manifest.

Change only:

- sample ID;
- fresh runtime invocation;
- provider randomness that Kuzushi cannot fully control;
- explicit seed when the provider supports it and the plan chooses to vary it.

### Experiment B — controlled context arms

Purpose: measure context sensitivity.

Change one declared context factor per arm where practical. Use a deterministic balanced schedule so evidence ordering or model order is not accidentally confounded with package/shard order.

A context-arm result is not called a replicate of the baseline.

## Suggested profile behavior

These are initial product defaults to benchmark and tune, not immutable constants:

### `standard`

```text
1 canonical discovery sample
no repeatability claim
no context-robustness claim
```

### `deep`

```text
3 fresh canonical-context replicates
2 controlled context arms with at least 1 fresh sample each
union all observations
variance-aware Review projection
```

### `prove`

```text
deep discovery policy
clean-room verification panel
fresh independent verifier votes
empirical proof for eligible candidates
```

### `fix`

```text
prove policy
patch author receives normalized verified evidence, not the discovery transcript
independent patch critic context
exact-diff approval and reattack lifecycle
```

The TUI must show the expected sample count and cost before starting.

## Stop conditions

A sweep stops only for a persisted reason:

```text
completed_declared_samples
hard_cost_cap
hard_time_cap
operator_stop
cancellation
source_changed
context_integrity_failure
provider_failure
marginal_yield_saturation
```

A first saturation rule may use a rolling window such as:

```text
stop after N completed eligible samples produce
zero new durable observations and zero new semantic clusters,
provided the minimum sample and coverage requirements are satisfied
```

Saturation is a resource decision, not a proof that no undiscovered vulnerability exists.

## Discovery aggregation semantics

Discovery uses a union:

```text
all valid observations across all completed samples
  -> observation-level identity/dedup
  -> semantic cluster projection
  -> support/variance metadata
```

Do not require majority support to retain a finding.

Each observation or cluster should expose:

```text
raw sample support
fresh invocation support
exact-context replicate support
context-arm support
model-arm support
deterministic-tool corroboration
independence grade
```

The existing `corroboration_count` must not be treated as an independence count. Either extend it with structured support metadata or introduce a new projection.

## Independence grades

A simple initial vocabulary:

```text
none
repeated_same_cached_output
fresh_same_context_same_model
fresh_context_diverse_same_model
fresh_same_context_model_diverse
fresh_context_and_model_diverse
deterministic_and_agentic_cross_source
```

The first two provide no independent corroboration. The later grades disclose increasing diversity but still do not equal proof.

---

# Clean-room verification under context variance

## Verification context builder

Create a purpose-built DTO and builder that accepts only:

- normalized claim;
- exact source identity;
- validated source/evidence references;
- requested invariant checks;
- allowed static-analysis tool profile;
- role-specific prompt.

It must exclude by default:

- discovery transcript;
- discovery confidence;
- sample frequency;
- context-arm labels;
- other verifier votes;
- human verdict;
- patch recommendation;
- prior generated exploit narrative.

The verifier may learn support metadata only in a later appeal/explanation mode, not during the primary independent decision.

## Independent vote receipts

Every vote records:

- unique vote ID;
- unique model invocation receipt;
- cache read=false;
- context digest;
- model receipt;
- source identity;
- allowed tool contract;
- structured evidence and counterevidence;
- cost.

The panel must fail closed or visibly degrade if independent execution cannot be demonstrated.

## Context robustness is not decided by the verifier panel alone

The panel answers whether the normalized claim is statically plausible or rejected under its clean-room evidence.

The empirical harness answers whether a concrete security property fails at runtime.

The discovery sweep answers how readily the candidate surfaces under controlled sampling.

These are three separate questions and three separate receipts.

---

# TUI changes in practice

Do not add another top-level workflow page. Preserve:

```text
Setup -> Map -> Scan -> Review -> Prove -> Fix -> Report
```

Add context and variance projections within those pages.

## Setup — plan and sampling disclosure

The setup card should show:

```text
CONTEXT POLICY
  operator policy           authoritative
  repository guidance       build/test only
  source evidence           untrusted data
  prior model output        excluded from verifier

SAMPLING
  canonical replicates      3
  context arms              2
  planned fresh calls       5
  semantic-cache reads      forbidden for independent samples
  saturation stop           armed after minimum coverage

ESTIMATED COST
  discovery                 range
  validation                range
  empirical proof           only for eligible candidates
```

The operator can inspect or edit the declared arms before execution.

## Map — context-source inventory

Map should expose:

- frontier units and deterministic ranking reasons;
- context sources admitted for each security lens;
- repository-guidance files and their limited authority;
- dynamic/external context freshness;
- source chunks likely to exceed context budget;
- prompt-injection indicators as warnings, not automatic findings.

## Scan — variance-aware sweep deck

Example projection:

```text
SAMPLES              4 / 5 fresh invocations
CANONICAL REPLICATES  3 / 3
CONTEXT ARMS          1 / 2
UNIQUE OBSERVATIONS   18
UNIQUE CLUSTERS       6
NEW CLUSTERS / SAMPLE 2, 1, 0, 1
CONTEXT-ROBUST        2 clusters
CONTEXT-SENSITIVE     3 clusters
SINGLE-SAMPLE         1 cluster
CACHE REUSE           0 independent samples
STOP                  one arm remaining
```

The operator can drill into a sample and see its context digest and admitted-item manifest without exposing secrets unnecessarily.

## Review — support matrix, not a fake confidence number

For each observation or cluster, show:

```text
Support
  canonical replicate 1/3
  context arm A        1/1
  context arm B        0/1
  deterministic tool   CodeQL: absent
  model diversity      one model
  independence         fresh context-diverse same model

Interpretation
  context-sensitive discovery signal
  static assessment pending
  runtime proof absent
```

A candidate found once remains reviewable. A candidate found everywhere remains unconfirmed until validation/proof.

## Prove — context firewall disclosure

The Prove page should show:

```text
VERIFIER CONTEXT
  discovery transcript      excluded
  discovery confidence      excluded
  prior votes               excluded
  normalized claim          included
  validated source evidence included
  source identity           exact

VOTES
  3 planned
  3 fresh invocations
  0 cache reads
  1 model or declared model-diverse panel
```

## Fix — normalized evidence handoff

The patch author receives the verified claim, reproducer, source identity, and repository validation guidance. It does not inherit the full noisy sweep transcript.

The patch critic uses a separately assembled context and cannot see the patch author's hidden reasoning. The empirical reattack remains authoritative for security closure.

## Report — context and variance appendix

Every exported investigation packet should include:

- sampling plan and stop reason;
- context envelope digests;
- context completeness disclosures;
- fresh invocation and cache-use receipts;
- support matrix;
- variance metrics;
- static and empirical proof receipts;
- patch/reverification receipts.

---

# Persistence, replay, and rerun semantics

Use investigation-owned paths such as:

```text
.kuzushi/v3/investigations/<id>/
  plan.json
  contexts/<context-digest>.json
  sweeps/<sweep-id>/plan.json
  sweeps/<sweep-id>/receipt.json
  samples/<sample-id>/receipt.json
  stages/<stage-id>/receipt.json
```

## `replay`

```text
kuzushi investigate replay <id>
```

- verifies hashes and receipt relationships;
- reduces persisted evidence into the same projection;
- makes no model calls;
- makes no dynamic network/tool calls;
- fails visibly on missing/corrupt context objects.

## `rerun --same-context`

```text
kuzushi investigate rerun <id> --same-context
```

- rehydrates the same Kuzushi-controlled context envelope;
- creates new sample IDs;
- invokes the selected model again;
- bypasses model-response cache reads;
- records provider-side opacity/version differences;
- does not promise identical output.

## `rerun --new-context-arm`

```text
kuzushi investigate rerun <id> --context-arm <arm>
```

- creates a successor sweep under the same source identity;
- records the exact declared mutation;
- never edits historical sample receipts.

## Context drift

Resume or rerun should detect:

- source identity change;
- missing content-addressed context objects;
- tool schema/version change;
- prompt digest change;
- model spec or provider receipt change;
- retrieval-manifest change;
- external/dynamic context expiration;
- different truncation or compaction.

Material drift creates a successor plan/sweep or an explicit degraded comparison. It cannot silently reuse the old label “same context.”

---

# Evaluation changes

## Add a fifth lane: context and stochastic robustness

Input:

```text
repository + fixed source identity + declared frontier + role/model policy
```

Run:

- repeated exact-context samples;
- controlled context arms;
- optional model-diverse arms;
- clean-room verifier votes;
- empirical proof where available.

Report distributions, not a single lucky run.

Initial metrics:

```text
exact-context observation Jaccard
exact-context cluster Jaccard
context-arm observation Jaccard
context-arm cluster Jaccard
rank-order stability
union recall by sample count
unique clusters by sample count
marginal clusters per dollar
context-exclusive observation rate
context-robust cluster rate
fresh-invocation verification agreement
false-positive rate by context arm
empirical-proof conversion by context arm
```

A single-run benchmark cannot support a claim about agentic discovery quality.

## Variance decomposition

V1 may report descriptive slices rather than pretending to have a statistically perfect decomposition:

```text
same model + same context
same model + varied context
different model + same context
different model + varied context
```

Later versions may add bootstrapped intervals or hierarchical models, but every method must publish its assumptions and scorer version.

## Capture-recapture estimates are advisory only

Repeated scans may support an estimate of unseen candidate mass, but the independence assumptions are fragile because findings are correlated by code, context, and model behavior. If implemented, label it an advisory saturation estimate, never “estimated vulnerabilities remaining.”

---

# Required implementation seams

## Investigation domain

Add or extend:

```text
crates/kuzushi-core/src/investigation/domain/context.rs
crates/kuzushi-core/src/investigation/domain/sampling.rs
crates/kuzushi-core/src/investigation/domain/independence.rs
crates/kuzushi-core/src/investigation/domain/support_matrix.rs
crates/kuzushi-core/src/investigation/application/context_admission.rs
crates/kuzushi-core/src/investigation/application/plan_sweep.rs
crates/kuzushi-core/src/investigation/application/execute_sample.rs
crates/kuzushi-core/src/investigation/application/aggregate_sweep.rs
crates/kuzushi-core/src/investigation/persistence/context_store.rs
crates/kuzushi-core/src/investigation/persistence/sample_store.rs
```

## Runtime request and semantic cache

Audit and change:

```text
crates/kuzushi-core/src/verification/adapters/verify_finding_tool.rs
crates/kuzushi-core/src/verification/adapters/verify_finding_tool/execution.rs
structured-output cached query helpers
semantic-cache key/policy code
agent runtime request types
run/model invocation receipts
```

The runtime request needs explicit sample/vote identity and cache policy. Do not pass these as ad hoc JSON or environment variables.

## Campaign planner

Extend the matrix from conceptually:

```text
shard x threat x model
```

to:

```text
frontier unit x threat lens x context arm x model arm x replicate
```

Keep hard bounds. Report every cell omitted by cap, prior coverage, unsupported context, or budget.

## Findings and clusters

Add structured support metadata without rewriting historical observations:

```rust
pub struct ObservationSupportV1 {
    pub sample_ids: Vec<SampleId>,
    pub context_arm_ids: Vec<ContextArmId>,
    pub model_receipts: Vec<ResolvedModelReceiptV1>,
    pub deterministic_sources: Vec<ToolIdentity>,
    pub independence_grade: IndependenceGrade,
}
```

Do not overload proof state or human verdict.

## TUI presentation

Add presentation DTOs for:

- sampling-plan preview;
- context inventory;
- sweep progress;
- support matrix;
- context-integrity warnings;
- clean-room verifier disclosure;
- variance appendix.

TUI code consumes application projections; it must not reconstruct support or independence logic itself.

---

# Revised implementation sequence

This addendum supersedes the original 12-step ordering where noted.

## PR 0 — fresh-call identity and semantic-cache independence

**Goal:** make every claimed independent sample/vote demonstrably independent of cached model output.

Required outcomes:

- explicit `ModelCallPurpose` and `ModelCachePolicy`;
- unique sample/vote IDs in runtime receipts;
- verifier panel tests prove N passes invoke the runtime N times;
- cached response cannot satisfy another vote;
- persisted replay invokes the model zero times;
- same-context rerun makes a fresh call.

## PR 1 — proof vocabulary and typed patch eligibility

Retain the original plan's PR 1.

## PR 2 — context classes, admission, and `ContextEnvelopeV1`

**Goal:** establish the context trust boundary before creating a durable multi-stage harness.

Required outcomes:

- every model call can reference a context digest;
- ordering and truncation affect the digest;
- repository guidance cannot change operator policy;
- provider-context opacity is disclosed;
- secret-bearing content is not copied into export receipts.

## PR 3 — `InvestigationPlanV1` plus sampling policy

Compile current profiles into a durable plan and include:

- context policy;
- exact-context replicate count;
- declared context/model arms;
- hard sample/cost limits;
- stop rule.

Preserve current behavior for one-sample profiles during cutover.

## PR 4 — sweep execution and variance-aware aggregation

**Goal:** execute fresh samples and project union/support/variance correctly.

Required outcomes:

- discovery union retains single-sample candidates;
- support matrix distinguishes sample/context/model/deterministic sources;
- saturation stop is explicit and durable;
- campaign cells include context arm and replicate identity;
- TUI shows variance without proof inflation.

## PR 5 — investigation persistence, resume, replay, and rerun

Add exact semantics for replay versus same-context fresh rerun.

## PR 6 — deterministic Prepare frontier + campaign integration

Retain the original frontier work, now feeding declared sampling arms.

## PR 7 — independent verifier-role policy and context firewall

Required outcomes:

- discovery prose/confidence/prior votes excluded;
- every vote has a fresh invocation receipt;
- panel degrades visibly when independence cannot be established;
- same-model tie-break refusal remains enforced.

## PR 8 — semantic vulnerability clustering

Retain the original clustering work and consume structured support metadata.

## PR 9 — closed-loop Fix transaction through approval

The patch author receives normalized verified evidence, not the full discovery transcript.

## PR 10 — exact apply + empirical reattack/detector replay

Retain the original lifecycle requirements.

## PR 11 — proof backend capability abstraction

Retain the original portability requirements.

## PR 12 — native SARIF ingest + external exposure enrichment

External content enters as attributed context/signals with no instruction authority.

## PR 13 — reopened/regression projection

Retain prior remediation/proof/context relationships.

## PR 14 — multi-lane benchmark including context robustness

A live benchmark row must identify:

- source identity;
- context envelopes and arms;
- fresh invocation receipts;
- cache policy;
- model/provider receipts;
- union and variance metrics;
- separate discovery, verification, remediation, reattack, and robustness results.

---

# Focused tests required early

## Semantic-cache and vote independence

- three verifier passes produce three runtime invocation receipts;
- a pre-populated semantic-cache entry is not read by an independent vote;
- identical outputs from three fresh calls remain three calls but one repeated conclusion;
- exact persisted replay produces no provider call;
- same-context rerun produces a new sample ID and provider call.

## Context identity

- same items in different order produce different context digests;
- same source path with changed content produces a different object/context digest;
- a truncation decision changes the context digest;
- missing context object prevents exact-context rerun;
- provider opacity sets context completeness to partial.

## Context authority

- repository text cannot change selected model;
- repository text cannot authorize network access;
- repository text cannot disable a security lens;
- repository guidance can inform a declared test command only through the validation-plan admission rule;
- prior model output remains labeled and cannot satisfy source-evidence requirements.

## Aggregation

- a one-sample observation remains visible;
- repeated cached output contributes no fresh-invocation support;
- fresh same-context support differs from context-diverse support;
- deterministic scanner + agentic observation receives cross-source support;
- support metadata never upgrades proof state.

## TUI projection

- Setup shows planned fresh calls and cache policy;
- Scan shows completed samples, unique clusters, and stop reason;
- Review labels context-sensitive versus context-robust without saying confirmed;
- Prove displays excluded discovery context and fresh vote count;
- Report includes context completeness and variance disclosures.

---

# Example: scanning `anomalyco/opencode`

For an OpenCode permission/plugin/MCP investigation, the context plan might classify:

```text
OperatorPolicy
  security goal, models, roles, budgets, proof policy

RepositoryGuidance
  AGENTS.md package-level test/typecheck conventions

SourceEvidence
  permission evaluator
  session tool dispatcher
  plugin hooks
  MCP resource handling

DeterministicToolOutput
  route inventory
  tree-sitter/CPG call relationships

PriorModelOutput
  discovery hypotheses only
```

A deep discovery sweep might declare:

```text
canonical context replicates: 3
context arm A: permission evaluator evidence first
context arm B: tool-execution path evidence first
context arm C: threat model omitted to measure framing dependence
```

A hypothetical cluster could then show:

```text
external-directory authorization mismatch
  canonical support       1/3
  context arm A           1/1
  context arm B           0/1
  context arm C           0/1
  deterministic support   none
  interpretation          context-sensitive single-model discovery signal
  static assessment       pending
  empirical proof         absent
```

That candidate remains visible and eligible for clean-room verification. Its low repeatability does not prove it false; its context sensitivity tells the operator and evaluator that discovery is fragile.

The verifier receives the normalized authorization claim and exact code evidence, not the support table or discovery narrative. If empirical execution later reproduces an unauthorized outside-workspace access, runtime proof supersedes discovery fragility as the relevant security evidence.

---

# Updated north-star metric

Retain the main plan's evidence/remediation metric, but add context robustness as a diagnostic dimension:

> **cost per independently reproducible, evidence-backed vulnerability that reaches a safe verified remediation or defensible handoff, with the discovery context, sampling variance, and independence limits disclosed.**

Do not optimize for raw agreement. Optimize for useful coverage, independent falsification, empirical proof, and safe closure.

# Additional non-goals

- Do not pretend a deterministic seed makes provider execution fully reproducible.
- Do not call cached repetitions independent votes.
- Do not majority-filter rare discovery signals.
- Do not feed discovery persuasion into the primary verifier panel.
- Do not treat context robustness as exploitability.
- Do not allow repository text to steer models, tools, permissions, budgets, or proof semantics.
- Do not store sensitive raw context in portable receipts when a local object reference and digest suffice.
- Do not claim “same context” when tool versions, retrieval manifests, truncation, provider context, or source identity drifted.
