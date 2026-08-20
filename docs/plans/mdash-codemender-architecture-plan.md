# Kuzushi architecture plan — lessons from MDASH and CodeMender

> **Status:** implementation plan
> **Scope:** architecture and sequencing only; this change does not alter runtime behavior
> **Goal:** turn Kuzushi's existing evidence, campaign, verification, patch, and replay machinery into one typed, replayable, benchmarkable security-investigation harness.

## Executive decision

Kuzushi should **not** respond to MDASH by adding dozens of additional agents. The repository already has enough detectors, semantic hunters, MCP oracles, verifier passes, empirical proof, patching, campaign planning, and evidence persistence. The missing value is composition and explicit trust boundaries.

The target product contract is:

```text
Prepare
  -> Discover
  -> Adversarially validate
  -> Semantically cluster
  -> Empirically prove
  -> Draft and validate patch
  -> Human approval
  -> Apply exact reviewed patch
  -> Reattack + detector replay
  -> Publish evidence receipt
```

This combines the durable ideas behind MDASH (stage/role separation, independent validation, domain extensibility, semantic deduplication, selective escalation) with the best CodeMender product property (a closed find -> prove -> fix -> build/test -> reattack workflow), while preserving Kuzushi's differentiators: local-first operation, explicit proof states, source/provenance binding, operator-controlled models, no silent fallback, append-only decisions, and stronger post-patch empirical replay.

The implementation should happen as a sequence of independently useful PRs. The first PRs must strengthen the meaning of existing evidence before adding more automation.

---

## Current-state findings that drive this plan

### 1. `investigate` is a useful façade, but not yet a durable harness

`crates/kuzushi-cli/src/application/investigate.rs` currently compiles four closed profiles (`standard`, `deep`, `prove`, `fix`) into task lists and booleans. `fix` requests empirical verification and `autoPatch`, but explicitly stops at a build/test-checked patch draft and does not mutate the target.

This is a good safety baseline, but it means the high-level workflow is encoded as transient CLI branching rather than a first-class plan that can be persisted, inspected, resumed, diffed, replayed, or benchmarked.

### 2. Kuzushi already contains most of an MDASH-style validator architecture

`verify:finding` already supports:

- a cheap rejection-only `gateModel`;
- N independent panel passes;
- majority combination;
- a different-model tie-break escalation;
- explicit refusal to use the primary model as its own tie-breaker;
- source-identity binding;
- cost accounting;
- MCP-backed static evidence access.

The problem is product policy and semantics, not absence of machinery: panel passes default to 1, gate/escalation remain advanced opt-ins, and the SAST continuation consumes a generic `exploitable` boolean.

### 3. Static assessment and empirical proof remain too close in vocabulary

`verify:finding` writes an explicitly non-empirical proof snapshot, but its model schema can use `proofVerdict = exploited`, and operator output can say `VULNERABLE`. The SAST continuation then checks `/data/exploitable` to decide whether patch generation is eligible.

That is an avoidable trust ambiguity. A model conclusion and an executed reproducer are different domain concepts and should be impossible to confuse at the type/serialization boundary.

### 4. Patch synthesis is strong, and post-apply re-verification is stronger, but they are separate product transactions

`patch:finding` already:

- binds the exact source commit;
- requires originating detector provenance;
- synthesizes in disposable worktrees;
- validates build/test commands;
- iterates patch attempts;
- records cost and validation logs;
- persists patch provenance.

Separately, the patch lifecycle records `Applying`, `Applied`, `ReverifyRunning`, `Verified`, `StillVulnerable`, `Inconclusive`, etc. The empirical re-verifier can compare vulnerable vs patched checkouts using:

- original attack calibration;
- benign control calibration;
- attack variants;
- exact source identity;
- touched-file hashes;
- detector replay.

The missing feature is an application service that composes these capabilities into one resumable transaction with one human mutation gate.

### 5. Campaign planning is already a strong control-plane primitive

`campaign:plan` already crosses shards x threats x models, ranks cells, caps work, reports dropped work, sees prior overlap, and can fill coverage gaps. This should become an execution engine for a durable investigation plan rather than remain a mostly separate campaign concept.

### 6. Finding deduplication is still observation-oriented

`Finding` has durable identity, `sources`, `source_signature`, `corroboration_count`, and a bucketed `dedup_key`. The current key is intentionally location-oriented: normalized file + 8-line bucket + CWE/class.

That is useful for merging nearby scanner observations, but it is not enough to represent a semantic root cause shared across multiple sinks/files. We need to separate **finding observations** from **vulnerability clusters** rather than make one fingerprint perform both jobs.

### 7. External ingest and benchmark infrastructure are not yet product-grade

Kuzushi exports SARIF but generic external ingest is custom JSONL. `kuzushi-eval` and `experiments/recall-eval` exist, but the checked-in history still contains only a synthetic scaffold row, not live comparative evidence. Interoperability and evaluation should become core product contracts because they make Kuzushi useful even when another scanner discovers the initial signal.

---

# Target architecture

## Bounded-context view

```text
+---------------------+
| Investigation       |
| Plan / Harness      |
|---------------------|
| target identity     |
| frontier            |
| stages              |
| role policy         |
| tool policy         |
| budgets             |
| proof policy        |
| patch policy        |
+----------+----------+
           |
           v
+---------------------+       +----------------------+
| Discovery           | ----> | Findings             |
|---------------------|       |----------------------|
| deterministic scans |       | observations         |
| agentic hunts       |       | durable identity     |
| domain packs        |       | human decisions      |
| imported SARIF      |       | source evidence      |
+----------+----------+       +----------+-----------+
           |                             |
           v                             v
+---------------------+       +----------------------+
| Validation          | ----> | Vulnerability        |
|---------------------|       | Clusters             |
| rejection gate      |       |----------------------|
| blind verifier      |       | root-cause identity  |
| independent panel   |       | affected sinks       |
| tie-break           |       | observations         |
| empirical proof     |       | proof summary        |
+----------+----------+       +----------+-----------+
           |                             |
           +-------------+---------------+
                         v
              +----------------------+
              | Remediation          |
              |----------------------|
              | patch draft          |
              | build/test           |
              | approval receipt     |
              | exact application    |
              | reattack ladder      |
              | detector replay      |
              +----------+-----------+
                         |
                         v
              +----------------------+
              | Reporting / Eval     |
              |----------------------|
              | evidence receipt     |
              | SARIF/export         |
              | regression status    |
              | benchmark metrics    |
              +----------------------+
```

The new `investigation` context should **orchestrate existing bounded contexts**, not absorb their internals. Findings remain responsible for identity/evidence/decisions; verification remains responsible for proof; remediation remains responsible for patch lifecycle; modules remain the shared dispatch boundary.

---

# Workstream A — make proof semantics impossible to misread

## A1. Introduce separate static and empirical verdict vocabularies

### Problem

The current static verifier can serialize `proofVerdict: exploited` even though the surrounding snapshot correctly marks itself `empirical: false`. This leaks runtime terminology into a model-only assessment.

### Proposed domain model

Add explicit types under the verification/findings domain boundary, for example:

```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StaticAssessmentVerdict {
    Plausible,
    Rejected,
    InsufficientEvidence,
    Unsupported,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProofVerdict {
    Reproduced,
    NotReproduced,
    Inconclusive,
    Unsupported,
}
```

Do not reuse `PersistedProofVerdict` for static model opinions if it contains execution-oriented values.

### Required code changes

- `crates/kuzushi-core/src/verification/adapters/verify_finding_input.rs`
  - change the structured-output schema so static results cannot emit `exploited`;
  - rename the model-facing field to `assessmentVerdict` (with a temporary compatibility alias only if required);
  - keep `proofLevel <= 3` mechanically enforced.
- `crates/kuzushi-core/src/verification/adapters/verify_finding_tool.rs`
  - replace the generic `VULNERABLE` label with `PLAUSIBLE` / `REJECTED` / `INSUFFICIENT`;
  - emit `kind=static-exploitability-assessment` or equivalent;
  - keep `empirical=false` explicit.
- `crates/kuzushi-core/src/findings/domain/static_proof_state.rs`
  - retain the existing evidence ladder; map `StaticAssessmentVerdict` to terminal static states only when evidence requirements are satisfied.
- persistence and export projections
  - migrate old static `exploited` rows without pretending they had runtime evidence;
  - preserve old data as legacy static assessment provenance.

### Acceptance criteria

- No static/model-only code path can serialize `RuntimeProofVerdict::Reproduced` or the word `exploited` as its canonical verdict.
- No operator-facing surface uses `confirmed`, `exploited`, or equivalent for model-only evidence.
- Existing empirical proof rows remain unchanged in meaning.
- Migration tests demonstrate that legacy model verdicts remain readable but are projected as static assessments.

## A2. Replace `data.exploitable` patch gating with typed patch eligibility

### Problem

`run_sast_verification_and_patch.rs` currently uses a generic bool to decide whether a patch should be generated. That couples remediation eligibility to response shape rather than evidence policy.

### Proposed policy

```rust
pub enum PatchDraftEligibility {
    Refused,
    StaticAssessmentAccepted,
    RuntimeProofRequired,
    RuntimeProofSatisfied,
}

pub struct PatchPolicy {
    pub draft_requires: PatchDraftRequirement,
    pub apply_requires: PatchApplyRequirement,
}
```

Recommended defaults:

- a static assessment may authorize **drafting** only when the operator selected a policy that allows it;
- `investigate prove` never patches;
- `investigate fix` requires current empirical reproduction before drafting by default;
- target mutation always requires a current reviewed patch + explicit approval + source binding.

### Required seams

- `crates/kuzushi-core/src/modules/application/sast_scan/run_sast_verification_and_patch.rs`
- SAST request parsing/options
- `crates/kuzushi-core/src/remediation/patch/run_patch_finding.rs`
- tool result schema/projection tests

### Acceptance criteria

- No patch decision is based on an untyped JSON bool.
- Policy explains *why* a draft was allowed/refused.
- Default `fix` remains at least as strict as today.

---

# Workstream B — create `InvestigationPlanV1`, the missing harness object

## B1. Add a pure domain plan

### New bounded context

Create:

```text
crates/kuzushi-core/src/investigation/
  mod.rs
  domain/
    plan.rs
    stage.rs
    role_policy.rs
    proof_policy.rs
    patch_policy.rs
    budget_policy.rs
  application/
    compile_profile.rs
    execute_plan.rs
    resume.rs
    replay.rs
    diff.rs
  persistence/
    plan_store.rs
    state_store.rs
```

The domain types must have no filesystem/model/terminal dependencies.

### Proposed shape

```rust
pub struct InvestigationPlanV1 {
    pub schema_version: u32,
    pub investigation_id: String,
    pub target_identity: TargetContentIdentity,
    pub scope: InvestigationScope,
    pub stages: Vec<InvestigationStagePlan>,
    pub roles: BTreeMap<SecurityRole, RolePolicy>,
    pub tools: InvestigationToolPolicy,
    pub proof: InvestigationProofPolicy,
    pub patch: InvestigationPatchPolicy,
    pub budgets: InvestigationBudgetPolicy,
    pub prompt_digests: BTreeMap<SecurityRole, Blake3Hash>,
}
```

The plan should reference model specs explicitly; it must never contain fallback chains.

## B2. Compile current profiles into the plan without changing behavior

Refactor `crates/kuzushi-cli/src/application/investigate.rs` so:

```text
profile/flags
   -> compile InvestigationPlanV1
   -> persist/preview plan
   -> execute through shared investigation application service
```

The first migration PR should preserve today's task lists and flags byte-for-byte where possible. This is an architectural cutover, not a feature expansion.

### Persistence

Use v3-owned state:

```text
.kuzushi/v3/investigations/<id>/
  plan.json
  state.json
  stages/<stage-id>/receipt.json
```

`plan.json` should be immutable after execution begins. Operator changes create a successor plan with `supersedesPlanDigest` rather than editing history.

## B3. Add CLI lifecycle

Target commands:

```text
kuzushi investigate <target> --profile deep --plan
kuzushi investigate <target> --profile deep
kuzushi investigate resume <investigation-id>
kuzushi investigate show <investigation-id>
kuzushi investigate replay <investigation-id>
kuzushi investigate diff <a> <b>
```

`replay` does **not** mean “rerun stochastic models and expect identical output.” It means replay persisted stage receipts through the reducer and verify that the projected answer is identical. A separate `rerun --from-plan` may intentionally invoke models again.

### Acceptance criteria

- Existing profiles compile to a stable JSON plan.
- A plan digest is attached to every child run/result spawned by the investigation.
- Plan preview is side-effect-free.
- Resume skips already-completed stages only when their receipts are valid for the plan and source identity.
- CLI/TUI/headless execution still converge on the module registry for actual tool dispatch.

---

# Workstream C — MDASH-style Prepare and role separation

## C1. Add deterministic `prepare:frontier`

### Purpose

Do not spend strong-model tokens uniformly across the repository. Build a transparent work frontier before discovery.

### New tool

Register a descriptor-backed tool, likely under a new `prepare` or existing planning module:

```text
prepare:frontier
```

Output:

```json
{
  "schemaVersion": 1,
  "targetIdentity": {...},
  "units": [
    {
      "unitId": "src/auth/session.rs::validate_session",
      "paths": ["src/auth/session.rs"],
      "score": 87,
      "signals": [
        {"kind":"unauthenticated-entrypoint","weight":25},
        {"kind":"privileged-effect","weight":20},
        {"kind":"complexity","weight":8},
        {"kind":"recent-churn","weight":7}
      ]
    }
  ]
}
```

### V1 signal inputs

Prefer already-available deterministic facts:

- entry-point inventory / route map;
- repository inventory;
- CPG/tree-sitter call reachability when available;
- threat-model boundaries;
- current findings/corroboration;
- diff/churn information;
- known security-sensitive API categories;
- unsafe/native-memory boundaries;
- auth/authz/serialization/crypto/command/file/network sinks.

Do not let an LLM directly assign the canonical score in V1. Models may propose additional focus areas as separately attributed advisory signals.

### Campaign integration

Refactor campaign shards so a frontier can generate or weight shard inputs. `campaign:plan` remains the matrix/cap/gap-fill engine, but `InvestigationPlanV1` owns when and why campaign expansion occurs.

## C2. Promote verifier roles to policy, not advanced flags

Define security roles in the investigation plan:

```rust
pub enum SecurityRole {
    Discovery,
    PlausibilityGate,
    AdversarialVerifier,
    TieBreaker,
    PatchAuthor,
    PatchCritic,
}
```

A `RolePolicy` should name:

- explicit model;
- pass count;
- allowed tool profile;
- context visibility;
- budget cap;
- authority (`reject_only`, `advisory`, `decision_input`).

### Blind-verifier contract

The adversarial verifier should receive:

- normalized vulnerability claim;
- source location/evidence;
- exact source identity;
- requested proof questions.

It should **not** receive:

- discovery-agent confidence;
- discovery rationale beyond the normalized claim;
- prior verifier votes;
- human verdict unless policy explicitly asks for appeal/review.

This should be enforced by a purpose-built DTO rather than prompt convention.

### Default high-severity flow

```text
candidate
 -> deterministic prechecks
 -> cheap rejection-only gate (optional when configured)
 -> 3-pass adversarial panel for eligible candidates
 -> independent tie-break only on exact split
 -> empirical proof for candidates that remain plausible and are supported
```

Do not run a 3-pass panel on every low-severity scanner observation. Escalation selection should use severity, corroboration, proof state, and cost policy.

### Acceptance criteria

- Default deep/prove/fix plans make role structure visible in plan preview.
- Same-model tie-breaking remains impossible.
- Role model choice remains operator-owned and no-silent-fallback.
- Verifier context-independence has explicit regression tests.

---

# Workstream D — separate observations from semantic vulnerability clusters

## D1. Preserve current `Finding` as an observation-compatible record

Do not perform a destabilizing rewrite of every scanner producer. Existing findings can initially remain observation records with their durable identities and source evidence.

## D2. Add `VulnerabilityCluster`

Create a separate domain projection:

```rust
pub struct VulnerabilityCluster {
    pub cluster_id: VulnerabilityClusterId,
    pub target_identity: TargetIdentity,
    pub root_cause: Option<RootCauseDescriptor>,
    pub observation_ids: Vec<FindingIdentity>,
    pub affected_sinks: Vec<SinkIdentity>,
    pub cluster_evidence: Vec<ClusterEvidence>,
}
```

A cluster is not a replacement for a finding. It groups observations that appear to share one fixable root cause.

## D3. Staged clustering algorithm

Run deterministic/high-confidence stages first:

1. exact durable/source-signature relation;
2. same structural source -> sink path;
3. same missing guard/validation locus;
4. same vulnerable function and candidate fix locus;
5. patch-equivalence / semantic comparison for unresolved cases.

Use an LLM only as a late advisory classifier when structural data cannot decide. Persist the evidence for the clustering decision and its confidence.

### Never-collapse rules

- distinct sinks are preserved even when one root cause is shared;
- attack-chain findings never collapse into their component observations;
- uncertain clusters remain separate rather than forcing a merge;
- human split/merge decisions are append-only and auditable.

### Why this matters

This gives Kuzushi MDASH-like dedup/root-cause behavior without weakening the existing precise finding ledger. Review, patching, and reporting can operate at either observation or cluster level.

### Acceptance criteria

- Current `dedup_key` behavior remains as observation-level collision handling.
- New cluster projection can group cross-file observations without changing their durable finding IDs.
- One cluster can report N observations and M affected sinks.
- Human decisions can override a proposed grouping without deleting history.

---

# Workstream E — make Fix a closed, resumable security transaction

## E1. Add an investigation remediation application service

Do not implement this by embedding mutation into `patch:finding`. Keep existing tools cohesive and orchestrate them.

Proposed application seam:

```text
crates/kuzushi-core/src/investigation/application/remediate.rs
```

State machine:

```text
CandidateSelected
  -> RuntimeProofRequired
  -> RuntimeProofSatisfied
  -> PatchDrafting
  -> PatchValidated
  -> AwaitingApproval
  -> Applying
  -> Applied
  -> ReverifyRunning
  -> Verified | StillVulnerable | Regression | Inconclusive
```

Persist every transition through existing run/lifecycle primitives rather than shell-only state.

## E2. Approval receipt

Before target mutation, create a reviewable immutable approval proposal containing:

- investigation-plan digest;
- target/source identity;
- finding/cluster identity;
- exact diff hash and rendered diff;
- patch provenance;
- build/test plan and results;
- empirical proof reference;
- original attack result;
- benign control result;
- variant results available before application;
- model/tool/cost provenance;
- rollback/recovery semantics.

Approval must bind to the exact diff hash + source identity. If either changes, approval is invalid.

## E3. Apply exact reviewed diff

Reuse the existing patch lifecycle and touched-file hashing. Do not ask the patch model to regenerate at application time.

The application stage should:

1. re-check clean source binding;
2. verify the approved diff digest;
3. record `Applying` before mutation;
4. apply exact diff;
5. hash touched files;
6. record `Applied` or `ApplyFailed`;
7. never commit/push automatically.

## E4. Automatically run the existing stronger re-verification ladder

After application:

1. verify vulnerable checkout still reproduces original attack;
2. verify vulnerable benign control remains clean;
3. verify patched benign control remains clean;
4. verify patched original attack is blocked;
5. replay all recorded attack variants against vulnerable and patched checkouts;
6. replay the originating detector;
7. persist a content-addressed re-verification receipt;
8. derive final lifecycle state.

## E5. Add behavioral-regression evidence

Extend patch validation beyond “build/test passed”:

- reproducer-derived regression test when feasible;
- bounded benign differential corpus;
- public API/schema snapshot when a project exposes one;
- fuzzer seed/corpus replay when associated evidence exists;
- optional model critic as advisory only.

A patch cannot become `Verified` merely because an exploit no longer fires if normal behavior is broken.

## E6. Generalize empirical execution backends

Today the strongest ladder recognizes Bwrap as isolating. Introduce a capability-bearing proof backend abstraction without pretending all backends are equally strong.

Example capabilities:

```rust
pub struct ProofBackendCapabilities {
    pub filesystem: IsolationLevel,
    pub process: IsolationLevel,
    pub network: IsolationLevel,
    pub resource_limits: bool,
}
```

Potential adapters:

- Linux Bwrap (existing strongest path);
- OCI/container backend;
- macOS sandbox/VM backend;
- Windows sandbox/VM backend;
- remote self-hosted isolated runner;
- plain process only as explicitly degraded execution evidence.

Proof labels must be derived from capabilities. A plain process can never inherit an isolated-proof label.

### Acceptance criteria

- `investigate fix` can proceed from candidate to `AwaitingApproval` without mutating the target.
- One explicit approval binds to exact source+diff.
- Successful application automatically starts re-verification.
- Interruptions are resumable from durable state.
- No automatic commit, push, PR, or merge occurs.

---

# Workstream F — interoperability, regression memory, and evaluation

## F1. Native SARIF ingest

Add a descriptor-backed importer, preferably:

```text
workspace:import-sarif
```

Preserve:

- producer/tool identity;
- rule ID and metadata;
- physical locations;
- code flows/thread flows where available;
- partial fingerprints;
- CWE/taxonomy information;
- baseline state;
- severity/confidence supplied by the producer;
- report digest and import provenance.

Imported results enter Kuzushi as external **signals**, not confirmed vulnerabilities. They must use the same grounding/evidence-validation path as other external findings.

This makes CodeQL/GitHub Code Scanning/MDASH/other SARIF producers natural upstream sources for Kuzushi proof and remediation.

## F2. Exposure-context enrichment contract

Do not build a Defender or Wiz clone. Define a neutral optional enrichment schema that external systems can feed into prioritization:

```json
{
  "component": "payments-api",
  "internetReachable": true,
  "environment": "production",
  "handlesSensitiveData": true,
  "activeDeploymentCount": 14,
  "privilegedEffects": ["database-write"],
  "source": "external-security-graph"
}
```

This data affects prioritization, never proof state.

## F3. Explicit reopened/regression semantics

A previously verified remediation that reappears should not become an unrelated new issue. Add a regression projection over durable finding/cluster identity and patch lifecycle:

```text
reopened_same_root_cause
patch_reverted
variant_bypasses_patch
source_changed_since_verification
detector_regression
identity_ambiguous
```

Track:

- fixed-at commit/source identity;
- last empirically verified identity;
- application ID;
- reproducer digest;
- detector input digest.

## F4. Make evaluation a first-class CLI contract

Create benchmark lanes that measure different claims separately:

### Lane 1 — blind discovery

Input: repository + scope only.

Metrics:

- recall;
- precision;
- duplicate/cluster rate;
- cost;
- wall time;
- unsupported/incomplete cases.

### Lane 2 — verification

Input: candidate vulnerability supplied.

Metrics:

- correct rejection rate;
- correct plausible rate;
- empirical reproduction rate;
- false confirmation rate;
- cost per decision.

### Lane 3 — remediation

Input: empirically verified vulnerability.

Metrics:

- patch synthesis success;
- build/test success;
- original exploit blocked;
- benign behavior preserved;
- variant resistance;
- detector replay result;
- cost/time.

### Lane 4 — reattack

Input: patch + original reproducer + variants.

Metrics:

- vulnerable calibration correctness;
- patched blocking correctness;
- control preservation;
- variant bypass rate.

Every benchmark receipt records:

- source commit/identity;
- investigation-plan digest;
- role model specs;
- prompt digests;
- tool versions;
- proof backend/capabilities;
- scope/frontier;
- token/dollar cost;
- wall time;
- exact scorer version.

Do not publish one aggregate “Kuzushi score” that mixes discovery, verification, and remediation.

---

# Domain-security packs — the extensibility direction to take from MDASH

Kuzushi should evolve KWP/module composition into a domain-security pack contract, not a metric of “number of agents.”

A pack may contribute:

```text
frontier/targeting signals
security invariants
source/sink taxonomies
detector/query definitions
specialist auditor role instructions
proof harness builders
benign-control builders
attack-variant generators
patch validators
benchmark fixtures
```

Example packs:

- `django-multitenancy`
- `graphql-authorization`
- `rust-unsafe-memory`
- `go-service-authz`
- `linux-kernel-lifetime`
- `terraform-iam`
- `robotics-command-safety`
- `agent-tool-permissions`

The pack schema must declare capabilities rather than gain arbitrary host authority. Existing KWP isolation/approval rules remain in force.

V1 should be deliberately small: define the manifest shape and make one pack exercise frontier signals + verifier invariants + proof-case generation end to end before broadening the API.

---

# Proposed PR sequence

## PR 1 — Proof vocabulary and typed patch eligibility

**Goal:** make model opinion vs runtime proof impossible to confuse.

Files/areas:

- `verification/adapters/verify_finding_input.rs`
- `verification/adapters/verify_finding_tool.rs`
- verification/findings domain types
- SAST post-processing eligibility
- persistence/export projection migration tests

Exit criteria:

- static verifier cannot emit runtime-proof terminology;
- patch gating is typed/policy-based;
- no existing empirical proof claim is weakened.

## PR 2 — `InvestigationPlanV1` domain + profile compiler

**Goal:** convert transient `investigate` branching into a durable harness without behavior changes.

Exit criteria:

- all four profiles compile to persisted/previewable plans;
- execution attaches plan digest to child runs;
- `--plan` is side-effect free;
- current profile behavior is preserved.

## PR 3 — investigation persistence/resume/replay

**Goal:** make long operations stage-resumable and inspectable.

Exit criteria:

- immutable plan + durable stage receipts;
- resume validates source/receipt identity;
- replay reproduces persisted projection without model calls.

## PR 4 — deterministic Prepare frontier + campaign integration

**Goal:** spend security-analysis budget where it has the highest expected value.

Exit criteria:

- deterministic explainable frontier artifact;
- campaign planner can consume frontier-generated/weighted shards;
- capped plans report what was omitted.

## PR 5 — default independent verifier-role policy

**Goal:** make gate/panel/tie-break architecture a first-class investigation policy.

Exit criteria:

- role model/tool/context policy visible in plan;
- deep/prove/fix use explicit verifier policy;
- blind-context contract is tested;
- same-model tie-break remains refused.

## PR 6 — semantic vulnerability clustering

**Goal:** distinguish scanner observations from fixable root causes.

Exit criteria:

- observation identities are preserved;
- cross-file root-cause clusters exist as a separate projection;
- human split/merge is auditable;
- attack chains never collapse into components.

## PR 7 — closed-loop Fix transaction through approval

**Goal:** connect proof + patch validation to one durable pre-mutation approval state.

Exit criteria:

- investigation can reach `AwaitingApproval` with exact diff/source/proof receipt;
- no target mutation occurs before explicit approval.

## PR 8 — apply + automatic empirical reattack/detector replay

**Goal:** produce an end-to-end verified remediation receipt.

Exit criteria:

- exact approved diff is applied;
- interruption/recovery is durable;
- original/control/variants + originating detector are replayed automatically;
- final state cannot claim verified without a valid receipt.

## PR 9 — proof backend capability abstraction

**Goal:** make empirical proof portable without weakening labels.

Exit criteria:

- Bwrap remains the reference implementation;
- backend capability level is persisted;
- degraded backends cannot mint strong isolated-proof states.

## PR 10 — native SARIF ingest + external exposure enrichment

**Goal:** make Kuzushi a vendor-neutral evidence/proof control plane.

Exit criteria:

- SARIF producer/code-flow/fingerprint provenance preserved;
- imports begin as signals;
- external exposure affects priority only, never proof.

## PR 11 — reopened/regression projection

**Goal:** track recurrence as lifecycle history rather than duplicate findings.

Exit criteria:

- verified fixes can transition to a typed reopened reason;
- prior remediation/proof linkage is retained.

## PR 12 — first-class multi-lane benchmark command and receipts

**Goal:** make detection/proof/remediation quality measurable and comparable.

Exit criteria:

- discovery, verification, remediation, and reattack are scored separately;
- every row has source/plan/model/prompt/tool/backend provenance;
- live model rows are distinguishable from scaffold/self-test rows.

---

# Schema and compatibility strategy

## Never rewrite historical truth in place

Kuzushi already relies on append-only/evidence-preserving behavior. New semantics should follow the same rule:

- legacy static verifier rows remain readable;
- migrations project them into the new vocabulary with a legacy marker;
- a new investigation plan never mutates an already-started plan;
- cluster merge/split records are events, not destructive rewrites;
- reopened findings retain prior patch/proof/application references.

## Version new public artifacts from day one

At minimum:

```text
InvestigationPlanV1
InvestigationStageReceiptV1
ApprovalReceiptV1
VulnerabilityClusterV1
SarifImportReceiptV1
BenchmarkReceiptV1
ProofBackendCapabilitiesV1
```

Add JSON schemas only for artifacts intended for external consumption. Internal Rust persistence can use typed serde structs, but export boundaries need explicit versioning.

## Preserve module-registry authority

The investigation orchestrator must not grow its own tool-option parser or execution path. It compiles stage requests, then dispatches through the same descriptor/authorization/runtime boundary used by scan, shell, and run.

---

# Testing strategy

Each PR should add the narrowest contract tests at its new boundary.

## Domain tests

Pure tests for:

- verdict conversion;
- patch eligibility;
- plan validation/digest stability;
- cluster invariants;
- backend capability -> proof-strength mapping;
- reopened-state derivation.

## Application tests

Fixture-based tests for:

- profile -> plan compilation;
- resume/skip/refuse decisions;
- role context blindness;
- exact approval binding;
- apply/reverify interruption;
- SARIF normalization.

## Integration tests

Use synthetic vulnerable fixtures to prove:

```text
signal -> assessment -> empirical reproduction -> draft -> approval -> apply -> reattack -> verified
```

and failure variants:

```text
static plausible but runtime not reproduced
patch builds but benign control fails
patch blocks original but variant bypasses
source changed after approval
originating detector cannot be replayed
proof backend degraded/unavailable
```

## Existing repository gates

Every implementation PR must remain compatible with the repo's existing architecture/CRAP/model-safety gates. Broad verification should happen only after focused tests pass.

---

# Metrics that should become product invariants

Kuzushi should eventually surface these per investigation and per benchmark:

```text
candidate signals
unique observations
semantic clusters
human-confirmed findings
static plausible rate
empirical reproduction rate
false-confirmation rate
cost per empirically reproduced finding
patch-draft success rate
build/test-validated patch rate
approved application rate
original exploit block rate
benign-control preservation rate
variant bypass rate
detector replay clean rate
reopened rate
```

The key north-star metric should not be “findings generated.” A better measure is:

> **cost per independently reproducible, evidence-backed vulnerability that reaches a safe verified remediation or a defensible handoff state.**

---

# Explicit non-goals

- Do not add “100 agents” to match MDASH marketing.
- Do not build a mandatory cloud control plane.
- Do not make an LLM judge authoritative for patch correctness.
- Do not replace the existing module registry with a workflow framework.
- Do not collapse findings and vulnerability clusters into one overloaded identity type.
- Do not let exposure/risk enrichment upgrade proof state.
- Do not automatically commit, push, open a PR, or merge after patch application.
- Do not weaken no-silent-model-fallback or operator-owned model selection.
- Do not publish benchmark numbers from scaffold/self-test rows as live detection quality.

---

# Recommended first implementation slice

Start with **PR 1: proof vocabulary + typed patch eligibility** before building `InvestigationPlanV1`.

Why:

1. It corrects a trust ambiguity in an existing shipping path.
2. It creates the domain types every later orchestration layer should consume.
3. It is small enough to validate independently.
4. It prevents the new end-to-end Fix workflow from institutionalizing a generic `exploitable` boolean as its security boundary.

After PR 1 lands, build `InvestigationPlanV1` as a behavior-preserving architectural migration. Only then add new Prepare, role-policy, clustering, and closed-loop remediation behavior.

The intended end state is not “Kuzushi has features similar to MDASH and CodeMender.” It is stronger and more specific:

> **Kuzushi is the local-first, vendor-neutral security evidence workbench where every serious vulnerability can move through a typed chain from signal, to independent assessment, to empirical reproduction, to reviewed patch, to reattack-verified remediation—with the complete provenance replayable and measurable.**
