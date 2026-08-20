# Research execution, persistence, observation, and authority

## 1. Goal

Make exploitability-first research automatic without making it unauditable or unsafe.

The operator sees one Scan plan. Internally, Kuzushi must know:

- why each strategy was selected;
- what authority it required;
- which variants executed;
- what was observable;
- what terminal outcome each unit reached;
- what evidence supports each candidate;
- which evaluator advanced proof.

## 2. Planning from Map

The planner consumes current-revision durable Map evidence:

```text
repository inventory
components
entry points
routes
dependencies
threat model
static findings
CPG/CodeQL availability
existing tests and fixtures
build systems
language/runtime inventory
prior findings and proof gaps
```

It produces a bounded strategy set.

### 2.1 Research surface classes

Initial surface classes:

```text
input parsing and deserialization
authentication and authorization
command and tool execution
filesystem paths and archive extraction
process creation and child authority
network destinations and protocol peers
configuration and instruction loading
native/FFI boundaries
state-machine and concurrency transitions
cross-component data flow
patch-regression and historical vulnerable loci
```

### 2.2 Strategy templates

Initial templates should be compositional, not talk-named:

```text
static boundary trace
source-to-sink corroboration
differential configuration test
path canonicalization differential
metamorphic input mutation
dangerous-default review
lifecycle/state-transition mutation
bounded harness generation
sandboxed reproduction
crash minimization
authority-chain verification
patch primitive retest
```

A strategy template declares:

- compatible surfaces and languages;
- required Map evidence;
- required tools/backends;
- effect and approval class;
- resource estimates;
- expected outputs;
- terminal reasons;
- candidate normalization contract;
- evaluator contract.

## 3. Automatic selection policy

The normal user should not have to open Strategy Queue.

A strategy may be selected automatically only when:

- the operator started the research action;
- its effect is read-only or admitted sandbox execution;
- all descriptor and workspace requirements pass;
- the selected target and revision are bound;
- required backends are available;
- the expected cost fits the current budget;
- its resource risk is below the auto-select ceiling;
- no policy requires explicit per-strategy approval.

Strategies requiring target writes, repository mutation outside a disposable copy, network effects, external actions, privileged observers, or high resource risk remain explicit.

The generated plan receipt should summarize:

```text
selected 8
blocked 2
skipped unavailable 1
estimated cost $4.20
estimated runtime 35-70m
highest risk medium
```

## 4. Run structure

One parent Scan run owns the operator-visible attempt.

Child runs may own individual strategies or backends. Parent and child identities must remain linked through existing run semantics.

```text
parent exploitability Scan
├── static-boundary strategy
├── path-differential strategy
├── parser-mutation strategy
├── sandbox-reproduction strategy
└── candidate-normalization and ranking
```

The parent result contains aggregate references, not copied raw payloads.

## 5. Suggested additive run artifacts

Canonical run files remain unchanged.

Research producers may declare:

| Artifact | Purpose |
| --- | --- |
| `research-plan.json` | Selected and rejected strategy summaries with digests and requirements |
| `research-funnel.json` | Terminal accounting from strategy through finding |
| `observation-boundary.json` | Visible, partial, unavailable, and omitted surfaces |
| `evaluator-receipts.jsonl` | Bounded evaluator outcomes and evidence references |
| `proof-plan.json` | Optional finding-specific next proof plan |
| `poc-manifest.json` | Export-only PoC bundle manifest |

These are producer-declared artifacts registered in `artifacts.json`, not new canonical mutable stores.

## 6. Semantic events

Additive target-wide events may include:

```text
ResearchPlanAccepted
ResearchStrategyTerminal
ResearchObservationCommitted
ResearchCandidateDispositioned
FindingProofPlanUpdated
ProofEvaluatorReceiptCommitted
PocBundleExported
```

Events should carry identities and references, not artifact bodies.

Example:

```rust
struct ResearchStrategyTerminalEvent {
    target_identity: TargetContentIdentity,
    parent_run_id: RunId,
    strategy_id: StrategyId,
    template_digest: Digest,
    outcome: StrategyTerminalOutcome,
    result_artifacts: Vec<ArtifactRef>,
    cost: Option<Money>,
    duration: Duration,
    terminal_reason: SafeText,
}
```

## 7. Funnel accounting

The funnel is a first-class product invariant.

```text
Map surfaces considered
  -> strategies proposed
  -> strategies admitted
  -> strategies completed/partial/blocked/failed
  -> experiment variants attempted
  -> observations emitted
  -> candidates normalized
  -> candidates deduplicated
  -> candidates rejected
  -> findings persisted
  -> findings proof-ready
```

Every item entering a stage receives one downstream terminal reason.

This enables trustworthy metrics and prevents silent candidate loss.

## 8. Observation boundary

Every research attempt and proof receipt declares what could be observed.

```rust
struct ObservationBoundary {
    target_identity: TargetContentIdentity,
    source_scope: SourceObservationScope,
    build_scope: BuildObservationScope,
    runtime_scope: RuntimeObservationScope,
    process_scope: DimensionState,
    filesystem_scope: DimensionState,
    network_scope: DimensionState,
    authorization_scope: DimensionState,
    kernel_scope: DimensionState,
    omitted_surfaces: Vec<OmittedSurface>,
    degraded_surfaces: Vec<DegradedSurface>,
    limits: Vec<ResourceLimit>,
    boundary_digest: Digest,
}
```

Dimension states:

```text
complete
partial
unavailable
unknown
not_applicable
```

There is no default `complete`.

### 8.1 Source boundary

Include:

- target content identity;
- included and excluded roots;
- generated/vendor/submodule treatment;
- languages detected;
- parsers/indexers available;
- parser failures;
- CPG/CodeQL build identity;
- file, byte, depth, timeout, and candidate caps.

### 8.2 Runtime boundary

Include:

- harness identity;
- sandbox backend;
- OS/platform;
- process-tree visibility;
- filesystem visibility;
- network visibility;
- authorization/approval event visibility;
- crash/sanitizer collection;
- missing kernel or container detail;
- time and resource caps.

### 8.3 TUI disclosure

Scan shows aggregate coverage.

Prove shows only limits relevant to the selected proof claim.

Examples:

```text
process and filesystem effects observed
kernel sandbox state unavailable
```

or:

```text
source path complete for Rust and TypeScript
generated code excluded
```

## 9. Authority manifest

Automatic research must not rely on ambiguous startup authority.

Before an effectful strategy begins, bind:

```rust
struct ExecutionAuthorityManifest {
    target_identity: TargetContentIdentity,
    prepared_tool_input_digest: Digest,
    runtime_and_model: Option<RuntimeSelectionReceipt>,
    config_sources: Vec<AuthoritySource>,
    environment_influence: Vec<EnvironmentInfluence>,
    executable_resolutions: Vec<ExecutableResolution>,
    capability_grants: Vec<CapabilityGrantRef>,
    explicit_approvals: Vec<ApprovalRef>,
    sandbox_identity: Option<SandboxIdentity>,
    authority_digest: Digest,
}
```

This can extend current run provenance rather than introducing a separate user-facing artifact for every run.

### 9.1 Rules

- Target-controlled input cannot increase operator authority.
- Relative executable and path resolution must be recorded after canonical preparation.
- Missing or changed authority identity invalidates a proof receipt that depends on it.
- Model selection remains explicit and no-silent-fallback.
- External backends receive only declared capabilities.
- Plugin and KWP outputs remain untrusted until host validation and writer commit.

## 10. Experiment isolation

Research strategies may need to mutate or execute a project.

The default safety order is:

1. read-only source snapshot;
2. disposable workspace copy;
3. OS-sandboxed process;
4. container or VM backend when required;
5. explicit external target only when the operator authorizes it.

The active source checkout should not be mutated by a research experiment unless the tool descriptor explicitly requires and receives target-write approval.

Generated harnesses and mutations live in run or module workspaces and are referenced by digest.

## 11. Candidate ingest

A backend returns candidate observations:

```rust
struct ResearchCandidate {
    producer: BackendIdentity,
    weakness: Option<Weakness>,
    structural_location: StructuralLocation,
    title: SafeText,
    severity_hint: Severity,
    evidence: Vec<UntrustedEvidenceRef>,
    requested_proof_hint: Option<ProofHint>,
}
```

The host:

1. validates paths, spans, artifacts, and grants;
2. reads source where necessary;
3. computes canonical identity;
4. normalizes evidence;
5. applies candidate limits;
6. deduplicates against existing identity;
7. commits through the writer actor;
8. records rejected or degraded candidates in funnel accounting.

Producer fingerprints remain provenance only.

## 12. Evaluator receipts

An evaluator receipt is immutable and closed-form.

```rust
enum EvaluatorOutcome {
    Satisfied,
    Falsified,
    Inconclusive,
    InvalidExperiment,
    ObserverUnavailable,
    BackendFailed,
}
```

It binds:

- predicate identity and version;
- exact input artifacts;
- target identity;
- authority manifest digest;
- observation-boundary digest;
- backend identity;
- deterministic or statistical policy;
- output evidence;
- outcome.

A model cannot author the final outcome field.

## 13. Reproduction policy

Reproduction is measured, not inferred.

```rust
struct ReproductionSummary {
    attempts: u32,
    successes: u32,
    failures: u32,
    invalid_attempts: u32,
    median_duration: Option<Duration>,
    environment_identities: Vec<Digest>,
    success_predicate: EvaluatorIdentity,
}
```

Invalid attempts do not count as failures or successes.

A single successful run may establish an observation but should display its sample size.

## 14. Replay

Replay must reconstruct:

- selected strategy plan;
- strategy terminal outcomes;
- candidate funnel;
- finding observation lineage;
- proof plan at the time;
- proof receipts;
- current proof projection;
- PoC export manifest.

Unknown event versions, hash breaks, gaps, or malformed tails stop at the last valid prefix and disclose degraded replay.

## 15. Retention and disk discipline

Exploit research can generate large harness, corpus, build, crash, and trace artifacts.

The plan must:

- keep semantic events bounded;
- store large data in CAS or declared artifact roots;
- enforce per-run and per-strategy byte caps;
- make retention visible before launch;
- integrate with existing run pruning;
- distinguish required PoC artifacts from disposable search intermediates;
- avoid permanent per-worktree build roots where possible;
- never silently delete an artifact referenced by a retained proof receipt.

## 16. Security boundaries

The first implementation must preserve:

- one prepared dispatch boundary;
- descriptor-backed options;
- explicit effect and approval;
- target-relative path safety;
- process-group cancellation;
- no ambient KWP exec;
- deny-by-default plugin authority;
- host-computed finding identity;
- evidence validation;
- writer-actor durability;
- no raw secrets or prompts in lifecycle streams;
- explicit model/runtime selection;
- cost accounting that distinguishes unknown from zero.
