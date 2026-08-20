# Domain model: keep the product finding-centered

## 1. Design rule

The product must not expose a second security-research domain beside findings.

The operator already understands:

```text
Target
Run
Finding
Evidence
Proof
Decision
Artifact
```

Those remain the primary nouns.

Internal research state may exist to make planning, replay, and evaluation correct, but it is projected into the existing TUI and durable truth systems.

## 2. User-visible objects

### 2.1 Target

A selected project with stable identity:

```rust
struct ResearchTarget {
    workspace: WorkspaceTarget,
    source_identity: TargetContentIdentity,
    current_revision: Option<GitRevision>,
}
```

The target is not a “campaign.” It is the same target used by Map, Scan, findings, proof, and Fix.

### 2.2 Research attempt

A research attempt is an ordinary Kuzushi run or parent/child run union with an additive purpose:

```rust
enum ScanPurpose {
    Standard,
    ExploitabilityResearch,
    ProofFollowUp { finding_identity: FindingIdentity },
}
```

The purpose affects planning and presentation. It does not create a new run store.

### 2.3 Finding

A research candidate becomes a normal durable finding only after host validation.

The finding keeps:

- stable target-scoped identity;
- weakness and structural locator;
- evidence;
- observation sources;
- static proof state;
- runtime verification;
- human decision;
- remediation history;
- current next proof plan;
- PoC artifact references.

Model-generated text cannot define canonical identity.

### 2.4 Evidence

Evidence remains typed and attributable.

Research adds evidence kinds only when existing kinds cannot represent the claim:

```text
source span
source/sink/path
configuration influence
process effect
filesystem effect
network effect
crash
controlled output
authorization decision
observer receipt
evaluator receipt
reproducer artifact
```

Every evidence item binds to:

- target identity;
- producing run and attempt;
- backend identity;
- artifact digest;
- observation boundary;
- timestamp;
- safe bounded summary.

### 2.5 Proof plan

A proof plan is the next-action projection for one finding.

```rust
struct FindingProofPlan {
    finding_identity: FindingIdentity,
    target_identity: TargetContentIdentity,
    current_state: ExploitProofSnapshot,
    next_step: Option<ProofStep>,
    blocked_reason: Option<ProofBlocker>,
    estimated_cost: Option<Money>,
    estimated_runtime: Option<DurationRange>,
    required_backend: Option<ProofBackendIdentity>,
    plan_digest: Digest,
}
```

The TUI uses it for:

```text
NEXT v establish attacker control
```

A proof plan is not proof. It is advisory host-owned planning state.

### 2.6 Proof receipt

A completed proof experiment produces a receipt:

```rust
struct ProofReceipt {
    receipt_id: ProofReceiptId,
    finding_identity: FindingIdentity,
    target_identity: TargetContentIdentity,
    experiment_run_id: RunId,
    backend: ProofBackendIdentity,
    evaluator: EvaluatorIdentity,
    input_artifacts: Vec<ArtifactRef>,
    observation_boundary: ObservationBoundaryRef,
    outcome: EvaluatorOutcome,
    effect_evidence: Vec<EvidenceRef>,
    receipt_digest: Digest,
}
```

Only a valid receipt may advance runtime proof dimensions.

### 2.7 PoC bundle

A PoC bundle is an export artifact, not new mutable state.

```rust
struct PocBundleManifest {
    finding_identity: FindingIdentity,
    target_identity: TargetContentIdentity,
    proof_snapshot: ExploitProofSnapshot,
    reproduction_summary: ReproductionSummary,
    artifacts: Vec<ArtifactRef>,
    known_limits: Vec<ProofLimit>,
    bundle_digest: Digest,
}
```

Export reads durable state. It does not manufacture stronger proof.

## 3. Internal-only research state

These objects may exist internally but should not become normal TUI pages.

### 3.1 Research strategy

A generated, ranked unit of work:

```rust
struct ResearchStrategy {
    id: StrategyId,
    target_identity: TargetContentIdentity,
    surface: ResearchSurface,
    template: StrategyTemplateIdentity,
    rationale: SafeText,
    expected_yield: Option<Score>,
    expected_cost: Option<Money>,
    expected_runtime: Option<DurationRange>,
    risk: StrategyResourceRisk,
    requirements: StrategyRequirements,
    plan: Vec<PlannedToolCall>,
}
```

It can reuse or extend the current Strategy Proposal domain.

### 3.2 Experiment attempt

An individual controlled variant inside a strategy:

```rust
struct ExperimentAttempt {
    id: ExperimentAttemptId,
    strategy_id: StrategyId,
    run_id: RunId,
    variant_identity: Digest,
    changed_variables: Vec<ControlledVariable>,
    held_constants: Vec<BoundIdentity>,
    terminal: ExperimentTerminal,
}
```

The operator normally sees aggregate progress and results, not one row per variant.

### 3.3 Observation

A bounded statement about an effect:

```rust
struct ResearchObservation {
    id: ObservationId,
    attempt_id: ExperimentAttemptId,
    kind: ObservationKind,
    evidence: Vec<EvidenceRef>,
    boundary: ObservationBoundaryRef,
    confidence: ObservationConfidence,
}
```

An observation is not automatically a finding or proof transition.

### 3.4 Evaluator receipt

The evaluator answers a closed question over exact evidence.

Examples:

```text
Did the process execute the expected marker?
Did the write occur outside the admitted root?
Did the crash reproduce under the exact harness?
Did source data reach the sink under the specified guards?
Did the patch remove the original primitive?
```

The receipt is internal infrastructure projected into Prove and Replay.

### 3.5 Cascade edge

A completed observation may suggest another strategy or proof step.

```rust
struct ResearchCascadeEdge {
    source_observation: ObservationId,
    proposed_strategy: StrategyId,
    rationale: SafeText,
}
```

This supports automatic follow-up without creating a visible hypothesis tree.

## 4. State relationships

```text
Map evidence
  -> generated ResearchStrategy
  -> admitted Scan plan
  -> ExperimentAttempt
  -> ResearchObservation
  -> candidate normalization
  -> Finding observation
  -> FindingProofPlan
  -> ProofReceipt
  -> ExploitProofSnapshot
  -> PoC bundle
```

Durable source-of-truth ownership stays explicit:

| State | Source of truth |
| --- | --- |
| Map evidence | Existing target artifacts, CAS, V3 log, projections |
| Strategy proposal and correction | Existing strategy domain / V3-compatible durable queue |
| Run lifecycle | `items.jsonl`, run summary, target log terminal bridge |
| Finding identity and observations | Findings domain and target event log |
| Human decision | Append-only finding decision event |
| Runtime proof | Proof receipt and finding proof event |
| SQLite rows | Rebuildable projection |
| PoC bundle | Immutable export manifest and referenced artifacts |

## 5. Proof snapshot

The TUI needs one coherent projection:

```rust
struct ExploitProofSnapshot {
    static_state: StaticProofState,
    reproduction: ReproductionState,
    attacker_control: AttackerControlState,
    boundary_crossing: BoundaryCrossingState,
    primitive: PrimitiveState,
    reachability: ReachabilityState,
    impact: ImpactState,
    freshness: ProofFreshness,
    observation_limits: Vec<ProofLimit>,
}
```

These dimensions remain orthogonal.

A crash may be reproduced while attacker control is unknown.

A write primitive may exist only in a local harness.

An effect may cross a workspace boundary without proving a kernel sandbox escape.

A model assessment may increase prioritization but cannot advance empirical dimensions.

## 6. Candidate lifecycle

```text
signal
  -> source-grounded candidate
  -> linked/static candidate
  -> reproduced anomaly
  -> attacker-controlled behavior
  -> boundary or primitive established
  -> impact demonstrated
  -> clean reproduction
```

Candidates may also terminate as:

```text
rejected false positive
expected behavior
not reachable
not reproducible
harness incomplete
observer unavailable
inconclusive
duplicate
out of scope
superseded by stronger finding
```

No candidate disappears without a terminal reason.

## 7. Invariants

### 7.1 No second truth system

- Internal strategies and experiments do not own findings.
- External backends return untrusted candidates and evidence references.
- The host writer actor commits canonical events.
- SQLite is a projection.
- Run sidecars are exports or receipts, not a second mutable database.

### 7.2 Models propose; evaluators decide

A model may:

- rank surfaces;
- draft a strategy;
- draft a harness;
- explain an observation;
- propose a proof step;
- summarize impact.

A model may not assert that:

- a process executed;
- a boundary was crossed;
- attacker control exists;
- a crash reproduced;
- a PoC succeeded;
- a patch closed the primitive.

Those require host-owned evidence and evaluator receipts.

### 7.3 Missing is not negative

```text
observer unavailable != no effect
harness build failed != not reproduced
backend absent != rejected
candidate not rediscovered != verified absent
unknown cost != zero cost
```

### 7.4 Exact identity binds proof

Proof transitions bind to:

- target content identity;
- finding identity;
- backend and evaluator identity;
- harness and input digests;
- policy and authority digest;
- observation boundary;
- run receipt.

Relevant identity change makes the proof stale.

### 7.5 Human decisions survive machine reruns

A later scanner or model may add observations. It must not silently rewrite an explicit human decision.

### 7.6 Bounded semantics only

Persist:

- safe summaries;
- identities;
- predicates;
- outcomes;
- artifact references;
- costs;
- timings;
- terminal reasons.

Do not persist:

- hidden reasoning;
- raw model transcripts;
- unrestricted stdout/stderr;
- credentials;
- target secrets;
- unbounded mutation payloads in semantic events.

## 8. TUI projection mapping

| Internal state | Default TUI projection |
| --- | --- |
| Research surface ranking | Map priority rows |
| Generated strategy plan | Map NEXT summary and optional Strategy Queue |
| Active experiment | Run Focus semantic step |
| Experiment funnel | Scan |
| Deduplicated candidate | Review finding row |
| Current proof dimensions | Review compact snapshot and Prove |
| Next proof plan | `NEXT v ...` |
| Evaluator outcome | Prove receipt/replay |
| Observation limitation | Scan coverage and Prove limits |
| PoC manifest | Prove export surface |
| Cascade proposal | Automatically generated next proof plan or advanced Strategy Queue |

## 9. Compatibility approach

The first implementation should be additive:

- add a Scan purpose/profile rather than a new workflow enum;
- add proof dimensions without changing existing static proof labels;
- add optional receipt and boundary references;
- reuse existing finding identity;
- reuse current strategy proposal and correction mechanics where possible;
- preserve CLI, shell, and run preparation through `ModuleRegistry`;
- preserve current `.kuzushi/v3` paths;
- publish schemas only after one internal vertical slice stabilizes the shape.

Compatibility shims are preferable to a migration that rewrites existing finding or proof rows.
