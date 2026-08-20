# Implementation sequence and acceptance

## 1. Sequencing rule

Do not begin by building a generic research ledger, a new TUI page, or a new exploit engine.

Build one end-to-end journey through existing surfaces:

```text
Map priority
-> generated research plan
-> Run Focus
-> Scan funnel
-> Review candidate
-> `v` proof step
-> Prove receipt
-> PoC export
```

Each PR should be independently reviewable and preserve current behavior when the feature is not selected.

## 2. PR A — Exploitability research purpose and options

### Goal

Represent exploitability-first Scan intent through the existing descriptor and preparation system.

### Changes

- Add an additive research purpose/profile to canonical scan input.
- Add descriptor-backed options for:
  - research enabled/purpose;
  - time or cost budget;
  - maximum strategy count;
  - maximum experiment variants;
  - automatic low-risk strategy selection;
  - optional focus text.
- Ensure CLI, shell, and run consume the same canonical input.
- Reject unknown and incompatible inputs at preparation.
- Record the resolved purpose and option digest in run metadata/input.

### Non-goals

- No research strategy implementation.
- No TUI redesign.
- No proof changes.
- No new environment-variable product controls.

### Acceptance

- [ ] Preparation produces byte-equivalent canonical input across modes.
- [ ] Target-local config cannot select a model or increase execution authority.
- [ ] Missing model leaves deterministic research available and model-backed strategies unavailable.
- [ ] Run input and summary disclose the purpose and budget.
- [ ] Existing standard scans remain unchanged.

## 3. PR B — Map research-priority projection

### Goal

Add an explainable research-priority section to Map.

### Changes

- Define a pure `ResearchSurfacePriority` presentation/domain projection.
- Derive priorities from existing current-revision Map evidence.
- Include score factors and missing evidence.
- Render top priorities in TTY and plain mode.
- Add one `NEXT` action to start research.
- Preserve Summary/DFD/Entry points/Components ownership and navigation.

### Acceptance

- [ ] No priority exists without supporting Map evidence.
- [ ] Priority reasons are stable and bounded.
- [ ] Missing generated/vendor/native visibility appears as a limitation.
- [ ] Page visits do not change workflow state.
- [ ] Compact mode retains top priority and NEXT.
- [ ] Existing Map snapshots update intentionally.

## 4. PR C — Strategy synthesis and default plan

### Goal

Generate a bounded research plan without requiring Strategy Queue interaction.

### Changes

- Add strategy templates for the first fixture:
  - static boundary trace;
  - path/configuration differential;
  - sandboxed effect reproduction.
- Reuse or adapt current Strategy Proposal, preflight, correction, cost, runtime, risk, and terminal fields.
- Generate proposals from Map priorities.
- Auto-select only low-risk admitted strategies inside budget.
- Persist one plan artifact and strategy queue lineage.
- Open Run Focus from the Map action.

### Acceptance

- [ ] The normal fixture journey never opens Strategy Queue.
- [ ] Advanced Strategy Queue shows the same generated strategies.
- [ ] Every unselected strategy has a reason.
- [ ] Explicit operator corrections take precedence over regeneration.
- [ ] High-risk/effectful strategies require explicit approval.
- [ ] Estimated cost and runtime appear before launch.
- [ ] No target mutation occurs outside a disposable admitted workspace.

## 5. PR D — Research funnel and Scan projection

### Goal

Make completed research legible and complete.

### Changes

- Add terminal outcome vocabulary for strategy and experiment stages.
- Produce `research-funnel.json` as a declared artifact.
- Bridge bounded terminal facts into target events.
- Project tested surfaces, strategy outcomes, candidate counts, proof-ready count, cost, duration, and observation coverage into Scan.
- Add plain/JSON equivalent projection.

### Acceptance

- [ ] Every admitted strategy terminates.
- [ ] Every generated candidate terminates as rejected, deduplicated, degraded, or persisted.
- [ ] Partial, failed, blocked, skipped, and unavailable remain distinct.
- [ ] Clean output is scoped to the observation boundary.
- [ ] Parent/child run union does not double-count candidates.
- [ ] Restart reconstructs the same Scan summary.
- [ ] Compact TUI and plain output preserve the same truth.

## 6. PR E — Candidate normalization and Review ranking

### Goal

Turn research observations into a small, useful Review queue.

### Changes

- Validate research candidate evidence at host ingest.
- Compute canonical identity from host-owned structural evidence.
- Attach observation source and reproduction summaries.
- Add a research-value projection using inspectable factors.
- Show primitive/reproduction state in Review rows and selected detail.
- Preserve human decision authority.

### Acceptance

- [ ] Producer-controlled canonical fingerprints are rejected.
- [ ] Same defect across strategies converges on one finding.
- [ ] Distinct loci remain distinct.
- [ ] Fabricated or unavailable citations visibly degrade.
- [ ] Ranking never changes severity or proof state.
- [ ] Human decisions survive later observations.
- [ ] A candidate may be rejected without deleting its funnel receipt.

## 7. PR F — Finding proof planner and `v`

### Goal

Make `v` execute the smallest useful next proof step.

### Changes

- Add additive exploit proof dimensions.
- Create pure proof-step selection over current finding/proof/target/backend state.
- Project exact NEXT wording in Review and Prove.
- Bind the existing `v` action to prepared proof input.
- Open Run Focus with the finding and proof claim.
- Report blockers when no safe backend is available.

### Acceptance

- [ ] The planner never treats a model assessment as empirical proof.
- [ ] The same state produces the same plan digest.
- [ ] A changed target invalidates or replans the step.
- [ ] The first fixture transitions through attacker control and boundary crossing separately.
- [ ] Missing observer produces blocked/inconclusive, not negative proof.
- [ ] `v` targets the displayed finding even under filters.
- [ ] Plain mode prints the exact equivalent command.

## 8. PR G — Evaluator receipt and proof transition

### Goal

Advance proof only from authenticated, host-owned receipts.

### Changes

- Define internal evaluator identity, predicate, input, outcome, and receipt.
- Bind target, authority, observation, backend, harness, and artifact identities.
- Commit receipts through the writer actor.
- Update proof projection from receipts.
- Add replay and stale-proof behavior.
- Expose relevant evidence and limits in Prove.

### Acceptance

- [ ] Missing receipt cannot advance empirical state.
- [ ] Invalid experiment cannot count as success or failure.
- [ ] Conflicting receipts remain visible and resolve by explicit policy.
- [ ] Receipt replay is deterministic.
- [ ] Artifact or target identity change stales the dependent state.
- [ ] Raw model output cannot set evaluator outcome.
- [ ] Proof and human decision remain separate.

## 9. PR H — PoC bundle export

### Goal

Export a selected finding’s reproducible evidence without adding a new workflow phase.

### Changes

- Add Prove contextual export action.
- Define bundle manifest and file layout.
- Include target identity, proof snapshot, reproduction command/procedure, receipts, observation limits, known gaps, and hashes.
- Copy or reference minimized harness/input artifacts safely.
- Render preview and final receipt.
- Add secret and path safety.

### Acceptance

- [ ] Bundle export never mutates finding/proof truth.
- [ ] Missing artifacts block or visibly degrade export.
- [ ] Bundle reproduces on a clean fixture checkout.
- [ ] Known proof gaps appear in human and machine-readable summaries.
- [ ] Absolute local paths and credentials are absent.
- [ ] Bundle files authenticate against the manifest.
- [ ] Fix and Report semantics remain unchanged.

## 10. PR I — Dogfood, benchmarks, and release gates

### Goal

Prove the whole journey works and is worth using.

### Changes

- Add deterministic vulnerable fixture and negative controls.
- Add `J-RESEARCH-01` TUI journey.
- Add benchmark manifest.
- Measure funnel, precision, proof upgrade, cost, time, reproduction, and PoC success.
- Add one historical real-world vulnerability replay.
- Document operator workflow and resource cleanup.

### Acceptance

- [ ] One clean-machine project-to-PoC journey passes.
- [ ] Negative controls produce no proof-ready finding.
- [ ] Candidate attrition is fully accounted.
- [ ] Unknown cost remains unknown.
- [ ] Cancellation and budget exhaustion settle every unit.
- [ ] Target source remains unchanged during read-only/default research.
- [ ] Hosted and local validation boundaries are reported honestly.
- [ ] Release remains blocked if a false empirical confirmation is possible.

## 11. Recommended first implementation slice

The first code PR after alignment should be smaller than PR A through I combined.

Implement:

```text
one additive Scan purpose
one deterministic Map priority
one generated static strategy
one Scan funnel row
one expected fixture finding
one static next-proof plan
```

No runtime proof yet.

This establishes the vertical seams without inventing the final backend interface.

The second code PR can add the deterministic sandboxed proof receipt for the same fixture.

## 12. Repository seams

Likely implementation areas:

```text
crates/kuzushi-core/src/modules/application/sast_scan/
crates/kuzushi-core/src/modules/
crates/kuzushi-core/src/strategy/
crates/kuzushi-core/src/findings/domain/
crates/kuzushi-core/src/findings/persistence/
crates/kuzushi-core/src/storage_v3/writer_actor/
crates/kuzushi-cli/src/application/
crates/kuzushi-tui/src/app/
crates/kuzushi-tui/src/ui_view_models/
crates/kuzushi-tui/src/renderer/
schemas/
examples/
tests/
docs/
```

Implementers must locate the current canonical seam before editing; this list is a map, not authorization to duplicate policy across layers.

## 13. Validation ladder

### Focused domain tests

- priority scoring;
- strategy admission;
- funnel reduction;
- candidate normalization;
- proof planning;
- evaluator outcomes;
- staleness;
- PoC manifest.

### Mode parity

- shell and headless prepared input;
- TTY/plain/JSON projection;
- same target and run identities;
- same proof state and next action.

### Integration

- full fixture run;
- interruption recovery;
- budget stop;
- backend unavailable;
- observer failure;
- target revision change;
- duplicate candidate convergence;
- clean PoC replay.

### Quality

- format;
- focused tests;
- strict Clippy;
- CRAP-risk;
- architecture and model-safety gates;
- docs checks;
- quick repository verification;
- full suite before release-bound schema or packaging changes.

## 14. Risks

### Scope explosion

Mitigation: one fixture, three strategy templates, one proof ladder, no new page.

### False confirmation

Mitigation: evaluator receipt required for empirical transitions; adversarial tests around observer and harness failure.

### Resource growth

Mitigation: budget and artifact caps, disposable workspaces, retention policy, integration with prune.

### TUI overload

Mitigation: project priorities in Map, funnel in Scan, candidates in Review, proof in Prove; advanced state stays in Replay/Strategy Queue.

### Duplicate truth

Mitigation: writer actor and existing finding/event/run stores remain canonical.

### Backend abstraction too early

Mitigation: implement the first backend internally; stabilize a public trait only after at least two real adapters share the boundary.

## 15. Rollback

The documentation PR is additive.

Each implementation PR should be independently revertible.

Persisted additions should be versioned and optional until the vertical slice is stable. Existing runs and findings must remain readable without research artifacts.
