# Delivery, Benchmarks, and Product Path — Kuzushi Security Research Control Plane

> **Status:** proposal for review
> **Date:** 2026-08-19
> **Plan index:** [security research control-plane productization](./README.md)
> **Roadmap constraint:** the current [ROADMAP](../../../ROADMAP.md) remains authoritative.

---

## 1. Evaluation and benchmark program

### 1.1 Research funnel accounting

Every candidate entering a campaign gets a terminal reason.

Suggested stages:

```text
generated
malformed
duplicate
unsupported
visibility_incomplete
signal_only
static_path_established
static_rejected
runtime_planned
runtime_blocked
runtime_failed
runtime_not_reproduced
runtime_reproduced
reachability_established
primitive_established
impact_demonstrated
patched
retested
closed
```

A candidate cannot disappear between stages.

### 1.2 Core metrics

#### Verified precision

```text
verified true positives / all reviewed positive findings
```

Always disclose the review denominator and unresolved count.

#### Oracle recall

```text
known vulnerabilities detected / known vulnerabilities in eligible boundary
```

“Ineligible boundary” must be separate from “missed.”

#### Proof-upgrade rate

```text
findings that advance to a stronger evidence dimension / findings entering Prove
```

#### Cost per confirmed finding

```text
total measured campaign cost / confirmed findings
```

Unknown cost remains unknown; it is never zero.

#### Time to first verified finding

From campaign start to the first host-evaluator-backed finding.

#### Research replay rate

Percentage of terminal hypotheses whose projection and evaluator inputs can be reconstructed from durable artifacts.

#### Boundary completeness

Report each dimension, not a single score.

#### Funnel loss

Counts and percentages by terminal reason.

#### Patch closure strength

Distribution of closure claims:

```text
signal-only
static
runtime
primitive
exposure
impact
```

### 1.3 Executed benchmark manifest

Every benchmark slice should bind:

```text
target/corpus digest
Kuzushi commit and config digest
model/provider/version
prompt and policy digests
tool/plugin/backend identities
sandbox/executor identity
seed and repetition policy
observation boundary
authority manifest digest
evaluator identity
cost and latency
terminal outcome
contamination/holdout status
```

### 1.4 Initial benchmark tracks

Before broader backends:

1. repository vulnerability discovery;
2. static path adjudication;
3. runtime reproduction;
4. patch closure;
5. negative-hypothesis accounting.

Later:

6. browser effects;
7. binary exploitability;
8. agent authority/trajectories;
9. malicious peers and deployment paths.

### 1.5 No fabricated metrics

If an experiment is not implemented, the metric is undefined.

Do not infer persistence from same-session behavior.
Do not infer exploitability from a crash.
Do not infer full recall from eligible files only without disclosing eligibility.
Do not infer zero cost from missing accounting.
Do not infer a fixed vulnerability from a missing scanner result.

---

## 2. Product packaging and commercial path

### 2.1 Product shape

The recommended product remains one Kuzushi workbench with progressively richer capabilities.

#### Community/core

- local-first repository workbench;
- findings/evidence/proof;
- research questions, hypotheses, experiments, evaluator receipts;
- built-in static and existing runtime backends;
- local replay and export;
- public schemas;
- one-target campaigns.

#### Pro hypothesis

Potential paid value—validate before implementing license machinery:

- saved research campaign templates;
- richer multi-run/campaign comparison;
- advanced proof backends;
- scheduled local campaigns;
- signed/digest-bound review bundles;
- customizable evaluator and policy packs;
- expanded benchmark dashboards;
- long-term evidence retention controls;
- priority backend support.

#### Team/enterprise hypothesis

- shared policy/evaluator packs;
- role-based approvals;
- team review queues;
- fleet campaign coordination;
- CI quality and proof-regression gates;
- organization-wide benchmark baselines;
- audit exports;
- optional remote workers;
- SSO and administrative policy only when a team coordination product exists.

The core evidence format, replay, and local inspection should not require the cloud.

### 2.2 Do not monetize scanner count

Scanner breadth is easy to copy and hard to price sustainably.

The paid value should be:

- governed workflow;
- proof depth;
- reproducibility;
- team review;
- policy;
- benchmark credibility;
- integration and support.

### 2.3 Product discovery before pricing

Before committing to pricing:

1. interview at least 10 senior AppSec/product-security practitioners;
2. demo a complete research case, not a module catalog;
3. ask which artifact they would take to a developer, reviewer, or incident lead;
4. measure time currently spent reconciling scanner/model output;
5. recruit 3 design partners with real repositories;
6. seek at least one paid pilot before building cloud collaboration.

A paid pilot can be services-assisted. The goal is to validate the workflow's value, not pretend the product is self-serve before the benchmark is credible.

### 2.4 Positioning

Recommended one-line positioning:

> **Kuzushi is the local-first security research workbench that turns scanner and AI output into replayable, evaluator-backed findings you can defend.**

Alternative for a technical audience:

> **A security-research control plane for hypotheses, experiments, proof, remediation, and benchmark truth.**

Avoid:

- “autonomous hacker”;
- “AI finds every vulnerability”;
- “multi-agent pentest platform”;
- “fully verified” without boundary qualification.

---

## 3. Go-to-market proof before broad expansion

### 3.1 Reference workflows

Build and publish internally first:

1. **Kuzushi self-security campaign**
   Question: can target-controlled input influence executable or module authority before canonical dispatch?

2. **Known vulnerable repository campaign**
   Question: can the system progress from scanner signal to static path, runtime witness, patch, and exact retest?

3. **Negative research campaign**
   Several plausible hypotheses are rejected, demonstrating that Kuzushi preserves and explains negative evidence rather than producing only positive findings.

4. **Cross-engine disagreement campaign**
   Semgrep/CodeQL/CPG/model-backed tools disagree; evaluator receipts and operator decisions produce one defensible finding state.

### 3.2 Public credibility artifacts

Do not launch the broader story until Kuzushi can show:

- a real scoreboard;
- one complete replayable campaign bundle;
- cost and failure accounting;
- false-positive accounting;
- one patch closure with a stronger claim than signal disappearance;
- an honest observation-boundary report;
- reproducibility on a clean machine.

### 3.3 Design-partner demo

A 20-minute demo should be:

1. open one question;
2. inspect two hypotheses;
3. run an existing static experiment;
4. show the boundary and evaluator receipt;
5. promote a finding only to the proof actually earned;
6. run a runtime attempt;
7. show blocked/inconclusive behavior honestly;
8. patch and rerun;
9. export the bundle.

Do not spend the demo browsing dozens of tools.

---

## 4. Implementation sequence

### Phase 0 — Align and freeze contracts

**Goal:** review this RFC and settle the smallest domain vocabulary before code.

Deliverables:

- accepted relationship to the control-room PRD and roadmap;
- naming decision: `research`, `investigation`, or another bounded context;
- initial event list;
- initial observation-boundary dimensions;
- first evaluator kind;
- first vertical-slice use case;
- explicit non-goals.

Exit:

- reviewers can identify the first three code PRs;
- no unresolved disagreement about finding versus hypothesis identity;
- no plan to bypass existing dispatch, writer, artifact, or authorization boundaries.

### Phase 1 — Truth primitives

#### 1A. Observation boundary

Add a minimal additive domain type for:

- target identity;
- source inclusion/exclusion;
- static engine coverage/failures;
- runtime harness scope;
- omissions and completeness.

Attach it to one existing run path and export it. No hypothesis model yet.

Exit:

- a clean or positive result cannot be rendered without its boundary;
- missing required boundary forces an honest degraded status;
- replay produces the same boundary summary.

#### 1B. Evaluator receipt

Add a host-owned evaluator receipt with:

- evaluator identity;
- exact input references;
- boundary reference;
- closed outcome vocabulary;
- reasons;
- determinism declaration.

Use one deterministic evaluator already present in Kuzushi.

Exit:

- model output cannot manufacture a satisfied evaluator receipt;
- unavailable evidence is not success;
- receipt replay and schema validation pass.

#### 1C. Terminal funnel accounting

Add terminal reason accounting to one existing campaign/scan path.

Exit:

- every candidate entering the selected path has a terminal reason;
- summary counts reconcile to input counts;
- unknown/unsupported/blocked remain separate.

### Phase 2 — Minimal research ledger

#### 2A. Question and hypothesis events

Implement:

- create question;
- propose/accept/reject hypothesis;
- falsification predicate;
- read-only projection.

No experiment execution yet.

#### 2B. Experiment linkage

Link an authorized prepared tool run to an experiment plan and attempt.

Reuse:

- `ModuleRegistry`;
- existing approval;
- existing run creation;
- existing cancellation/settlement;
- existing artifacts.

#### 2C. Observation, evaluator, disposition

Commit observation and evaluator references through the writer actor. Apply a host-owned disposition.

#### 2D. Replay and export

Add:

```text
research list
research show
research tree
research export
```

Exit:

- a complete question → hypothesis → experiment → observation → disposition tree replays deterministically;
- no raw prompt/response is needed to reconstruct it;
- existing findings can link to the tree without identity migration.

### Phase 3 — First product vertical slice

**Use only existing repository-security capabilities.**

Recommended slice:

> A source-to-sink hypothesis investigated by a static path backend, optionally followed by the existing runtime verification path.

Required behavior:

1. open a question from an existing finding;
2. create a hypothesis with a typed path predicate;
3. execute a prepared existing tool;
4. capture the boundary;
5. record observations;
6. apply a deterministic evaluator;
7. update research disposition;
8. link the finding and proof state;
9. export the campaign;
10. rerun after a patch.

Exit:

- one reference fixture passes end to end;
- one negative case is rejected;
- one incomplete-boundary case remains inconclusive;
- one blocked authorization case remains blocked;
- one patch retest produces an exact closure claim.

### Phase 4 — Operator experience and benchmark

#### 4A. TUI projection

Only after CLI/domain stability:

- research summary in finding detail;
- active hypothesis/experiment view;
- boundary and evaluator inspector;
- next-action projection.

#### 4B. Benchmark scoreboard

Measure:

- eligible recall;
- verified precision;
- cost;
- latency;
- funnel loss;
- replay rate;
- closure strength.

#### 4C. Reference bundles

Check in or publish reproducible example campaigns that do not expose sensitive target data.

Exit:

- a design partner can understand the workflow without repository internals;
- benchmark metrics come from executed manifests;
- the TUI consumes application DTOs rather than reading stores directly.

### Phase 5 — Startup authority

Add the manifest to model-backed and executable experiments.

Start with:

- config sources;
- environment influence;
- executable resolution;
- loaded modules/MCP;
- model/runtime selection;
- grants/denials.

Then add adversarial conformance fixtures.

Exit:

- every effectful experiment has a pre-effect authority manifest;
- target-controlled authority escalation attempts are refused and visible;
- packaged release behavior is tested, not just source design.

### Phase 6 — Broader backends, gated

Order after existing roadmap P3:

1. browser/CDP;
2. malicious protocol peer;
3. authority graph importer;
4. trajectory runtime on Kuzushi-owned effects;
5. binary solver import;
6. deployment exposure observation.

Each backend must land as a narrow adapter plus benchmark, not as a new architecture.

### Phase 7 — Team product, only after usage evidence

Potential work:

- shared policy and evaluator packs;
- reviewer/approver roles;
- fleet research campaigns;
- signed exports;
- organization scoreboards;
- optional coordination service.

Do not build this from speculation.

---
