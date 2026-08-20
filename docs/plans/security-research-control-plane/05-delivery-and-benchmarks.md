# Delivery, dogfood, benchmarks, and adoption

## 1. Delivery principle

Do not productize broad “AI security research.”

Deliver one narrow end-to-end promise:

> Point Kuzushi at a source project, run one exploitability-first sweep, select one candidate, press `v` to advance proof, and export a reproducible PoC bundle.

The first release should use existing engines and workflow surfaces wherever possible.

## 2. First vertical slice

Use one synthetic vulnerable fixture with a realistic project-controlled boundary.

Recommended fixture:

```text
A small coding-agent-like CLI:
- loads project configuration;
- displays one path in an approval decision;
- resolves a different canonical executable target;
- has a safe mode and a deliberately vulnerable mode for test mutation;
- emits observable process and filesystem effects.
```

The vertical slice proves:

1. Map ranks the path/command boundary.
2. The generated strategy runs without opening Strategy Queue.
3. Run Focus displays semantic progress.
4. Scan accounts for strategy and variant outcomes.
5. Candidate ingest creates one stable finding.
6. Review shows current primitive and next proof step.
7. `v` proves attacker control with a deterministic evaluator.
8. A second `v` proves or falsifies boundary crossing.
9. Prove displays observation limits.
10. `e` exports a self-contained PoC bundle.
11. Replay reconstructs the sequence.
12. Changing the target revision stales the proof.

## 3. Dogfood sequence

### 3.1 Stage A: deterministic fixture

Goals:

- zero model dependency;
- fast local execution;
- exact expected findings;
- exact proof transitions;
- exact PoC manifest;
- CI-safe.

### 3.2 Stage B: nondeterministic harness fixture

Add:

- flaky reproduction;
- invalid attempts;
- budget stop;
- observer failure;
- harness incomplete;
- candidate deduplication;
- proof planner retry policy.

### 3.3 Stage C: real open-source project

Choose a project with:

- a fixed historical vulnerability;
- reproducible vulnerable revision;
- buildable local harness;
- published patch;
- clear attacker entry point.

Measure whether Kuzushi:

- ranks the relevant surface;
- discovers or imports the candidate;
- rejects nearby false positives;
- advances to the known primitive;
- verifies patch closure.

### 3.4 Stage D: Pwn2Own-style dogfood

Point Kuzushi at a checked-out complex target project.

The objective is not to claim a contest vulnerability. It is to validate operator workflow:

```text
one target
one bounded sweep
background execution
small Review queue
finding-specific proof advancement
reproducible export
```

Contest-specific rules and final submission work remain outside the product.

## 4. Product metrics

### 4.1 Time to first useful result

Measure:

```text
time to first source-grounded candidate
time to first reproduced anomaly
time to first proof-ready finding
time to first PoC export
```

### 4.2 Precision

Measure:

```text
candidate observations
deduplicated findings
human-rejected findings
evaluator-falsified findings
proof-ready findings
reproduced findings
```

Do not report only raw detection count.

### 4.3 Proof upgrade

```text
signal -> linked
linked -> reproduced
reproduced -> attacker controlled
controlled -> boundary/primitive
primitive -> impact
impact -> clean reproduction
```

Report conversion and attrition reasons.

### 4.4 Cost

Measure:

```text
cost per strategy
cost per candidate
cost per human-reviewed finding
cost per reproduced finding
cost per proof-state upgrade
cost per exported PoC
```

Unknown remains unknown, never zero.

### 4.5 Reliability

Measure:

- valid reproduction attempts;
- success ratio;
- invalid attempt ratio;
- harness build success;
- observer availability;
- cancellation and settlement correctness;
- replay integrity;
- PoC clean-machine success.

### 4.6 Coverage honesty

Measure completeness across:

- source inventory;
- language parsing;
- entry-point mapping;
- selected research surfaces;
- strategy execution;
- runtime observers;
- backend availability;
- generated/vendor code;
- resource caps.

## 5. Benchmark manifest

Every published or retained benchmark result binds:

```text
Kuzushi commit and version
target repository and revision
target build identity
configuration and research plan digest
model/provider identity when used
prompt and policy digests
backend and sandbox identities
observation boundary
cost and timing
seed and attempt policy
terminal funnel
finding and proof outcomes
PoC reproduction result
```

A score without this manifest is not comparable.

## 6. Benchmark corpus

Initial corpus:

1. deterministic project-boundary fixture;
2. historical source-to-sink CVEs;
3. parser/crash fixtures;
4. path/archive extraction fixtures;
5. command execution and configuration fixtures;
6. authorization logic fixtures;
7. patched vulnerable revisions for closure testing.

The corpus should include negative controls and near-miss variants.

## 7. Acceptance thresholds for first release

Suggested release gates:

- every admitted strategy has a terminal outcome;
- every persisted candidate has validated evidence or a visible degraded state;
- no model-only path advances empirical proof;
- proof receipts bind target and observation identity;
- a clean target revision stales prior proof when required;
- the deterministic fixture exports a PoC reproducible on a clean machine;
- no known false “confirmed” state in adversarial tests;
- cancellation and budget exhaustion settle every run;
- TUI and plain projection agree on next action and proof state;
- the normal journey does not require Strategy Queue.

## 8. TUI journey testing

Add an executable DevEx journey:

```text
J-RESEARCH-01 project to PoC
```

Steps:

1. launch `kz --target <fixture>`;
2. commit deterministic Map;
3. verify Map priorities;
4. start exploitability research;
5. background and reopen completed run;
6. inspect Scan funnel;
7. open Review;
8. select the expected finding;
9. press `v`;
10. complete proof run;
11. inspect Prove;
12. export PoC;
13. verify target source unchanged;
14. restart Kuzushi and replay the proof.

At compact terminal sizes, preserve:

- target;
- phase/page;
- attempt outcome;
- candidate count;
- selected finding;
- proof state;
- observation limit;
- one NEXT action.

## 9. Packaging and distribution

No new distribution product is required.

The feature ships in the existing native package.

Possible later packaging:

```text
Core
  Map, bounded research plan, Review/Prove, local PoC export

Labs
  fuzz, differential, browser, binary, or protocol backends

Team
  shared policy/evaluator packs and review synchronization
```

Do not gate proof honesty or replay behind a paid tier.

## 10. Operator documentation

User docs should answer:

- What does exploitability-first research do?
- What authority can it use?
- How much can it cost?
- How do I background it?
- What is a candidate versus reproduced finding?
- What does `v` prove?
- Why is proof inconclusive?
- How do I export a PoC?
- How do I delete or prune research artifacts?
- Which backends are available on my platform?

The quick-start story:

```bash
kz --target ./project
```

Then:

```text
Enter Start Map
Enter Start research
b
Review
v
e
```

## 11. Design-partner evidence

Before broad positioning, run with at least three experienced operators on real projects.

Observe:

- whether Map priorities are understandable;
- whether default plans feel trustworthy;
- whether users open Strategy Queue;
- whether Scan funnel explains failures;
- whether Review ranking matches human judgment;
- whether `v` selects a useful next experiment;
- whether PoC bundles reduce manual work;
- whether resource usage is acceptable.

A design partner should complete the journey without instruction beyond the one-command starting point.

## 12. Product positioning

Avoid:

```text
autonomous zero-day machine
Pwn2Own autopilot
AI hacker that proves everything
```

Use:

> Kuzushi is the local-first terminal workbench that turns project security signals into replayable, evaluator-backed exploit evidence.

The differentiator is not the number of agents. It is the governed transition from candidate to proof.

## 13. Scope gates for later work

A new specialist backend requires:

1. a real project use case;
2. a deterministic or bounded evaluator;
3. an observation-boundary contract;
4. sandbox and authority design;
5. artifact and retention limits;
6. TUI integration through existing surfaces;
7. benchmark fixtures;
8. no new top-level workflow unless the current cockpit cannot represent the truth.

Cloud, collaboration, marketplace, and fleet research stay deferred until the local project-to-PoC journey is credible.
