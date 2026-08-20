# Kuzushi exploitability-first research plan

> **Status:** product and architecture proposal for PR review

> **Scope:** project-first research through the existing Kuzushi TUI

> **Supersedes in this PR:** the earlier campaign-oriented “security research control plane” interaction model
> **Does not supersede:** [`ROADMAP.md`](../../../ROADMAP.md), the canonical terminal cockpit contract, or the existing control-room PRD

## Decision

The product should not ask an operator to create a research campaign, maintain a hypothesis database, import contest rules, or learn a second workflow.

The product should start with one project:

```bash
kz --target /path/to/project
```

Kuzushi then uses its existing terminal cockpit to:

1. map high-value attack surfaces;
2. generate and execute bounded exploit-oriented research strategies;
3. account for what was tested, skipped, reproduced, or inconclusive;
4. rank the few findings worth human attention;
5. choose the next missing proof step for a selected finding;
6. export a reproducible proof-of-concept bundle.

The user-visible flow remains:

```text
Target -> Setup -> Map <-> Run Focus -> Scan <-> Run Focus
       -> Review -> Prove <-> Run Focus -> Fix -> Report
```

This proposal does **not** add a Campaign page, Hypotheses page, Experiments page, authority-graph page, or research dashboard. It does not repurpose Fix as offensive exploit packaging. Fix remains remediation. A proof-of-concept export is a contextual action from Prove.

## One-sentence promise

> Point Kuzushi at a project; it finds the dangerous boundaries, runs exploitability-first research, ranks the strongest candidates, and lets the operator press `v` to push a candidate toward reproducible proof.

## What the operator sees

The default journey is intentionally small:

```text
$ kz --target ./project

Setup
  one target, a preselected safe Map plan, optional model/budget readiness
  -> Enter Start Map

Map
  ranked attack surfaces and trust boundaries
  -> Enter Start research

Run Focus
  current research steps, bounded output, cost, background/cancel controls
  -> b to background or remain and observe

Scan
  tested surfaces, experiment funnel, reproduced anomalies, skipped coverage
  -> Review

Review
  ranked exploit candidates with primitive and reproduction state
  -> v on one candidate

Prove
  current proof ladder, evidence, observation limits, and one next experiment
  -> v repeatedly until proof is strong or the candidate is rejected
  -> e to export a PoC bundle
```

The normal path does not require opening Strategy Queue. Strategy Queue remains an advanced inspection and correction surface for operators who want to see or alter the generated research plan.

## What is automatic

After the operator commits the Map or Scan action, Kuzushi may automatically:

- derive likely trust boundaries from repository context;
- rank parsers, deserializers, command execution, filesystem, process, network, authentication, native, and cross-component surfaces;
- generate bounded research strategies;
- auto-select low-risk read-only strategies within the approved budget;
- run static, structural, differential, mutation, and sandboxed reproduction work;
- deduplicate repeated anomalies into stable findings;
- reject candidates that fail deterministic checks;
- attach a next proof plan to serious findings;
- background long-running work;
- update proof freshness when the project revision changes.

Automatic does not mean ambient authority. Repository execution, target mutation, external actions, network use, and materially expensive work still pass through existing descriptor, approval, budget, sandbox, and no-silent-fallback policy.

## What remains internal

The DEF CON research comparison identified useful architectural concepts:

- research hypotheses;
- controlled experiments;
- cascade lineage;
- observation boundaries;
- startup authority;
- evaluator receipts;
- exploitability milestones;
- trajectory-level policy.

These concepts are useful for correctness, replay, and planning, but they are **not new primary operator objects**.

They remain implementation details behind the existing durable objects:

```text
Target
Run
Finding
Evidence
Proof
Human decision
Artifact
```

An operator may inspect detailed lineage in Replay or Trace, but the normal workflow is finding-centered.

## Product boundary

### In scope for the first product increment

- repository-centered AppSec and product-security research;
- source and build metadata;
- project-controlled configuration and instruction surfaces;
- parser and deserializer boundaries;
- command, filesystem, process, and network authority transitions;
- existing static/CPG/CodeQL evidence;
- bounded harness generation and sandboxed reproduction;
- class-specific proof ladders;
- reproducible PoC export.

### Not in scope for the first increment

- contest administration;
- Pwn2Own registration or rules management;
- cloud collaboration;
- endpoint monitoring;
- generic autonomous pentesting;
- browser, hypervisor, firmware, mobile, or automotive exploit engines;
- an external plugin marketplace;
- a new persistent research database;
- a replacement for the findings store or V3 event log;
- a TUI page for every internal research concept.

Specialist backends may be added later, but they must plug into the same finding, proof, run, authorization, and replay contracts.

## Why this fits Kuzushi

Kuzushi already has the correct product shape:

- a local-first Rust terminal cockpit;
- deterministic Target and Setup readiness;
- Map, Scan, Review, Prove, Fix, and Report;
- foreground Run Focus with backgrounding, steering, cancellation, and durable receipts;
- a persistent Strategy Queue;
- findings with stable identity, evidence, proof, human decisions, and replay;
- descriptor-backed tools and one shared dispatch boundary;
- explicit runtime/model selection;
- scoped KWP and plugin authority;
- append-only V3 events and hash-linked run items;
- cost and budget accounting.

The missing work is connective tissue:

```text
Map evidence
  -> exploitability-ranked strategies
  -> bounded research sweep
  -> candidate funnel accounting
  -> finding-specific next proof plan
  -> evaluator-backed proof transitions
  -> PoC export
```

## Pwn2Own as dogfood, not product structure

Pwn2Own is a valuable dogfood scenario because it demands:

- high-value attack-surface selection;
- aggressive false-positive rejection;
- reliable reproduction;
- precise separation of anomaly, primitive, boundary crossing, and impact;
- self-contained evidence.

Kuzushi should help discover and prove a bug in a checked-out target project. It should not become a Pwn2Own campaign manager.

A representative dogfood journey is:

```bash
kz --target ./coding-agent-project
```

Then:

```text
Map identifies project-controlled configuration, tool execution,
path containment, and child-process authority as high-value surfaces.

Scan runs bounded research strategies.

Review ranks two proof-ready candidates.

Prove drives one candidate from a reproduced target mismatch
to attacker control, boundary crossing, and a minimized PoC.

Export writes a self-contained evidence bundle.
```

Contest-specific eligibility and final submission formatting remain downstream work.

## Success criteria

The product is successful when a serious operator can:

1. point Kuzushi at a project without creating any new campaign object;
2. understand in Map why Kuzushi chose its research priorities;
3. launch a bounded sweep with one action;
4. return later to a Scan receipt that accounts for every strategy and candidate;
5. see a Review queue ordered by research value rather than raw scanner severity;
6. press `v` and receive the correct next proof experiment;
7. distinguish reproduced behavior from attacker control, boundary crossing, and impact;
8. export a PoC that a second machine can reproduce;
9. replay how the finding reached its current proof state;
10. trust that missing visibility or failed execution did not become confirmation.

## Packet

- [`01-product-workflow.md`](./01-product-workflow.md) — complete TUI journey and screen contracts.
- [`02-domain-model.md`](./02-domain-model.md) — user-visible objects, internal-only research state, and invariants.
- [`03-persistence-boundary-authority.md`](./03-persistence-boundary-authority.md) — execution planning, durable events, observation and authority truth.
- [`04-proof-and-agent-horizon.md`](./04-proof-and-agent-horizon.md) — proof planner, class-specific ladders, evaluator contract, and backend boundary.
- [`05-delivery-and-benchmarks.md`](./05-delivery-and-benchmarks.md) — delivery gates, dogfood, metrics, packaging, and adoption evidence.
- [`06-pr-sequence-and-acceptance.md`](./06-pr-sequence-and-acceptance.md) — focused implementation sequence and acceptance program.

## Review decisions

Review should resolve these questions:

1. Is the one-project, existing-TUI workflow the correct product contract?
2. Should exploitability-first behavior be a Scan strategy selected automatically from Map, rather than a new top-level mode?
3. Should Strategy Queue remain advanced-by-default while generated strategies execute through the normal Map/Scan action?
4. Is `v` on a finding the single operator contract for advancing proof?
5. Should PoC export remain contextual to Prove, leaving Fix and Report semantics unchanged?
6. Is the first vertical slice narrow enough: one fixture, one research strategy family, one proof ladder, one PoC bundle?
