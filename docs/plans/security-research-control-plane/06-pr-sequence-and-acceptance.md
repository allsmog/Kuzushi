# PR Sequence and Acceptance Program — Kuzushi Security Research Control Plane

> **Status:** proposal for review
> **Date:** 2026-08-19
> **Plan index:** [security research control-plane productization](./README.md)
> **Roadmap constraint:** the current [ROADMAP](../../../ROADMAP.md) remains authoritative.

---

## 1. Proposed first twelve implementation PRs

These are deliberately small and reviewable. Titles are illustrative.

### PR 1 — `feat(research): define observation-boundary domain`

Changes:

- pure domain types;
- completeness states;
- bounds and redaction;
- focused serialization tests;
- no runtime integration.

Acceptance:

- no unbounded free-form payloads;
- no optimistic default completeness;
- unknown and unavailable remain distinct.

### PR 2 — `feat(runs): record source and static observation boundary`

Changes:

- derive boundary from one existing scan path;
- persist artifact/reference;
- add run projection;
- export in JSON/markdown.

Acceptance:

- included/excluded/failed surfaces reconcile;
- no clean claim without boundary;
- existing run schemas remain backward compatible.

### PR 3 — `feat(research): add evaluator receipt contract`

Changes:

- evaluator identity;
- outcome vocabulary;
- evidence/boundary references;
- writer event and projection;
- schema tests.

Acceptance:

- direct backend promotion rejected;
- evidence unavailable cannot satisfy predicate;
- receipt is immutable.

### PR 4 — `feat(eval): emit deterministic path evaluator receipt`

Changes:

- adapt one existing static path mechanism;
- exact input/tool/config identity;
- negative and inconclusive fixtures.

Acceptance:

- same artifacts produce same outcome;
- parser/index failure is inconclusive;
- model prose cannot change evaluator outcome.

### PR 5 — `feat(eval): account for every candidate terminal reason`

Changes:

- funnel state/reason;
- summary reconciliation;
- no candidate loss.

Acceptance:

```text
input = malformed + duplicate + unsupported + rejected + inconclusive + positive + blocked/failed
```

### PR 6 — `feat(research): persist questions and hypotheses`

Changes:

- IDs, events, projection;
- falsification predicate;
- propose/accept/reject;
- read-only queries.

Acceptance:

- accepted hypothesis requires predicate;
- model cannot accept its own proposal;
- replay stable.

### PR 7 — `feat(research): link experiment plans to prepared dispatch`

Changes:

- plan digest;
- target identity;
- requested authority;
- authorization binding;
- run/attempt link.

Acceptance:

- changed input invalidates authorization;
- direct executor calls impossible;
- one attempt maps to one run.

### PR 8 — `feat(research): record observations and dispositions`

Changes:

- observations;
- evaluator application;
- disposition events;
- finding links.

Acceptance:

- automated disposition requires receipt;
- contradictory receipts retained;
- finding identity unchanged.

### PR 9 — `feat(cli): inspect and export research trees`

Changes:

```text
research list
research show
research tree
research export
```

Acceptance:

- plain/JSON parity;
- bounded output;
- deterministic ordering;
- no TUI dependency.

### PR 10 — `feat(research): dogfood static-to-runtime campaign`

Changes:

- reference fixture;
- static path attempt;
- runtime attempt;
- patch retest;
- negative and incomplete cases.

Acceptance:

- complete end-to-end replay;
- exact boundary disclosure;
- no overclaim from local harness;
- closure claim names rerun predicates.

### PR 11 — `feat(authority): persist startup authority manifest`

Changes:

- config/env/runtime/module/executable/grant identity;
- pre-effect recording;
- degraded unresolved state.

Acceptance:

- target source cannot silently escalate;
- secret values never persisted;
- manifest digest binds authorization.

### PR 12 — `feat(tui): project research lineage without new workflow state`

Changes:

- finding detail summary;
- research tree view;
- boundary/evaluator detail;
- no new mutable TUI store.

Acceptance:

- derives from application DTOs;
- CLI/TUI status parity;
- no phase advancement from page visits;
- snapshots disclose uncertainty.

---

## 2. Detailed acceptance program

### 2.1 Domain tests

- invalid state transitions rejected;
- automated disposition without receipt rejected;
- receipt after disposition time rejected;
- observation from another target rejected;
- changed plan digest invalidates authorization;
- cascade without source observation rejected;
- close question with active hypothesis requires explicit override;
- unbounded text rejected/clipped through shared policy;
- duplicate idempotency key does not duplicate events.

### 2.2 Persistence and replay

- append, crash, replay;
- truncated tail stops at last valid prefix;
- hash mismatch degrades;
- duplicate delivery idempotent;
- projection rebuild equals live projection;
- old targets with no research events remain valid;
- unknown future event version stops safely or is preserved according to V3 compatibility policy;
- SQLite can be deleted and rebuilt.

### 2.3 Authorization

- read-only static experiment needs no extra approval beyond descriptor policy;
- repository execution requires explicit approval;
- changed target snapshot invalidates stale authorization;
- expired authority rejected;
- canceled invocation cannot commit late observations;
- backend cannot request undeclared authority;
- target-local config cannot broaden grants.

### 2.4 Boundary

- excluded generated/vendor files visible;
- parser failure visible;
- truncation visible;
- unsupported language visible;
- local harness not rendered as deployment reachability;
- missing network/deployment scope not silently complete;
- required boundary missing → evaluator inconclusive;
- non-applicable boundary does not count as missing.

### 2.5 Evaluator

- deterministic fixtures stable;
- malformed evidence rejected;
- wrong target rejected;
- missing artifact rejected;
- conflicting evidence produces inconclusive or explicit conflict;
- evaluator version/digest change visible;
- model-produced text cannot satisfy a binary predicate by itself.

### 2.6 Reports

Every research export includes:

- target and Kuzushi identities;
- question/hypotheses;
- experiment plans and attempts;
- authority and boundary;
- observations and evaluator receipts;
- findings/proof links;
- human decisions;
- cost/latency;
- failures and blocked work;
- remaining uncertainty;
- reproduction instructions where safe;
- integrity/degradation state.

---

## 3. Definition of productized

This initiative is not productized merely because domain types exist.

It is productized when all of the following are true:

1. A new operator can start from a finding and open a research question without editing event JSON.
2. A hypothesis has a visible falsification predicate.
3. An existing tool can run as an authorized experiment without a parallel dispatch path.
4. Every result shows an observation boundary.
5. An evaluator receipt—not a model narrative—owns the automated disposition.
6. The research tree replays from durable state.
7. A negative result remains useful and queryable.
8. A finding displays exactly which proof dimensions were established.
9. A patch can be retested against the same predicates.
10. An export can be reviewed on another machine.
11. The campaign has complete terminal accounting and measured-or-unknown cost.
12. At least one real benchmark and one dogfood campaign pass.
13. The current repository-security golden path is not made slower or more confusing by default.
14. Broader backends remain optional and capability-scoped.
15. A design partner says the exported evidence replaces meaningful manual reconciliation work.

---

## 4. Risks and mitigations

### 4.1 Scope explosion

**Risk:** “Research control plane” becomes justification for browsers, binaries, cloud, MCP discovery, and pentesting at once.

**Mitigation:** enforce roadmap gates and first vertical slice; each backend requires a separate RFC/benchmark.

### 4.2 Duplicate truth systems

**Risk:** research status diverges from runs, findings, or proof.

**Mitigation:** link canonical identities; reuse run terminal states; findings remain authoritative; all research writes use V3 events.

### 4.3 Model narrative masquerades as science

**Risk:** persuasive explanations are interpreted as evaluator outcomes.

**Mitigation:** closed evaluator receipt contract; model-only results capped and labeled; automated disposition requires receipt.

### 4.4 Schema burden

**Risk:** too many public schemas freeze an immature design.

**Mitigation:** begin with internal Rust/event types; publish only after a complete vertical slice and migration review.

### 4.5 Dangerous experimentation

**Risk:** a hypothesis plan is treated as permission to execute.

**Mitigation:** preserve descriptor effect/approval policy; authorization binds exact plan/target/authority; fail closed on stale authority.

### 4.6 TUI overload

**Risk:** research objects create a second complex cockpit.

**Mitigation:** CLI/domain first; project through existing phases; add only read-only DTO-backed TUI views after stability.

### 4.7 False completeness

**Risk:** a boundary summary becomes another optimistic score.

**Mitigation:** dimensioned completeness; unknown/unavailable explicit; evaluator-required dimensions; wording tests.

### 4.8 Backend supply-chain risk

**Risk:** external proof backends expand trusted code and executable authority.

**Mitigation:** digest identity, capability grants, conformance corpus, strict output, host-owned commit, maturity labels.

### 4.9 Benchmark gaming or contamination

**Risk:** research prompts or corpus knowledge leak into evaluation.

**Mitigation:** manifest holdout/contamination status, fixed seeds, blinded slices where possible, raw denominator disclosure.

### 4.10 Commercial distraction

**Risk:** licensing/team/cloud work arrives before core credibility.

**Mitigation:** design partners and paid pilots first; no cloud requirement; benchmark gate before platform expansion.

---

## 5. Open decisions

These should be resolved during review, not guessed during implementation.

### 5.1 Naming

Options:

- `research` — clearest for the scientific loop;
- `investigation` — familiar to AppSec teams;
- `case` — useful container but too generic;
- `experiment` — too narrow for question and remediation lineage.

Recommendation: use `research` as the bounded context and “investigation” in operator-facing prose where it reads more naturally.

### 5.2 Confirmation vocabulary

Should hypothesis states include `Confirmed` in v1?

Recommendation: no. Start with:

```text
proposed
accepted
active
reproduced
falsified
inconclusive
superseded
expired
```

Add `confirmed` only when domain-specific evaluator policies define it precisely.

### 5.3 First evaluator

Candidates:

- static source-to-sink predicate;
- exact runtime crash reproduction;
- patch retest predicate.

Recommendation: static source-to-sink first because it is deterministic, bounded, and uses existing infrastructure; add runtime reproduction in the vertical slice.

### 5.4 Question creation

Should any model automatically create questions?

Recommendation: models may propose; an operator or explicit campaign policy creates/accepts them. Avoid uncontrolled research-tree growth.

### 5.5 Research object retention

Recommendation: research events follow target event retention; large artifacts follow existing run/CAS retention policies. Pruning must not leave a disposition claiming evidence that is no longer available without marking that degradation.

### 5.6 External backend API

Recommendation: do not publish a stable external `ProofBackend` API until two internal adapters share it. Premature public abstraction would freeze the wrong boundary.

### 5.7 Commercial boundary

Recommendation: keep all core evidence and replay local and open. Validate paid workflow features through design partners before deciding license boundaries.

---

## 6. Review checklist

Reviewers should reject this plan if it:

- creates a second mutable database;
- bypasses `ModuleRegistry`;
- bypasses the writer actor;
- lets a model confirm itself;
- treats prompt transcripts as required durable state;
- changes finding identity;
- introduces browser/binary/agent-estate breadth before current evidence and benchmark gates;
- adds TUI state before domain/replay;
- creates arbitrary execution authority;
- collapses observation boundary to one score;
- uses confidence as a substitute for proof;
- claims productization without a vertical slice and benchmark.

Reviewers should approve the direction only if the first implementation slices make the current repository-security product more truthful and more defensible even if no later backend is ever built.

---

## 7. Recommended immediate next action

After this RFC is reviewed, the first code issue should be:

> **Add an additive, replayable observation-boundary contract to one existing static scan path, and require one deterministic evaluator to disclose missing or degraded required surfaces.**

That work is narrow, strengthens current roadmap P1-P3, creates no new scanner or TUI feature, and tests the most important product principle:

> Kuzushi must never claim more than it could observe.

Only after that contract survives implementation and review should the minimal question/hypothesis ledger begin.
