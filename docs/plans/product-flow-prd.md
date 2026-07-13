# PRD — Kuzushi as a control room for non-deterministic security scans

> **Status:** proposal, awaiting review. **Owner:** operator experience.
> **Current-state reconciliation:** 2026-07-12. Items marked Exists or Partial
> below reflect the live Rust tree; the remaining proposal is the sweep/harness
> composition layer, not the already-shipped onboarding, strategy queue,
> evidence-list, triage, or headless contracts.
> **Companion docs:** screen/interaction behavior in
> [`docs/design/product-flow-design-spec.md`](../design/product-flow-design-spec.md);
> code seams in [`docs/plans/cannon-port-plan.md`](./cannon-port-plan.md).
> **Grounded in:** the 2026-07 journey / devEX / token-waste / perf audits; a
> file-by-file map of current Kuzushi (`design-sync/kuzushi-tui-kit`); the
> cannon harness (`~/vibe-code/vuln-scan-cannon-harness`); Anthropic's
> defending-code reference harness; the three AIxCC-winning cyber-reasoning
> systems (atlantis / buttercup / theori); the IRIS neuro-symbolic taint method;
> and Google's OSS-Fuzz-Gen / Project Naptime→Big Sleep. Citations in §16.

---

## 1. Thesis

**An LLM security scan is non-deterministic and it costs money every time you
run it.** The same agent, pointed at the same code, surfaces different findings
run to run — and each run spends tokens and takes seconds-to-minutes per file.
That is not a bug to be fixed; it is the material the product is made of.
Anthropic's own reference harness says it plainly: *models are stochastic,
don't expect the nth run to have zero new findings* — and its entire design is
**two countermeasures**:

> **Any single AI scan is flaky and noisy. The countermeasures are: union across
> a permuted sweep (coverage from variance) and a separate adversarial verifier
> whose only job is to disprove findings (precision). Everything else — the
> ledger, the cockpit, seeding — is lifecycle management around those two.**

Kuzushi's job is to make that governable. It is the **control room** for
non-deterministic scans: a **control plane** to steer *where* the
non-determinism spends and *how hard* to corroborate it, and a **visual plane**
to *see* the otherwise-invisible agent reasoning — attack surface, threat model,
data-flow, attack chains, and a findings ledger with an honest proof state.

The 42 built-in modules are not a catalog to browse. They are **composable
parts** — detectors, analysis oracles, signal generators, verifiers — that the
operator (and the workflow) assemble into **strategies** and fire as **sweeps**
against a target, phase by phase.

**The pieces already exist.** Kuzushi ships a deduping findings ledger with
corroboration counts, sticky human triage, a three-tier model router, per-op
budget caps, batch triage, twelve MCP analysis servers, on-demand CPG/CodeQL
builds, a five-page security-visualization gallery, attack chaining, and
prompts-as-files. **What's missing is the room that composes and steers them:**
the sweep, the mutable harness, saveable strategies, per-scan engine enablement,
and a deterministic seed plane. This PRD specifies that room.

**One-sentence promise:** *point Kuzushi at a target, aim it, and fire
controlled sweeps of AI scans you can steer, price, corroborate, and see — until
you have confirmed, evidence-backed findings you can defend.*

---

## 2. The load-bearing idea (why this product exists)

Discovery is easy to parallelize; the bottleneck has moved to **verification,
triage, and patching** (Anthropic reference harness, `docs/blog-post.md`). A
product that just fires more agents produces more noise. The value is in the
loop that turns noisy, stochastic, expensive AI output into a small set of
corroborated, proven findings — **without clobbering the human's judgment along
the way.**

Two mechanisms recover signal from non-determinism, and both must be **operator-
controllable**, not buried:

1. **Sample** — fire a *sweep*: the same target hit from many angles
   (`focus × strategy × model × runs`), results **unioned and deduped** so
   coverage comes from variance instead of a single lucky pull.
2. **Corroborate** — a separate **adversarial verifier** (guilty-until-proven-
   innocent, multi-vote, blind, and where possible **crash/PoV-backed**) whose
   only job is to disprove. In the reference harness this roughly halved false
   positives; requiring a reproducing PoC drove them near zero.

Everything else in this PRD — the ledger, the two planes, budget, strategies,
the harness — is lifecycle management around those two mechanisms.

---

## 3. The problem with today's flow

Kuzushi works, and most of the machinery is real and good. The failure is that
it presents the **parts** but not the **control room**, so the operator cannot
actually govern a non-deterministic scan. Symptoms, each traceable to an audit
or the current-state map:

**A. Steering exists, but a sampled sweep does not.** The live Strategy Queue
persists proposals with expected cost/runtime, yield, rounds, preflight, risk,
approval, correction, and outcome; approved proposals can be fired from the
shell. What is still absent is the `focus × strategy × model × runs` matrix and
one sweep object that unions those sampled runs into a governed result.

**B. You can't shape the scan itself — the harness is frozen.** The engine
wiring, detector set, and tool graph are compile-time
(`builtin_registration.rs`). Prompt *text* is editable (prompt-override files +
the `PromptMutation` ledger), but you cannot mutate the **harness** — seed it
from recon, retarget it by typing *"focus on SQLi"*, or let coverage feedback
evolve it. Operator "focus" exists only as one-off `ask`/`prompt mutate`, not as
a first-class steering input that re-ranks the scan.

**C. Engines you own aren't controllable per-scan.** Kuzushi has 12 MCP oracle
servers, `cpg:build`, and `codeql-db:build`, but enablement is **artifact-
presence-gated** behind the scenes (`with_mcps_for_target` probes disk), never an
explicit, cost-estimated operator toggle in the run UI. There is no way to say
*"turn on the Joern CPG and the CodeQL DB for this confirm pass"* and see the
latency/cost that implies. LSP is a single clang MCP, not a general control.

**D. The two planes are conflated.** A deterministic seed (Semgrep/CodeQL/SARIF)
and a non-deterministic LLM hunt are different kinds of evidence that should
*corroborate* one row — Kuzushi's ledger already merges them and tags
`vuln_source` — but nothing lets you **ingest an external SARIF/Semgrep file** as
a seed, and nothing surfaces or steers the two planes as first-class surfaces.

**E. Strategy proposals are persistent, but reusable recipes remain partial.**
`StrategyProposal` and `StrategyCorrection` provide a durable approved/corrected
queue with runnable tool input and result lineage. They are not yet a named
recipe catalog such as `deep = pattern + iris-taint + review×2 + invariant`
that can be selected as the variant axis of a sampled sweep.

**F. The trust signifiers now follow persisted reality.** Findings and review
queues surface proof/confidence state; canceled/interrupted runs stay terminal;
journey state derives from workspace artifacts; and targetless views omit phase
chrome. The remaining visual-plane work is sweep-level aggregation: sampled-run
variance, cost, and corroboration are not yet one live control-room projection.

**G. The default is now a phase cockpit, not the catalog.** Workbench and the
planning picker drive the target through Map/Hunt/Confirm/Fix, while the module
catalog remains an advanced discovery surface. The missing step is to make the
approved Strategy Queue feed a visible sampled sweep instead of firing one
proposal at a time.

**H. Keyless first-run value exists.** Target and credential onboarding both
offer the offline fixture; it activates through the canonical target transition,
clears stale target state, and runs the deterministic demo without a model,
credential, network call, or external scanner.

**I. Duplicate triage is fixed; prompt caching remains.** Triage defaults to the
latest scan, collapses duplicate fingerprints, and skips persisted verdicts
unless the operator explicitly requests re-triage. The shipping model path still
lacks a proven prompt-cache contract for unchanged large context.

**J. The earlier headless blockers are closed.** `recon:import` is registered and
tested through the real registry; workspace-backed tools require an explicit
target; run preparation failures remain machine-readable; and export preserves
the requested format/path contract. These are regression invariants now, not
open product requirements.

**K. Detection quality is a claim, not a number.** `baseline.json` is `{}`;
`kuzushi-eval` exists but is recall-centric, standalone, and not a `kuzushi`
verb. No head-to-head-vs-SARIF, no regression gate, no prompt self-tuning.

**The through-line:** the differentiator is *governed evidence*. Today the
operator has the parts but not the controls to sample, steer, corroborate, and
see a non-deterministic scan. This PRD builds the control room.

---

## 4. What already exists (so we build the room, not the parts)

Grounding for every requirement below — verified against the current tree. The
gap is composition and control, not greenfield capability.

| Capability | Status | Where |
| --- | --- | --- |
| Deduping findings ledger, `corroboration_count`, severity-max merge | **Exists** (dedupes *within* a `scan_id`; accumulates *across* runs) | `findings/domain/finding_record.rs`, `persistence/open/finding_writes.rs` |
| Sticky human triage (`triaged_by`, refuses to overwrite human), suppress/snooze | **Exists** | `persistence/open/triage_and_verification.rs` |
| Three-tier model routing + per-role overrides (`Cheap/Mid/Deep`, `MODEL_<ROLE>`, `models.toml`) | **Exists** | `runtime/domain/response_and_roles.rs`, `agent_router/routed_runtime_dispatch.rs` |
| Per-op budget caps + spend ledger + cost-cap halt card | **Exists** | `spend/drop.rs`, `spend/parse_budget_flag.rs` |
| Batch triage over all findings, concurrency, `costCapUsd`, `stage2Tier` | **Exists** | `modules/triage/*` |
| Live Semgrep + CodeQL detectors (persist to the one ledger) | **Exists** | `native_scanners/register_modules.rs` |
| Attack chaining → attack-tree viz | **Exists** | `scan/engines/exploit_chain/`, `ui_view_models/viz_data.rs` |
| Threat-model build + TUI regenerate (`threats regen`, `g rebuild`) | **Exists** | `capabilities/threat_model/`, `modules/threat_model_module.rs` |
| 5-page viz gallery: 3D attack-surface terrain, DFD, exploit-chain, attack-path, heatmap | **Exists** | `renderer/views/scene/`, `ui_view_models/viz_data.rs` |
| 12 MCP oracle servers (tree-sitter, Joern, CodeQL, clangd, gtags, entry-points, …) | **Exists**, artifact-gated | `crates/kuzushi-mcp-*`, `runtime/mcp_probe.rs` |
| On-demand CPG + CodeQL DB build | **Exists** | `modules/cpg_module.rs`, `codeql_db_module.rs` |
| Neuro-symbolic taint (LLM specs → CPG/CodeQL flows → LLM triage), evidence ladder | **Exists** (experimental) | `capabilities/taint_iris_next/`, `docs/taint-iris-next.md` |
| Prompts-as-files (`.kuzushi/prompts/<module>/<verb>.md`) + mutation ledger | **Exists** | `options/prompt_paths.rs`, prompt-mutation ledger |
| Phase derivation 組→崩→作→掛 from workspace reality | **Exists** | `ui_view_models/journey.rs` |
| Phase-bucketed module catalog (42 modules, ~67 tools) | **Exists** | `builtins/.../builtin_registration.rs` |
| Persistent strategy proposals, approval/correction/fire, cost/runtime/preflight/outcome lineage | **Exists** | `strategy/`, `app/strategy/`, `ui_view_models/strategy_queue.rs` |
| Keyless offline demo through canonical target activation | **Exists** | `demo.rs`, `app/effects.rs`, `navigation_target_story.rs` |
| Latest-scan, verdict-aware, fingerprint-deduped triage | **Exists** | `modules/triage/` |
| Reachable `recon:import`, explicit target policy, machine-readable run errors, format-preserving export | **Exists** | `recon_module.rs`, CLI run/export tests |

| Missing connective tissue | Status |
| --- | --- |
| Signal-driven, priced, budget-gated **sweep** (`focus × strategy × model × runs`) | **Partial** (priced proposal queue exists; sampled matrix/union does not) |
| A mutable, recon-seeded, operator-steerable **harness** object | **New** |
| Named, saveable, replayable **strategies** | **Partial** (durable proposals/corrections exist; reusable recipe catalog does not) |
| Per-scan **engine enablement** UI (CPG/MCP/LSP toggle + cost estimate) | **New** (artifact-gated only) |
| **Deterministic seed ingest** (external SARIF/Semgrep file → ledger) | **New** (live-run only) |
| Engagement-scoped **cross-run merge** (corroborate one row across `scan_id`) | **New** (per-`scan_id` today) |
| Confirmed-vs-guess **in the findings list**; cost/corroboration always visible | **Partial** (proof/confidence exists; sweep cost/corroboration rollup does not) |
| LLM-authored **fuzz harness** build-and-fix loop (PoV proof) | **New** |
| Detection as a **number** (F1 + head-to-head-vs-SARIF + gate + tune) | **New** (`kuzushi-eval` standalone) |

---

## 5. The two planes

The user-facing model is two planes over one engagement folder and one ledger.

### 5.1 The control plane — steer the non-determinism

Everything the operator turns, in one place (surfaced at the phase-boundary
**steering gate**, §8 of the design spec):

- **The sweep** — the unit of sampled non-determinism: `focus × strategy ×
  model × runs`. Fire N permuted scans at one target; **union + dedupe** the
  results into the ledger with a corroboration count. `runs` samples variance;
  `strategy`/`focus` aim it; `model` tiers it.
- **Priced, budget-gated proposals** — signal generators (commit-archaeology
  incomplete-fix hunts, threat-model reachability audits, dependency-intel
  footguns, prompt evolution, fuzz-recon) *propose* priced sweeps ranked by
  yield. The operator approves under a hard budget cap; `$/round` self-calibrates
  from actuals. Cost is enforced **between** proposals; a single in-flight
  overshoot is surfaced, never hidden.
- **The harness** (§7) — the mutable scan config: which engines, which strategy,
  which model tiers, which focus areas, which oracle, which seeds.
- **Per-scan engine enablement** — turn on the Joern CPG, the CodeQL DB, specific
  MCP oracles, or the clangd LSP *for this pass*, with a **cost/latency estimate
  shown before you commit**, defaulting off for broad first-pass and on for a
  scoped confirm. Enablement stays **artifact-gated and honest** — never a silent
  heavyweight spin-up; a missing prerequisite refuses with an actionable build
  hint, it does not degrade silently.
- **The analysis-depth ladder** — `structural → linked → path (CPG) → proven
  (symbolic/PoV)`. The operator picks target depth; Kuzushi picks the engine.
  `minEvidenceLevel` becomes the user-facing knob.
- **Verify config** — `--when severity>=X --max N --votes K`, multi-lens
  (reachability / exploitability / mitigation), optional metamorphic and PoV.
- **Model tiering** — delegate cheap work (dedup, classify, easy triage) to weak
  models and hard work (root-cause, patch, PoV) to strong ones; per-role map +
  presets; same-role fallback on error; **cost-per-confirmed-finding** surfaced.
- **The seed plane** — ingest deterministic scanner output (Semgrep / CodeQL /
  SARIF) as `sources[]`, deduped and corroborated against the hunt.
- **Human judgment** — mark FPs, confirm, suppress; **sticky** — an AI re-run
  never overwrites a human verdict.

### 5.2 The visual plane — see the invisible

The agent's reasoning is otherwise a black box; the visual plane renders it (all
of this exists today — the PRD wires it to control-plane reality):

- **Attack surface** (3D terrain / route+entry map), **DFD**, **threat model**
  (trust-tier graph), **attack tree**, **attack chains**, **findings table** with
  proof markers, **coverage matrix** — the five-page `/scene` gallery + the
  Workbench cockpit.
- **Live sweep activity** — per-round DAG, which model, which strategy,
  **live cost**, agent tree, tool calls, latency; coverage growth for fuzz
  harnesses (`cov:`/`ft:`/`NEW`). The invisible spend made legible.
- **Hotkeys/commands to regenerate** the threat model, chains, or the attack
  surface when the picture drifts (`threats regen`, `r` for chains).
- **The proof story** — each finding shows its evidence tier, the oracle that
  produced it (structural / tree-sitter / Joern / CodeQL / PoV), its
  corroboration count, and its vote breakdown — the confirmed-vs-guess signal, in
  the list, not buried in detail.

---

## 6. Composable parts → strategies

The 42 modules are **parts of four kinds**, composed — never a catalog to shop:

| Kind | Parts (examples) | Role in a scan |
| --- | --- | --- |
| **Detectors** | `semgrep`, `codeql`, `static_review` (LLM), `secrets` (deterministic), `dynamic`/fuzz | turn a target into candidate findings |
| **Analysis oracles** | tree-sitter, Joern CPG, CodeQL, clangd LSP, entry-points, (KLEE, opt-in) | answer reachability / callers / taint-path deterministically |
| **Signal generators** | commit-archaeology, threat-model, dependency-intel, evolution, fuzz-recon | *propose* priced sweeps from evidence about the target |
| **Verifiers** | multi-lens vote, metamorphic, PoV/crash | try to disprove; promote proof state |

A **strategy** is a named, saveable, replayable recipe that composes parts — the
sweep's **"variant" axis**:

```
strategies/deep.toml     = pattern(semgrep+codeql) + iris-taint(CPG) + review×2 + invariant-check
strategies/quick.toml    = secrets + static_review×1
strategies/pr-review.toml = diff-scope + review + reachability-vote   (Full vs Delta mode)
```

Diversity + merge beats one pipeline: the AIxCC winners all run *many* diverse
engines/agents in parallel and funnel into one dedup/score gate (theori merges
five vuln sources; atlantis ensembles input-generators and three diverse patch
agents). Strategies make that composition a first-class, operator-owned object.

---

## 7. The harness — the mutable unit of a scan

"The harness" is the whole configuration of a non-deterministic scan, modeled as
**one versioned, editable artifact** under `engagement/` (not scattered flags):

```
harness = {
  focus_areas[]     # ranked {entry(file:function:line), input_surface, rank}
  strategy          # the composed recipe (§6)
  engines_enabled   # cpg? codeql-db? which MCP oracles? clangd LSP?
  model_tiers       # {find: mid, triage: cheap, verify: deep, patch: deep}
  runs / variants   # the sampling matrix
  oracle            # ASan/UBSan crash | asserted invariant | reachability
  seeds[]           # corpus seeds / operator hunches / imported findings
  budget            # cap + priced proposals
}
```

Three ways it mutates — this is the product's differentiator:

1. **Recon seeds it.** A recon/discover pass clusters attacker-reachable code
   into ranked focus areas, detects the toolchain/build system, and extracts an
   input vocabulary — pre-populating a partitioned harness plan (never hand a
   fuzzer `main()`). This is the "map" of the Aim phase.
2. **The operator edits it — by typing intent.** *"Focus on SQLi"* /
   *"target the parser"* is a **first-class steering input** that re-ranks focus
   areas, sets the oracle's CWEs, and biases seed generation. (This is the knob
   the fuzz-plugin sources lack and the reference harness only gestures at — it
   is Kuzushi's differentiator.) The operator can also hand-edit the harness file
   or attach a design doc / prior findings as evidence (provenance-tagged
   `<untrusted-source>` blocks — already in flight for `threat-model:build`).
3. **Feedback mutates it dynamically.** For agentic taint, the reachability
   oracle prunes unreachable candidates. For fuzzing, an **LLM-authored harness**
   runs a build-and-fix loop (compiler rejects → LLM fixes), and coverage signal
   (`cov:`/`ft:`/`NEW`) decides *extend budget vs saturated → stop*, with an
   escalation ladder (a clean crash is a signpost, not the prize — keep mutating
   toward a controllable OOB write). Only a reproducing PoV promotes a finding to
   `proven`. This is the OSS-Fuzz-Gen / Big Sleep mechanic, productized.

---

## 8. Who this is for

| Persona | Wants | Fails them today |
| --- | --- | --- |
| **Bug-bounty hunter** | Aim at an in-scope repo, fire a cheap sweep, get confirmed reportable findings, export a bundle. | Offline value and export work; sampled sweep/budget governance is not yet one flow. |
| **AppSec engineer (CI)** | Seed with the team's Semgrep/CodeQL, corroborate with an AI hunt, gate PRs on high-severity, keep FP rate *known*. | CI gating works; external SARIF/Semgrep seed ingest and a published FP number remain. |
| **Security researcher** | Compose a deep strategy, enable a CPG + symbolic tier, steer by typed focus, mutate a fuzz harness, measure the run. | Durable proposals/corrections exist; reusable recipes, explicit engine-cost controls, typed focus, and measure/tune remain. |

Shared need: **govern a non-deterministic scan — sample it, steer it,
corroborate it, see it — cheaply and defensibly.**

---

## 9. Product principles

1. **Non-determinism is managed, never hidden.** Surface variance
   (net-new vs re-found across runs), sample it (sweep), and corroborate it
   (verifier). Never present one stochastic pull as ground truth.
2. **Sample + corroborate.** Union across a permuted sweep for coverage; a
   separate guilty-until-proven-innocent verifier for precision. These are the
   two load-bearing mechanisms; everything else supports them.
3. **Cost is always visible and gated.** Every run shows `$cost`; proposals are
   priced; budgets are enforced per-op and per-call; cost-per-confirmed-finding
   is a first-class metric.
4. **Evidence, not chat.** Every finding carries an evidence tier, the oracle
   that produced it, a proof state, and a next action. Proof beats opinion —
   prefer a reachability path or a PoV crash to a model assertion.
5. **Deterministic seed + non-deterministic hunt corroborate one row.**
   Semgrep/CodeQL/SARIF and the AI hunt are different evidence for the same
   defect; merge them with `sources[]`, don't duplicate them.
6. **Parts compose; strategies are owned by the operator.** The catalog is
   building blocks. Diversity + merge beats one pipeline.
7. **Engine enablement is explicit, cost-estimated, and honest.** Turn engines on
   per-scan with the cost shown; artifact-gated; refuse-with-hint over silent
   degradation.
8. **Human judgment is sticky.** Manual FP/confirm survives every re-run.
9. **No silent fallback.** Model/provider/runtime never change without consent;
   every path resolves models through `resolve_tool_model` / `ctx.config.model`.
10. **Local-first, with explicit network boundaries.** Bundled detectors run
    locally. External scanners and model providers follow their selected
    configuration: Semgrep registry configs such as `auto` fetch rules, while
    Kuzushi disables Semgrep metrics. Operators who require an offline run must
    select only bundled detectors or provide already-local scanner rules.

---

## 10. The flow — phases as control loci

One spine, over one engagement folder and one ledger. Each phase is where you
compose parts and control non-determinism. Keep the honest phase *derivation*
(`journey.rs`); rebuild phase *execution* around the sweep.

```
   AIM (組)         HUNT (崩)          CONFIRM (作)        FIX (掛)          REPORT
   map + build   →  fire sweeps:    →  sample→corroborate →  patch + re-    →  export
   the harness      focus×strategy×    →prove: votes,        verify (PoV       evidence
   (recon seeds     model×runs,        lenses, PoV/          re-attack)        (SARIF /
    focus areas,    priced, budget-    metamorphic;                            bundle /
    threat model,   gated proposals    sticky human                           ledger)
    engines)        + seed ingest      triage
      │                  │                   │                  │
      └─ CONTROL PLANE (sweep · harness · budget · engines · depth · verify) ─┘
      └─ VISUAL PLANE   (surface · DFD · threat model · tree · chains · ledger · live cost) ┘
                                          ▲
                                MEASURE / TUNE — F1 vs a corpus, head-to-head
                                vs SARIF, regression gate, prompt self-tune
```

- **Aim (組).** Build the editable `engagement/` folder — profile, threat model
  (regenerable), map/focus areas, strategies, prompts, context — and **seed the
  harness** from recon. Feeds the generators' signals. Pick which engines to
  prepare (CPG/CodeQL DB) here, where the cost is a one-time build.
- **Hunt (崩).** The **sweep**: signal generators propose priced permutations;
  approve under budget; fire `focus × strategy × model × runs`; **union + dedupe**
  into the ledger with corroboration. Live scanners and imported SARIF feed the
  same rows. This is the control plane's centerpiece.
- **Confirm (作).** Sample → corroborate → prove. Configurable verification
  (`when/max/votes`), multi-lens blind verifier, optional metamorphic and PoV;
  the reachability oracle (CPG) is the deterministic FP suppressor; human triage
  is sticky. Batch-triage all findings at once.
- **Fix (掛).** Patch synthesis (optionally diverse patch agents, pick best) +
  re-verify against the same ledger row (PoV re-attack, tests pass).
- **Report.** One explicit exit — SARIF (CI/Code Scanning), markdown bundle
  (bounty), ledger (audit) — via both the friendly verb and the headless flag.
- **Measure / Tune.** Turn the non-determinism into a number: F1 on a labeled
  corpus, head-to-head vs an imported SARIF, a CI regression gate, and prompt
  self-tuning on a holdout.

---

## 11. Goals & non-goals

### Goals
- G1. Fire a controlled, priced sweep and see net-new-vs-re-found across its runs.
- G2. Steer a scan by typed intent ("focus on SQLi") and by editing one harness.
- G3. Enable/disable analysis engines (CPG/CodeQL/MCP/LSP) per-scan with cost shown.
- G4. Ingest an external Semgrep/CodeQL/SARIF file as a deterministic seed that
  corroborates the AI hunt in one ledger row.
- G5. Compose, save, and replay a named strategy.
- G6. Confirmed-vs-guess (evidence tier + oracle + votes) visible in every list.
- G7. Delegate cheap work to weak models, hard work to strong; cost-per-confirmed
  surfaced; budget enforced per-call.
- G8. Keyless first run records real deterministic scanner signals as
  `signal_only` findings in ~60s via `demo`.
- G9. Every phase reachable identically in shell, `scan --until`, and `run`.
- G10. Detection quality is a reproducible number (F1 + head-to-head + gate).

### Non-goals
- Surface backward-compat (verb names, layout) — waived; on-disk `.kuzushi/`
  paths are **migrated**, not broken.
- A fully-autonomous CRS. Kuzushi keeps a human in the loop; don't over-claim
  autonomy in triage/patch (the reference harness calls these "still open").
- A cloud control plane. Local-first.
- Replacing live `native_scanners` — Semgrep/CodeQL stay as detector parts.
- Shipping roadmap modules (blackbox/pwn/honeypot/…) until they produce
  first-class evidence artifacts.

---

## 12. Requirements

`[Rn] statement → acceptance`. Status = **Exists** (wire/expose) / **Partial** /
**New**. Wave tags map to §14.

### 12.1 Non-determinism control — the sweep (New)
- **[R1] Priced, budget-gated sweep.** `focus × strategy × model × runs`;
  generators propose, operator approves under a cap, `$/round` self-calibrates.
  *Accept:* generators propose from git/manifest/graph fixtures; the queue
  prices, ranks by yield, refuses over-budget; EMA recalibrates after a fire.
- **[R2] Union + engagement-scoped merge.** Sweep runs union into one ledger row
  per defect, merging on `dedup_key` **across `scan_id`** with a corroboration
  count. *Accept:* two runs / two engines over one defect → one row, corroboration 2.
- **[R3] Variance is visible.** A campaign shows **net-new vs re-found** per run.
  *Accept:* firing a second run reports how many rows are new vs corroborated.
- **[R4] Budget honesty.** Cap gates between proposals; a single in-flight
  overshoot is surfaced. *Accept:* the UI shows the overshoot, not a hidden cap.

### 12.2 The harness — mutable, seeded, steerable (New)
- **[R5] The harness is one versioned artifact.** `engagement/harness.toml`
  captures focus/strategy/engines/tiers/runs/oracle/seeds/budget. *Accept:*
  round-trips: generate → edit → re-read → re-fire.
- **[R6] Recon seeds it.** A discover pass pre-populates ranked focus areas,
  toolchain, and input vocabulary. *Accept:* a fresh target yields a partitioned,
  ranked harness without hand-authoring; a fuzzer is never handed `main()`.
- **[R7] Typed-intent steering.** "Focus on SQLi" re-ranks focus areas, sets the
  oracle CWEs, and biases seeds. *Accept:* the same command measurably reorders
  the harness plan and the next sweep's scope.
- **[R8] Dynamic mutation.** Reachability prunes unreachable candidates; an
  LLM-authored fuzz harness runs a build-and-fix loop and coverage decides
  extend-vs-stop; only a PoV promotes to `proven`. *Accept:* a build failure
  re-prompts (capped); coverage growth extends budget; a signed-overflow stays
  `candidate`, an OOB-write with a reproducing input becomes `proven`.

### 12.3 Composable strategies (New)
- **[R9] Named, saveable, replayable strategies.** `engagement/strategies/*.toml`
  compose detectors + oracles + verifiers + tiers. *Accept:* `deep` expands into a
  sweep spec; picking it fires the composed passes; editing persists.
- **[R10] Diversity ensemble.** A strategy can run several diverse
  detectors/patch-agents in parallel and merge/pick-best. *Accept:* two detectors
  in one strategy corroborate into shared rows.

### 12.4 Analysis engines per-scan (Exists → expose)
- **[R11] Explicit engine enablement with cost estimate.** Toggle CPG / CodeQL DB
  / specific MCP oracles / clangd LSP for a pass; show latency/cost before commit;
  default off for broad, on for scoped confirm. *Accept:* enabling the CPG shows
  an estimate; disabling it falls back to structural with no silent spin-up.
- **[R12] Analysis-depth ladder.** `structural → linked → path (CPG) → proven
  (PoV/symbolic)` as the user knob (reuse `minEvidenceLevel`). *Accept:* raising
  target depth enables the engine that can reach it, or refuses-with-hint.
- **[R13] Reachability oracle is the FP suppressor.** Only a backend produces
  `path`; the LLM never promotes a hit the symbolic engine couldn't reach.
  *Accept:* a structural-only hit cannot become a finding at
  `minEvidenceLevel=linked`.
- **[R14] Optional symbolic (KLEE) deepest tier for C/C++.** Behind the same
  evidence interface; offered only when a CPG already confirmed a reachable C/C++
  sink. *Accept:* KLEE promotes `path → proven` with a concrete input, or is
  absent honestly.

### 12.5 The deterministic seed plane (New)
- **[R15] Ingest external SARIF/Semgrep/CodeQL files.** `findings seed <file>`
  tags `sources[]`, sets `triaged_by="imported"`, dedups against existing rows.
  *Accept:* seeding a SARIF over an existing row adds a source, not a duplicate.
- **[R16] Seed corroborates the hunt.** An imported deterministic finding and an
  AI-hunt finding over the same defect share one row. *Accept:* corroboration
  count reflects both planes.

### 12.6 Confirm / verify (Partial → configure)
- **[R17] Configurable verification.** `--when severity>=X --max N --votes K`;
  bare scan verifies nothing. *Accept:* filter/cap/votes each tested; the
  bare-scan-verifies-nothing invariant holds.
- **[R18] Adversarial, blind, multi-vote.** Guilty-until-proven; each verifier
  starts from code not the finder's claim; majority rules; split-vote policy is
  explicit. *Accept:* the verifier's context excludes the finder's reasoning; the
  vote breakdown is recorded.
- **[R19] Proof over opinion.** Where feasible, promote via a reproducing PoV /
  crash oracle or metamorphic perturbation, not a model claim. *Accept:*
  `proven` requires a reproducing artifact; a re-attack after patch is its own gate.
- **[R20] Sticky human triage + batch triage.** Manual FP/confirm survives
  re-runs; triage runs over all findings, deduped, skipping persisted verdicts.
  *Accept (Exists — protect + extend):* the sticky test passes; a repeat triage
  issues one call per unique un-triaged fingerprint.

### 12.7 Model tiering & cost (Exists → surface)
- **[R21] Per-role/tier model map + presets.** Cheap models for
  dedup/classify/easy-triage, strong for root-cause/patch/PoV; same-role fallback
  on error. *Accept:* a role map + a weak↔best preset switch; cost per role
  accounted.
- **[R22] Cost-per-confirmed surfaced; budget per-call.** *Accept:* the run shows
  $/confirmed-finding; a zero-cost backend run (reports `cost_usd 0.0`) still halts at
  the cap via a call-count/token fallback.
- **[R23] No duplicate triage; prompt caching.** *Accept:* repeat runs over
  unchanged context show cache hits; large invariant context moves to the prompt
  head; no re-triage of duplicates.

### 12.8 The visual plane (Exists → wire to reality)
- **[R24] Confirmed-vs-guess in every list.** Each finding row shows proof marker
  (`✓ ◇ ? !`), evidence tier, oracle, and corroboration. *Accept:* 100% of list
  rows carry the signal, not just detail.
- **[R25] The full gallery, fed by real state.** Attack surface, DFD, threat
  model, attack tree, chains, findings table, coverage matrix — each with an
  empty-hint when its artifact is absent. *Accept:* no dummy content; each page
  draws from its persisted artifact.
- **[R26] Regenerate on demand.** Hotkeys/commands regenerate threat model,
  chains, surface when they drift. *Accept:* `threats regen` / chain `r` rebuild
  from current findings.
- **[R27] Live sweep introspection.** The activity view shows per-round model,
  strategy, live cost, agent tree, tool calls, latency, and coverage growth.
  *Accept:* a running sweep shows spend and per-step confidence live.

### 12.9 Surface, first-run, discoverability (Exists → protect and compose)
- **[R28] Home is the control room, not a catalog.** Landing is the aim→fire
  cockpit; the 42-module catalog is one advanced, phase-grouped view with human
  names and rendered tab-completion. *Accept:* default is aim/fire; completion
  ghost-text renders.
- **[R29] Keyless first run reaches value.** `demo` is first-class in onboarding
  and every empty state; the model picker offers an offline choice; typed
  `target` runs the same onboarding as the picker. *Accept:* no key + no network →
  a finding via `demo` in ~60s. *Status: Exists — protect.*
- **[R30] Model↔runtime checked up front + export survives the reframe.**
  Incompatible pairs rejected at pick time; `export-findings` reachable from
  Report with the format honored. *Accept:* `doctor`/picker fail-loud pre-spend;
  the markdown bundle is reachable via the friendly verb.

### 12.10 Headless/CI parity, robustness, interaction (Exists → protect)
- **[R31] `recon:import` reachable; `--target` consistent; `run` errors are valid
  JSON; export honors format+dirs.** *Accept:* the four CI-blocking edges are
  closed (`… | jq` never sees empty stdout; `kuzushi --target . scan` works).
  *Status: Exists — protect.*
- **[R32] Palette degrades (256-color); width is unicode-aware.** *Accept:*
  semantic colors survive on macOS Terminal.app; 組崩作掛 don't misalign tables.
- **[R33] No empty-prompt hotkey trap; one scroll/keybind grammar; honest
  signifiers.** *Accept:* typing `config` doesn't fire `c`→exploit-chain; the DAG
  legend matches what rows render; canceled never flips to done; the phase chip
  never renders without a target. *Status: Exists — protect.*

### 12.11 Measure / tune (New)
- **[R34] Detection is a number.** `kuzushi measure` reports precision/recall/F1
  and head-to-head vs an imported SARIF; `--gate` fails CI on regression.
  *Accept:* F1 on a fixture corpus; `--against` apples-to-apples; gate exits
  non-zero on regression.
- **[R35] Prompts self-tune.** `kuzushi tune` picks the best prompt variant on a
  holdout, feeding the `evolve` generator's fitness. *Accept:* holdout split
  deterministic; fitness closes back to `evolve`.

---

## 13. The signifier & trust contract

Because the promise is *governed evidence*, the finding surface has a hard,
release-gating contract:

- Confirmed-vs-guess — proof marker (`✓ ◇ ? !`), **evidence tier**, **the oracle
  that produced it**, **corroboration count**, and **vote breakdown** — is visible
  in every list, not just detail.
- **Cost and corroboration are always on screen** during a run — the operator
  never spends blind.
- The phase chip/rail reflects **engagement reality** (artifacts on disk,
  findings, triage/verify state), never the viewed page, and never renders without
  a target.
- A terminal state is terminal: canceled never becomes done; a legend never names
  a state a row can't display.
- **Verification independence is a visible badge** — a finding shows that its
  verifier saw only the evidence (PoC/path), not the finder's reasoning
  (the two-container trust boundary).

A change that regresses this contract is a release blocker.

---

## 14. Rollout — waves (mapped to what exists)

Because most parts exist, the early waves are **expose + compose**, not build.

| Wave | Delivers | Nature |
| --- | --- | --- |
| **W0 — Honest surface & trust** | R24, R28, R33 + signifier fixes; render the gallery from real state | shipped; protect while composing sweep state |
| **W1 — Keyless value** | R29–R30 | shipped; protect |
| **W2 — Engine controls** | R11–R14 (surface the CPG/MCP/LSP enablement + depth ladder that exist artifact-gated) | expose |
| **W3 — Seed plane** | R15–R16 (external SARIF/Semgrep ingest) | build (small) |
| **W4 — Cost & tiering surfaced** | R21–R23 (per-role map exists; surface cost-per-confirmed; kill duplicate triage; prompt caching) | expose + fix |
| **W5 — Cross-run ledger** | R2, R20 (engagement-scoped merge; protect sticky triage) | build |
| **W6 — Configurable Confirm** | R17–R19 (votes/lenses/PoV over the existing verifier) | build |
| **W7 — The sweep** | R1, R3–R4 (compose the shipped priced proposal queue into sampled matrix execution + union) | build (deep) |
| **W8 — The harness** | R5–R8 (mutable, recon-seeded, typed-intent, dynamic fuzz build-and-fix) | build (deep) |
| **W9 — Strategies** | R9–R10 (promote durable proposals/corrections into reusable named recipes = the sweep variant axis) | build |
| **W10 — Detection as a number** | R34–R35 (fold into `kuzushi-eval`) | build |
| **cross** | R31–R32 (protect shipped headless parity; finish terminal palette portability) | regression coverage |

**Sequencing rule:** nothing here is worth doing while the ship-the-product work
(publish, platform binaries, supply-chain — `ROADMAP.md` P0) is red. W0–W4 are
mostly expose/fix and land early; W7/W8 (sweep + harness) are the deep new build
and are de-risked by W5's ledger.

---

## 15. Success metrics

| Metric | Today | Target |
| --- | --- | --- |
| Fresh launch → first finding (no key) | offline demo is available in onboarding | preserve ≤ 60s via `demo` |
| Steer a scan by typed intent | one-off `ask` | re-ranks the harness + next sweep |
| Enable an engine per-scan with cost shown | hidden/artifact-gated | explicit toggle + estimate |
| Confirmed-vs-guess visible in the list | proof/confidence markers exist | 100% of rows plus sweep corroboration/cost |
| Cost per confirmed finding | not surfaced | shown live |
| Duplicate LLM triage per unique fingerprint | 1× by default; explicit re-triage opts back in | preserve 1× |
| Deterministic seed corroborates the hunt | no ingest path | one row, `sources[]` ≥ 2 |
| Net-new vs re-found across a sweep | not shown | per-run counter |
| Verify configurability | all-or-nothing | when / max / votes / PoV |
| Published detection number | `baseline = {}` | F1 + head-to-head vs SARIF |
| Signifier/trust-contract violations | prior known set closed by executable tests | 0 regressions |
| Phase reachable in shell + scan + run | partial | 100% parity |

---

## 16. Risks, guardrails & references

**Risks / guardrails**
- **Model safety (hard gate).** No ported path inherits a default model;
  `check-model-safety.mjs` stays green; per-role/tier routing goes through
  `resolve_tool_model`.
- **Mode parity.** Sweep + harness + ledger + strategies live in `kuzushi-core`;
  the TUI gate is chrome over the same on-disk state. Update
  `docs/assessments/mode-parity.md` each wave.
- **CPG cost is exponential.** `reachableByFlows` must keep its caps
  (sources/sinks/flows/per-CWE timeout); default CPG off for broad passes.
- **Cap overshoot honesty.** A single in-flight sweep can exceed the cap; surface
  it, don't pretend the cap is hard.
- **Recon over-scaling.** More agents → more duplicates; the lever is **partition
  quality**, not agent count — cap fan-out.
- **Don't over-claim autonomy.** Triage/patch calibration is "still open" even in
  the reference harness; keep the human in the loop, keep triage sticky.
- **KLEE/symbolic is unintegrated today; `semgrep`/`language` taint backends are
  reserved stubs** — ship them as explicitly-optional, not implied.
- **`.kuzushi/` path moves** are migrated (additive `open/init`), not broken.
- **Baseline discipline.** Treat the current workspace gates as the source of
  truth; a failing BDD, snapshot, or findings-store test blocks the wave until
  it is fixed or assigned a narrow, executable quarantine with an owner.
- **CRAP gate.** New functions ≤ complexity 4, < 40 logical lines,
  `quality:crap-risk` < 7 — the sweep/harness/merge code are the likely offenders.

**References**
- cannon harness — `~/vibe-code/vuln-scan-cannon-harness` (`README.md`,
  `PERMUTATION.md`, `BENCHMARK.md`, `src/{queue,runner,ledger,stages}`).
- Anthropic defending-code reference harness — `~/clone-references/anthropic/…`
  (`docs/blog-post.md`, `docs/pipeline.md`, `harness/prompts/*`).
- AIxCC winners — `~/vibe-code/aixcc-winners/{atlantis,buttercup,theori}`
  (theori `configs/models-*.toml` model tiering; atlantis `crs-sarif` CPG stack +
  `crs-multilang` input-generator ensemble; buttercup 7-agent patcher +
  `sarif_matcher.py` dedup).
- IRIS neuro-symbolic taint — `docs/taint-iris-next.md`,
  `scripts/taint_iris_next_flows.sc`, `capabilities/taint_iris_next/`.
- LLM fuzzing — OSS-Fuzz-Gen (`google.github.io/oss-fuzz/research/llms/target_generation/`,
  `github.com/google/oss-fuzz-gen`), Project Zero Naptime→Big Sleep
  (`projectzero.google/2024/10/from-naptime-to-big-sleep.html`),
  26-bugs/CVE-2024-9143 coverage; local: `kuzushi-security-plugin/agents/fuzz-*`,
  `aixcc-winners/buttercup/fuzzer`.
- Current-state map — `crates/kuzushi-core/src/{findings,runtime,spend,modules,
  capabilities}`, `crates/kuzushi-tui/src/{ui_view_models,renderer}`,
  `crates/kuzushi-mcp-*`.

---

## 17. Open questions

1. **Harness home (W8):** one `engagement/harness.toml`, or per-strategy harness
   files? *(Recommend one harness + referenced strategies.)*
2. **Dedup key (W5):** exact-line `basename:line:cwe` vs the current `line/8`
   bucket? Exact matches cross-engine collisions; the bucket tolerates drift.
3. **Verify strategy (W6):** `--when/--max/--votes` on the existing verifier
   only, or also the full multi-lens 2-of-3 + metamorphic + PoV? *(Latter is the
   benchmarked edge but materially more work.)*
4. **Engine-enablement UX (W2):** an explicit pre-scan toggle panel, or infer
   from the analysis-depth ladder and only prompt on cost? *(Recommend
   depth-drives-engines, prompt on cost.)*
5. **Verb-collapse depth (W9):** hard-collapse 42 modules to ~8 phase verbs, or
   keep modules as strategy *passes* behind the verbs and only reframe the
   surface? *(Recommend reversible: reframe surface, keep modules as passes.)*

---

## 18. Appendix — the control room, one screen

```
$ kuzushi --target ./acme-api

  Kuzushi · acme-api · Node/Express · LIVE            崩 hunt 2/5   $0.85/$2.00
  ───────────────────────────────────────────────────────────────────────────
  組 aim ✓   崩 HUNT ▸   作 confirm   掛 fix   ▪ report
  ─────────────────────────────── CONTROL ──────────┬──────── VISUAL ─────────
  SWEEP   focus × strategy × model × runs            │ ATTACK SURFACE
    ▸ P-001 incomplete-fix hunt  $0.40 · yield .82   │   3 routes · 2 untrusted
      strategy: deep   model: mid   runs: 2  [k/s]   │   ╱╲  webhook.ts  ● hot
      P-002 SSRF reachability      $0.30 · .74 [k/s] │  ╱  ╲ users.ts    ◇
    harness  engines: cpg ✓ codeql ○ lsp ○  [edit]   │ ─────────────────────────
    seed     + semgrep.sarif (imported, 4)           │ FINDINGS (ledger)
    focus ›  "focus on sqli"________              ↵  │  ✓ SQLi  users.ts:31
  ──────────────────────────────────────────────────┤    critical · path · ×2
  NEXT ▸ approve sweeps, then `next` to fire         │  ◇ SSRF  webhook.ts:47
  steer: [m]odel [s]trategy [e]ngines [b]udget       │    high · linked · votes 1/2
  ───────────────────────────────────────────────────────────────────────────
  > _                                    demo · seed · measure · / for commands
```

The 42 modules, the MCP oracles, the CPG, the bounty/recon intake — all still
there as **parts**, composed into the strategy behind the sweep. The default is
the control room.
