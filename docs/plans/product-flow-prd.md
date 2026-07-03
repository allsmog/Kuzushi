# PRD — Kuzushi end-to-end product flow

> **Status:** proposal, awaiting review.
> **Owner:** operator experience.
> **Companion docs:** the implementation seams live in
> [`docs/plans/cannon-port-plan.md`](./cannon-port-plan.md); the screen-level
> behavior lives in [`docs/design/product-flow-design-spec.md`](../design/product-flow-design-spec.md).
> **Grounding:** the four 2026-07 audits (new-user journey, TUI+headless devEX,
> LLM token-waste, perf-waste), the cannon reframe decision (Direction A,
> 2026-07-02), `VISION.md`, and `ROADMAP.md`. Every problem claim below is
> traceable to one of those; every requirement is stated as a checkable outcome.

---

## 1. TL;DR

Kuzushi is a local-first security workbench whose engine is an LLM agent you
steer per phase — but the product *presents* itself as a 41-tile scanner catalog
(55 registered modules / 67 visible tools / 92 command specs). The gap between
what it **is** and what it **shows** is the single biggest drag on adoption:
new users hit an auth wall before they see value, can't find the capability they
want in an alphabetical wall of codenames, and can't tell a confirmed exploit
from an LLM guess.

This PRD defines one coherent end-to-end flow — **Aim → Hunt → Confirm → Fix →
Report** — steered from a single cockpit, backed by one editable engagement
folder and one findings ledger with sticky human decisions and honest proof
state. It folds the catalog *behind* the phases (still reachable for power
users), makes the keyless first run actually work, and makes every on-screen
signifier tell the truth.

**One-sentence product promise:** *point Kuzushi at a repo, and it walks you from
"what's the attack surface" to "here is a confirmed, evidence-backed finding and
a patch" — with a measurable detection number, not a claim.*

---

## 2. The problem with today's flow

The product works — the pieces are real and mostly good. The **flow between them
is confused**. Concretely, from the audits:

**A. It reads as an inventory, not a workspace.** Home shows ~41 modules like a
scanner catalog when the engine underneath is one steerable agent. There are 55
registered modules, 67 visible tools, 43 `ShellView` variants, 92 command
specs. The `/tools` list is a flat alphabetical wall of opaque codenames
(`randori:pasta`, `carlini-threat-hunt`, `shinsa`, `tob`, `x-ray`) with
circular descriptions and no headers. Tab-completion is fully implemented but
undiscoverable, and the ghost-text preview that would advertise it is tested
dead code that never renders.

**B. The keyless first run is broken end-to-end.** The one zero-friction win —
`kuzushi demo` (offline, no key, deterministic 7 findings) — is invisible in the
shell; it exists in the CLI/README only. The model picker offers only
paid/credentialed models with no offline choice. Defer the target picker and you
land in a bare Workbench with empty states that point only at `scan`/`next`
(which need a target *and* a model) and never at `demo`. A new user hits an auth
wall before they see a single finding.

**C. You can't trust what the screen tells you.** A canceled task flips
`×` → `✓ done` when its worker finishes late — an aborted run presented as clean
success. The Workbench fabricates a phase chip and rail with no target set,
contradicting its own target-gating invariant, and tracks the *viewed page*
rather than engagement reality (double "current" markers, Done regressing to
Current). The DAG legend advertises `● active` while rows render a braille
spinner; `●` means three different states across views. Focus signifiers lie off
the Review page. **When the tool's job is evidence, a dishonest signifier is a
product-level defect, not a cosmetic one.**

**D. The steering levers exist but are scattered.** Every lever the phased vision
needs already exists and is read fresh per stage — layered option store,
per-stage/per-role model overrides (with no silent fallback), prompt-override
files, KB/threat-model attach, `ask`/`plan`. What's missing is **one
phase-boundary steering gate** that surfaces them together at the moment they
matter. Today verification is opt-in but all-or-nothing: bare `scan` verifies
nothing; turn it on and it verifies *every* true positive with no severity
floor, cap, or vote threshold.

**E. Runs waste tokens and money.** Triage re-triages 4×-duplicated findings with
no verdict-skip and no latest-scan scope (the same fingerprint triaged 10–11× in
one observed run — 222 LLM calls, then canceled, zero results surfaced). No
Anthropic prompt caching anywhere in the shipping path. Carlini re-embeds the
full repo inventory per actor×run at the prompt tail, defeating caching. The cost
cap can't trip on the codex backend (reports `cost_usd 0.0` every call).

**F. Headless has sharp edges that block CI.** `recon:import` is advertised but
unreachable (not in the dispatch match arm) — a blocker. `--target` behaves three
different ways (`kuzushi --target . scan` errors "missing `<TARGET>`"). `run`
prepare-errors emit empty stdout, breaking `jq` in CI. Nearly every flag has
blank `--help`. The friendly `workspace export findings <path>` verb drops the
format argument and refuses directories, making the human/bounty markdown bundle
unreachable through the friendly path.

**G. Detection quality is a claim, not a number.** `baseline.json` is `{}`.
Kuzushi ships `kuzushi-eval` (precision/recall/F1 vs oracle corpora) but it's
recall-centric, standalone, and not wired to a `kuzushi` verb. There is no
head-to-head-vs-SARIF, no regression gate, no self-tuning loop.

**The through-line:** the product's differentiator is *evidence, not chat* —
findings with verified evidence, honest proof state, defensible next action, and
a published detection number. Today's flow undercuts that differentiator at
every seam. This PRD closes those seams into one flow.

---

## 3. Who this is for

| Persona | What they want | Where today's flow fails them |
| --- | --- | --- |
| **Solo bug-bounty hunter** | Point at an in-scope repo, get confirmed, reportable findings fast; export a markdown bundle for the program. | Auth wall before first finding; markdown bundle unreachable via the friendly verb; can't tell confirmed from guessed in the list. |
| **AppSec engineer (in CI)** | Gate PRs on high-severity findings, upload SARIF, keep the false-positive rate low and *known*. | `run`/`scan` `--target` inconsistency and empty-stdout errors; no published FP/TP number; verify is all-or-nothing. |
| **Security researcher / red-teamer** | Steer the agent per phase — pick methodology, models, prompts, budget; hunt variants and chains; measure the run. | Levers scattered across 92 commands; no phase-boundary gate; static 22-task walker instead of signal-driven proposals; no measure/tune verb. |

All three share one need: **a legible path from target to evidence they can
defend**, with the depth available when they want it and out of the way when they
don't.

---

## 4. Product principles (the bar every change is held to)

1. **Evidence, not chat.** Every capability must produce a first-class artifact,
   an honest proof state, and an operator next action. Anything that doesn't is
   roadmap material, not product surface. (From `VISION.md`.)
2. **One flow, depth on demand.** The default path is the five-phase spine.
   The full 55-module registry stays reachable behind an advanced catalog — the
   reframe *hides* complexity, it never *removes* capability.
3. **Honest signifiers.** A glyph, status, chip, or keybind hint must reflect the
   real state and the real intent. Canceled is not done; a fabricated phase chip
   is a bug; a legend that names a state the row can't show is a bug.
4. **Mode parity by construction.** Phase logic, the ledger, prompts, and the
   planner live in `kuzushi-core`. Shell gates and editors are interactive-only
   chrome over the same on-disk state. Every phase is reachable via shell,
   `scan --until`, and single `run`. No TUI-only or CLI-only product behavior.
5. **No silent fallback.** Model, provider, and runtime never change without
   explicit operator consent. Every ported path resolves models through
   `resolve_tool_model` / `ctx.config.model`.
6. **Local-first and honest about cost.** The only bytes that leave the machine
   go to the operator's model provider. Budget is enforced per-call, and the run
   never silently burns tokens re-triaging duplicates.

---

## 5. The end-to-end flow we are building

One spine, five phases, over one engagement folder and one ledger. The four
core phases already have honest *derivation* today (the `組 Map / 崩 Hunt /
作 Confirm / 掛 Fix` journey, derived from workspace reality); this PRD keeps that
derivation and rebuilds the *execution* and the *steering* around it, then adds
Report as the explicit exit and Measure/Tune as the calibration loop.

```
   AIM (組)          HUNT (崩)          CONFIRM (作)        FIX (掛)          REPORT
   map the       →  find candidate  →  prove or reject  →  patch &        →  export
   target &         vulns with          with verified       re-verify         evidence
   generate the     signal-driven       proof + votes                         (SARIF /
   engagement       proposals                                                 markdown /
   folder                                                                     ledger)
      │                  │                   │                  │
      └──────────────────┴─── one findings ledger (sources[], sticky triage, ───┘
                              corroboration, proof state) + one engagement/ folder
                                          ▲
                                MEASURE / TUNE — score the run vs a labeled
                                corpus, head-to-head vs SARIF, self-tune prompts
```

**Aim (組 Map).** `aim` generates and organizes an editable **`engagement/`
folder** for the target — `profile.toml`, `threat-model.md`, `map/`, `kb/`,
`strategies/`, `prompts/`, `context/`, `authorization.md` — synthesized from the
existing producers (context snapshot, threat model, entry-points, CPG). This is
where the operator sees the attack surface and edits the calibration before any
spend. (The threat-model source-bundle work already in flight — feeding parent
artifacts as provenance-tagged `<untrusted-source>` blocks — is a first brick of
this phase.)

**Hunt (崩).** The static 22-task walker is replaced by a **signal-driven,
priced, budget-gated proposal queue**. Generators (`commits` incomplete-fix
hunts, `threatmodel` reachability audits, `intel` dependency footguns, `evolve`
prompt breeding) propose salvos; each is priced and ranked by yield; the operator
approves under a budget at the phase-boundary gate. Live `native_scanners`
(Semgrep/CodeQL) and imported SARIF both feed the *same* ledger row via
`sources[]`.

**Confirm (作).** Verification is opt-in *and configurable*: `--when severity>=high
--max N --votes K`. Optionally the multi-lens, majority-vote verifier
(reachability / exploitability / mitigation) backed by the tree-sitter/Joern/
CodeQL MCP oracles. Human verdicts are **sticky** — an AI re-run never overwrites
`triaged_by="human"`.

**Fix (掛).** Patch synthesis and re-verification against the same ledger,
producing a defensible diff tied to the finding's evidence.

**Report.** One explicit exit: SARIF for CI/Code Scanning, a markdown bundle for
bounty programs, the ledger for audit — all reachable through *both* the friendly
verb and the headless flag, with the format argument honored.

**Measure / Tune (calibration loop).** `kuzushi measure` scores a run's confirmed
findings against a labeled corpus (precision/recall/F1), grades head-to-head vs
an imported SARIF, and gates CI on regression; `kuzushi tune` picks the best
prompt variant on a holdout. This turns "detection quality" from a claim into a
number.

---

## 6. Goals & non-goals

### Goals
- G1. A stranger with no API key sees real findings within ~60 seconds of launch.
- G2. The default surface reads as a phased cockpit; the catalog is one advanced
  view, not the home screen.
- G3. Every finding in every list carries an honest confirmed-vs-guess proof
  marker; no signifier contradicts engagement reality.
- G4. Verification is configurable (when / max / votes), not all-or-nothing.
- G5. One ledger row per real defect, accumulating `sources[]`, with sticky human
  triage that survives re-runs.
- G6. Every phase is reachable identically from shell, `scan --until`, and `run`.
- G7. A run does not re-triage duplicates, caches prompts where the provider
  supports it, and enforces the budget per-call.
- G8. Detection quality is a reproducible number (F1 vs corpus + head-to-head vs
  SARIF + regression gate).

### Non-goals
- Backward compatibility of the *surface* (verb names, view layout) — the user
  has explicitly waived it. `.kuzushi/` on-disk paths must still be *migrated*,
  not broken.
- Shipping the roadmap modules (blackbox, pwn, honeypot, yokai, revgraph) — they
  graduate only when they produce first-class evidence artifacts.
- A cloud/hosted control plane. Kuzushi stays local-first.
- Replacing `native_scanners` — live Semgrep/CodeQL stay as detector arms; the
  reframe folds them into Hunt passes, it doesn't remove them.

---

## 7. Requirements

Each requirement is `[Rn] statement → acceptance criteria`. Phase tags map to the
rollout in §9.

### 7.1 First-run & onboarding (cross-cutting; Phase 0/1)

- **[R1] Keyless first run reaches value.** From a fresh launch with no key, the
  shell surfaces `demo` as a first-class option, the model picker offers an
  offline/local choice, and every relevant empty state points at `demo` (not only
  `scan`/`next`). *Accept:* on a machine with no `ANTHROPIC_API_KEY` and no
  network, a new user runs `demo` from the shell landing and sees the 7-finding
  fixture result, using the same deterministic secret-scan+iac-scan path the CLI
  `demo` runs.
- **[R2] In-session auth is never a dead end.** API-key paste and OAuth both
  complete in-session (paste already exists — keep it and make it the advertised
  path). *Accept:* a user can go from "no credential" to "authenticated" without
  leaving the shell or relaunching.
- **[R3] Model↔runtime compatibility is validated up front.** An
  `anthropic:` model on a codex backend is rejected at pick time with an
  actionable message, not at first API call. *Accept:* `doctor` and the model
  picker both fail-loud on an incompatible pair before any spend.
- **[R4] `target <path>` and the target picker run the same onboarding.** The
  typed `target` verb applies the same initial onboarding phase (model picker /
  planner) the picker path does. *Accept:* both entry paths land in the same
  state with the same chrome.

### 7.2 Surface reframe (Phase 0 — reversible)

- **[R5] Home is the cockpit.** The default landing is the phased Workbench, not a
  41-tile catalog. `Catalog`/`Recommend`/`Module`/`ModuleRun` collapse into one
  advanced catalog view. *Accept:* `home` and fallbacks land on the Workbench;
  the three retired render arms are gone; module-count assertions updated.
- **[R6] Plumbing is hidden, not removed.** The 7 plumbing modules flip to
  `hidden_module`; they stay executable by name. *Accept:* visible module count
  drops to the reframed number; a guard test proves the 7 remain runnable by
  string.
- **[R7] The catalog is legible.** The advanced catalog groups tools by phase and
  category with headers, uses the human `name` field, and advertises
  tab-completion (render the ghost-text preview that exists today). *Accept:* no
  flat alphabetical wall; every tool row shows a plain-language name; completion
  preview renders.
- **[R8] `workspace:export-findings` survives the hide.** Before hiding
  `workspace`, the export action is surfaced from the Report phase / a `findings
  export` verb. *Accept:* export is reachable from the reframed surface with the
  format argument honored (closes the markdown-bundle gap).

### 7.3 Findings ledger (Phase 1 — the spine)

- **[R9] One row, many sources.** Cross-engine collisions merge to one ledger row
  that accumulates `sources[]` (`["semgrep","cannon","sarif:CodeQL"]`). *Accept:*
  running two engines over the same defect yields one row with two sources, not
  two rows.
- **[R10] Human triage is sticky.** A `triaged_by` author flag guards every triage
  write; an AI re-run never overwrites a human verdict. *Accept:* port cannon's
  `human_decisions_are_sticky_across_remerge` test; it passes.
- **[R11] Corroboration is counted.** Merge derives a corroboration count.
  *Accept:* the count is available to the verify `--votes` gate and shown in the
  finding detail.
- **[R12] Engagement-scoped merge.** Findings merge on `dedup_key` across
  `scan_id` so many engines corroborate one row. *Accept:* a scan and an imported
  SARIF over the same defect corroborate rather than duplicate.
- **[R13] SARIF/semgrep seed-ingest.** `findings seed <file>` ingests external
  results, tagging `sources[]` and `triaged_by="imported"`. *Accept:* `seed`
  dedups against existing rows and adds a source.

### 7.4 Confirm / verify (Phase 3/4)

- **[R14] Verify is configurable.** `--when severity>=X --max N --votes K` on the
  scan/verify request; bare scan still verifies nothing. *Accept:* severity
  filter, cap truncation, and vote threshold each have a test; the
  bare-scan-verifies-nothing invariant holds.
- **[R15] Reachability oracle is deterministic.** The verifier can ask "reachable
  from an untrusted entry?" via the MCP oracles (Joern/CodeQL), with an explicit
  fallback when MCP is absent. *Accept:* oracle-absent is an honest, named state,
  never a silent pass.

### 7.5 Hunt / permutation planner (Phase 5)

- **[R16] Signal-driven proposals replace the static walker.** Generators propose
  priced, ranked, budget-gated salvos; the operator approves at the phase gate.
  *Accept:* generators produce proposals from git/manifest fixtures; the queue
  prices, ranks by yield, and refuses over-budget salvos; EMA recalibrates cost.
- **[R17] Planner lives in core.** `Proposal`/`Queue`/`Generator` live in
  `kuzushi-core`; the TUI gate and `--approve P-001,P-003` are parity chrome.
  *Accept:* the same proposals are approvable from shell and headless.
- **[R18] Budget honesty.** The cap gates *between* proposals; a single in-flight
  proposal that overshoots is surfaced, not hidden. *Accept:* the UI shows the
  known single-proposal overshoot rather than pretending the cap is hard.

### 7.6 Measure / tune (Phase 6)

- **[R19] Detection is a number.** `kuzushi measure` reports precision/recall/F1
  on a labeled corpus and head-to-head vs an imported SARIF; `--gate` fails CI on
  regression past a baseline+margin. *Accept:* F1 on a fixture corpus; `--against`
  is apples-to-apples; the gate exits non-zero on regression.
- **[R20] Prompts self-tune.** `kuzushi tune` does a train/test split and picks the
  best prompt variant on a holdout, feeding the `evolve` generator's fitness.
  *Accept:* holdout split is deterministic; fitness closes back to `evolve`.

### 7.7 Token & cost efficiency (cross-cutting; can lead)

- **[R21] No duplicate triage.** Triage dedups by fingerprint and skips
  already-persisted verdicts, defaulting to latest-scan scope. *Accept:* a repeat
  triage over a DB with duplicates issues one LLM call per unique un-triaged
  fingerprint, not one per row.
- **[R22] Prompt caching on the shipping path.** Anthropic prompt caching is wired
  with stable prefixes; large invariant context (repo inventory) moves to the
  prompt *head*, not the tail. *Accept:* a repeat run over unchanged context
  shows cache hits; carlini stops re-embedding the inventory per actor at the
  tail.
- **[R23] Budget enforced per-call.** The cost cap trips on call-count/token
  fallback when the provider reports `cost_usd 0.0`. *Accept:* a codex-backend run
  halts at the cap.

### 7.8 Headless & CI parity (cross-cutting)

- **[R24] `recon:import` is reachable.** Wired into the dispatch match arm and
  declared in the module. *Accept:* the advertised command runs.
- **[R25] `--target` is consistent.** One resolution rule across `scan`/`run`/
  `findings`/`finding`/`shell`; `kuzushi --target . scan` works. *Accept:* the
  three-way inconsistency is gone; every subcommand's `--target` has help text.
- **[R26] `run` errors are always valid JSON.** Prepare-errors emit the same JSON
  envelope as execution-errors. *Accept:* `kuzushi run … | jq` never sees empty
  stdout on error.
- **[R27] Export parity.** `workspace export findings <path> <format>` honors all
  five formats and accepts a directory for the markdown bundle. *Accept:* the
  markdown bundle is reachable via the friendly verb.

### 7.9 Terminal robustness (cross-cutting)

- **[R28] Palette degrades.** Detect `COLORTERM`; downsample the truecolor palette
  to 256-color so semantic colors survive on macOS Terminal.app. *Accept:*
  semantic colors are distinguishable on a non-truecolor terminal; `NO_COLOR`
  still respected.
- **[R29] Width math is unicode-aware.** Layout uses display width, not
  one-cell-per-char, so kanji/CJK/emoji tables and the footer align. *Accept:*
  the phase chip (組/崩/作/掛) and CJK content don't misalign tables or spill the
  footer.

### 7.10 Interaction model (cross-cutting; design-spec detail)

- **[R30] No empty-prompt hotkey trap.** Typing in the prompt is never captured by
  view hotkeys; the input mode and the `/`-escape are advertised. *Accept:*
  typing `config` on the Workbench landing does not fire `c`→exploit-chain then
  insert the rest.
- **[R31] One scroll/keybind grammar.** Arrows scroll content where content
  scrolls (history recall gated to the prompt); `g`/`Shift+Tab`/pause semantics
  are consistent across views; every advertised key is wired. *Accept:* the DAG
  `● active` legend matches what rows render; no key hint names an unwired
  action.

---

## 8. The signifier contract (why §7.3/§C requirements are P0)

Because the product promise is *evidence*, the finding surface has a hard
contract, tracked as a standing gate (see the TUI-signifier invariant):

- Every finding in every **list** (not just detail) shows its proof state:
  confirmed `✓` / candidate `◇` / unverified `?` / rejected `!`.
- A phase chip/rail reflects **engagement reality** (artifacts on disk, findings,
  triage/verify state), never the viewed page, and never renders without a
  target.
- A terminal state is terminal: canceled never becomes done; a legend never names
  a state the row cannot display.
- Focus, spinner, and status glyphs mean one thing each, consistently across
  views.

A change that regresses this contract is a release blocker, not a polish item.

---

## 9. Rollout — phased, shippable, mapped to the port plan

This PRD's requirements map onto the eight engineering phases in
[`cannon-port-plan.md`](./cannon-port-plan.md). Recommended order — each ends
green (tests + `pnpm quality:crap-risk`) and is independently shippable:

| Wave | Delivers (requirements) | Port-plan phase | Why here |
| --- | --- | --- | --- |
| **W0 — Honest surface** | R5–R8, R30–R31, R28–R29, plus the §C signifier bug fixes | Phase 0 | Reversible, decision-independent, visible value on day one. |
| **W1 — Reach value keyless** | R1–R4 | (onboarding, folds into 0/1) | Removes the first-run wall; unblocks every downstream funnel metric. |
| **W2 — Efficient runs** | R21–R23 | (token audit) | Stops the bleeding; can land in parallel with W0. |
| **W3 — One ledger** | R9–R13 | Phase 1 | The spine; unblocks votes and measure. |
| **W4 — Prompts as files** | (prompt resolution + sha) | Phase 2 | Small, independent, high value; feeds Aim's `engagement/prompts/`. |
| **W5 — Configurable Confirm** | R14–R15 | Phase 3/4 | Turns all-or-nothing verify into a knob; needs W3's corroboration. |
| **W6 — Signal-driven Hunt** | R16–R18 | Phase 5 | The deepest change; de-risked by W3. |
| **W7 — Detection as a number** | R19–R20 | Phase 6 | Publishable F1 + regression gate + self-tune. |
| **W8 — Engagement folder** | (Aim capstone) | Phase 7 | One editable `engagement/` folder + strategies; the verb collapse. |
| **cross** | R24–R27 (headless/CI parity) | — | Land opportunistically; R24 is a standing BLOCKER, do it early. |

**Sequencing rule (from `ROADMAP.md`):** nothing in a later wave is worth doing
while the ship-the-product work (P0.1 publish, P0.2 platform binaries, P0.3
supply-chain) is red. W0–W2 can proceed in parallel with that; W3+ should follow
a clean baseline.

---

## 10. Success metrics

Extends the `ROADMAP.md` world-class table with flow metrics:

| Metric | Today | Target |
| --- | --- | --- |
| Time from fresh launch → first finding (no key) | auth wall (∞) | ≤ 60s via `demo` |
| Findings with repo-verified evidence (span + hash) | Semgrep-only | 100% of persisted |
| "Exploitable: confirmed" backed by proof (level 4) | LLM opinion can claim it | crash/PoV-backed only |
| Confirmed-vs-guess visible in the list | detail-only | 100% of list rows |
| Duplicate LLM triage calls per unique fingerprint | up to ~11× | 1× |
| Prompt-cache hit rate on repeat runs | 0 | > 0, provider-permitting |
| Verify configurability | all-or-nothing | when / max / votes |
| Published detection number (F1 + head-to-head) | `baseline.json = {}` | scoreboard on real corpora |
| Signifier-contract violations (§8) | ≥ 5 known | 0 |
| Every phase reachable in shell + `scan --until` + `run` | partial | 100% parity |

---

## 11. Risks & guardrails

- **Model safety is a hard gate.** No ported path inherits a default-model
  behavior; `scripts/check-model-safety.mjs` stays green.
- **Mode parity by construction.** Planner + ledger + prompts in `kuzushi-core`;
  every wave updates `docs/assessments/mode-parity.md`.
- **CRAP / clean-code gate.** New functions ≤ complexity 4, < 40 logical lines,
  `pnpm quality:crap-risk` < 7. The merge and planner code are the likeliest
  offenders.
- **Baseline red tests.** HEAD already fails some workspace tests (BDD onboarding
  + snapshot; findings-store parity drift). Capture the known-red set before W3 so
  new regressions are attributable.
- **`.kuzushi/` path moves.** Backward compat of the *surface* is waived, but
  on-disk paths must be migrated (additive `open/init` migration), not broken, or
  existing targets stop resolving prior-run artifacts.
- **Overshoot honesty.** Preserve the planner's between-proposals gating; surface
  the single-proposal cap overshoot rather than pretending the cap is hard.

---

## 12. Open questions (blockers on specific waves)

Carried from the port plan, framed as product decisions:

1. **Export home (W0):** keep `workspace` visible, or relocate `export-findings`
   to a `findings export` verb before hiding it? *(Recommend: relocate — the
   Report phase is the natural home.)*
2. **Dedup key (W3):** adopt cannon's exact-line `basename:line:cwe`, or keep
   Kuzushi's `line/8` bucket and add `sources[]`/sticky on top? *(Exact-line
   matches cross-engine collisions better; the bucket tolerates line drift.)*
3. **Verify strategy (W5):** ship `--when/--max/--votes` on the existing verifier
   only, or also port cannon's full multi-lens 2-of-3 verifier as an alternative
   strategy? *(The latter is cannon's benchmarked edge but materially more work.)*
4. **Measure home (W7):** extend `kuzushi-eval` in place, or build a fresh
   `measure`/`tune` module that calls into it? *(Extending is cleaner but touches
   its recall-shaped report schema.)*
5. **Verb-collapse depth (W8):** hard-collapse 55 modules to ~8 verbs, or keep
   modules as strategy *passes* behind the phase verbs and only reframe the
   surface? *(Recommend the reversible option: reframe the surface, keep modules
   as passes.)*

---

## 13. Appendix — the flow, one screen

```
$ kuzushi --target ./acme-api

  Kuzushi · acme-api · Node/Express · LIVE                     [組 aim 1/5]
  ───────────────────────────────────────────────────────────────────────
  組 AIM ▸  崩 hunt   作 confirm   掛 fix   ▪ report
  ───────────────────────────────────────────────────────────────────────
  ATTACK SURFACE (engagement/map)          NEXT ▸ review the surface, then
    3 routes · 2 untrusted entries              approve a hunt salvo
    POST /auth/login   public, no rate-limit
    GET  /api/users/:id  IDOR candidate    steer:  model · prompts · budget
    POST /api/upload   no type validation          strategy: [stride ▾]
  ───────────────────────────────────────────────────────────────────────
  > aim            build/refresh the engagement folder
  > next           advance to Hunt (approve salvos under budget)
  > demo           no key? see a finding now (offline)
```

The catalog, the 55 modules, the MCP oracles, the bounty/recon intake — all
still there, one keystroke away in the advanced view. The *default* is the flow.
