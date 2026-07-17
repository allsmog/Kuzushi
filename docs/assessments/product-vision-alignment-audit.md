# Product-vision alignment audit

> **Status:** decision input, not a merge-ready change. **Owner:** you (the
> product decision-maker). **Date:** 2026-07-03. **Branch:**
> `design-sync/kuzushi-tui-kit`.
> **This is a kill/finish list, not a facts dump.** Every row is a
> *recommendation* that turns on product intent only you hold. Nothing here is
> deleted; treat the buckets as proposals to accept, defer, or reject.

This audit asks one question of every shipped feature: **does it still serve
where the product is going?** It is deliberately *not* a dead-code audit — a
feature can be reachable, tested, and documented and still be a candidate,
because the bar is alignment with the vision below, not whether it runs.

---

## 1. Vision anchor — the product Kuzushi IS becoming

Read from the product-flow PRD + design spec committed on this branch
(`docs/plans/product-flow-prd.md`, `docs/design/product-flow-design-spec.md`),
`ROADMAP.md`, CLAUDE.md's intentional-asymmetry list, and the
`kuzushi-cannon-overhaul` / `product-flow-prd` / `operator-fit-audit` notes.

**Kuzushi is a control room for non-deterministic security scans.** Six core
flows define it:

- **A1 — Control plane + visual plane.** Steer *where* the non-determinism
  spends and *how hard* to corroborate (control), and *see* the invisible agent
  reasoning — attack surface, DFD, threat model, chains, ledger, cost (visual).
- **A2 — The 組→崩→作→掛→report phase spine** (Aim / Hunt / Confirm / Fix /
  Report), derived honestly from workspace reality (`journey.rs` kept), with the
  **Workbench/cockpit as home** — not a catalog.
- **A3 — Close the loop: finding → decision → action.** Sample (a priced
  sweep) + corroborate (an adversarial, blind, multi-vote verifier) → confirmed,
  evidence-backed findings with an honest proof ladder and sticky human triage.
- **A4 — Composable parts → strategies.** The ~42 modules are
  detectors / analysis oracles / signal generators / verifiers, assembled into
  saveable **strategies** and fired as **priced, budget-gated sweeps**.
- **A5 — The mutable harness.** One editable `engagement/` object, recon-seeded
  and steerable by typed intent ("focus on SQLi").
- **A6 — Local-first, BYO-model (no silent fallback), detection-as-a-number**
  (F1 + head-to-head vs SARIF + CI regression gate).

**What it is explicitly NOT anymore** (ROADMAP "explicitly NOT doing" + PRD
non-goals + design-spec §0):

- A **scanner catalog to browse** ("pick a module, run it, watch its
  transcript"). The default is aim→fire, not shop-the-inventory.
- A **fully-autonomous CRS.** A human stays in the loop; triage/patch is not
  over-claimed as autonomous.
- **Cloud / SaaS anything.** Local-first is the wedge.
- **Broad pentest automation / binary exploitation as product surfaces.**
  Roadmap-only per the README's own product-focus statement (blackbox / pwn /
  honeypot / HTB) — kept only until they produce first-class evidence artifacts.
- **New scan engines or TUI views beyond the golden path.** Breadth dilutes;
  the engines we have aren't measured yet.

Everything below is judged against **this**, not against whether it works.

---

## 2. Method & coverage

Six enumeration slices: shell verbs/ShellViews, the module/tool catalog, CLI
subcommands, scan engines/capabilities, viz-pages/config/env, and the retained
TypeScript SDK. The shell-verbs and CLI slices ran as dedicated sub-agents; a
session limit killed the other four mid-run, so the module, scan-engine, viz,
and TypeScript findings are **my own direct investigation** (registration
tables, LOC/`git log` dating, umbrella-composition tracing, `package.json`).
Coverage is complete; provenance differs. Load-bearing facts were verified
firsthand at `file:line`.

**Buckets** (per the brief — no DEAD bucket; pure unreachable/dead-code was
handled by prior surface-cut audits):

- **ORPHAN-FINISH** — half-built or unrouted, but *serves an anchor* → finish/wire.
- **LEGACY-CUT** — worked for a prior product direction now abandoned → cut or quarantine.
- **REDUNDANT-FOLD** — a newer flow already covers it → remove/fold.
- **KEEP** — serves an anchor and a main flow routes to it (listed only where it corrects a prior claim).

"Cut" is a product-surface recommendation — remove from the shipping surface /
stop maintaining as a feature. For already-`.deferred()` modules it means
"finish quarantining or delete," not "it's live today."

---

## 3. The three flagged claims — verified, with corrections

The brief flagged three things to **verify with evidence, not take as given.**
All three prior-memory claims were partly wrong.

### 3.1 "A shadow catalog nobody routes to" — PARTLY WRONG
The `operator-fit-audit` note called ~36% of tools a "hidden-but-runnable shadow
catalog." Tracing `builtin_registration.rs:290–390` and the `sast:scan` umbrella
(`modules/application/sast_scan/run_sast_scan.rs:268–338`) splits that surface
three ways — it is **not** one monolithic orphan bucket:

- **Composed by the main scan flow, just hidden from the catalog** →
  **KEEP.** `carlini_threat_hunt` is `.deferred()` (`builtin_registration.rs:307`)
  yet the umbrella runs it and emits `carliniThreatHunt` in the report
  (`run_sast_scan.rs:269`). `systems_hunt` (visible) is likewise composed
  (`run_sast_scan.rs:272,308`). These are anchor-4 parts the flow already uses;
  the hidden flag is a *surface* choice, not evidence of orphaning.
- **Plumbing that SHOULD be hidden** (the cannon-port-plan Phase 0 list:
  catalog, config, router, full-mode, classifier-gate, smoke, workspace,
  engagement, module-recommender) → out of scope here (surface-cut, not vision).
- **Genuine prior-direction surface** (pwn, uaf-hunt, offense, chrome-rce,
  vendor-assessment) → **LEGACY-CUT** (§4).

### 3.2 "Control-room views are half-built" — CONFIRMED, and they are ORPHAN-FINISH not LEGACY
The control-room scaffolding is **real but nascent**: `crates/kuzushi-core/src/engagement/`
is *untracked* (brand-new, 229 LOC), `crates/kuzushi-core/src/strategy/` (783
LOC, 3 files) and `crates/kuzushi-tui/src/ui_view_models/strategy_queue.rs` /
`app/strategy/mod.rs` are WIP-modified. The `StrategyQueue`, `engagement`, and
`module_recommender` domain objects are now reachable through exact verbs
(`strategy`, `aim`, `recommend`) and the Workbench shows AIM harness state, but
they still need a polished steering gate that makes them the default room rather
than verb-only surfaces. Because they directly implement A4/A5, they are
**ORPHAN-FINISH** (the highest-value finishes in this audit), not legacy.

### 3.3 "3 of 5 viz pages are filler" — WRONG; it's 1 (+1 conditional)
Tracing `ui_view_models/viz_data.rs` empty-hint logic and the
`viz_page_for_tool` mapping:

- **Findings heatmap** — fed by real `scan` findings (`viz_data.rs:97–116`) → KEEP.
- **3D attack-surface terrain** — fed by `risk_by_module(&app.findings)` → KEEP.
- **DFD** — fed by the persisted threat-model doc (`dfd_model`, `viz_data.rs:163–200`) → KEEP.
- **Attack path** — fed by `taint-iris:hunt` (`taint_flow`, `viz_data.rs:274–303`);
  real *when the hunt runs*, empty-hint otherwise → KEEP (conditional).
- **Attack tree** — sole feed is `exploit-chain:scan` (`viz_data.rs:221–248`),
  and exploit-chain is a standalone LLM-narrative prototype (§4) last touched
  2026-05-12. If exploit-chain is cut, this page loses its only main-flow feed →
  **REDUNDANT-FOLD** (§6).

So the visual plane is in far better shape than "3 of 5 filler" — every page has
an honest empty-hint and three have unconditional real feeds.

---

## 4. LEGACY-CUT — prior-direction surface the vision deprioritized

The through-line: **broad pentest / binary exploitation**, the **catalog-era
"browse & run" product**, and **duplicate build artifacts**. ROADMAP names all
of these in its "explicitly NOT doing" list; the PRD non-goals repeat it.

| Feature | LOC | Last real touch | Serves anchor? | Evidence |
| --- | --- | --- | --- | --- |
| **pwn** (module + shell view) | 2,516 core + 214 tui | 05-12 (pre-reframe) | none | `modules/pwn/mod.rs` (2.3k-LOC monolith ROADMAP P4.4 already flags), `app/pwn/mod.rs`, `Pwn` ShellView. Binary exploitation = roadmap-only. Reads `KUZUSHI_REVNG_*` env (doctrine violation, §8). |
| **uaf-hunt** | 2,357 | (deferred) | none | `capabilities/uaf_hunt/`, `.deferred()` at `builtin_registration.rs:329`. Use-after-free / memory-corruption hunt — same binary-exploit surface. |
| **offense** | (module) | (deferred) | none | `offense_module.rs`, `.deferred()` at `builtin_registration.rs:340`. Offensive-action surface, roadmap-only. |
| **chrome-rce** | 467 | 05-20 (pre-reframe) | none | `capabilities/chrome_rce/`. Browser-RCE assessment; niche pentest, untouched by the reframe. |
| **vendor-assessment** | 884 | 05-26 (pre-reframe) | none | `capabilities/vendor_assessment/`. Not a phase part; pre-reframe. |
| **`kz` duplicate binary** | ~7 (25 MB artifact risk) | 05-20 | none | Fixed in WIP: the duplicate `kz` bin target and byte-identical `src/bin/kz.rs` wrapper are removed. Re-add only if packaging explicitly needs the short command. |
| **Catalog / Module / ModuleRun / Tools** ShellViews | ~ (tui) | 05-14 – 07-02 | none | The "browse modules → pick one → run → watch transcript" product the vision explicitly retired. Survive only as `modules`/`use`/`tools` verbs + Catalog's odd reuse as a transient run screen (`onboarding/runner.rs:523`). `run` now auto-opens Activity; findings live in Workbench. |
| **Story** ShellView | (tui) | 05-15 | none | `ui_view_models/session_story.rs`, `story` verb. Session-replay novelty; no anchor. |
| **LangChain default-install stack** | (npm) | — | infra | `package.json` still carries the five `@langchain/*` packages required by the load-bearing bridge. The unused `langchain` umbrella was removed and `typescript` moved to development-only; making the bridge stack optional remains a separate packaging decision. |
| **`github:allsmog/*` plugin specifiers** | (npm) | — | none | `package.json` optionalDeps: `tob-skills`, `vuln-scout`, `promptarmor-plugin`, `shinsa-plugin`. ROADMAP P0.3 supply-chain liability (personal-repo availability/integrity). Back the deferred `prompt_armor`/`shinsa`/`tob`/`vuln-scout` modules. |
| **Retired `src/copilot/print.ts` shim** | (ts) | — | none | Removed. The supported print API lives under the exported `kuzushi/modules` surface in `src/modules/print.ts`. |

**Nuance for pwn/uaf/offense/chrome-rce:** the PRD non-goal is "don't *ship*
roadmap modules until they produce first-class evidence artifacts" — so the
honest recommendation is **quarantine, not necessarily delete**: keep them
`.deferred()` and explicitly experimental, stop counting them as product
surface, and remove pwn's `KUZUSHI_REVNG_*` env-var path. pwn is the one
actively-visible (non-deferred) binary-exploit surface and the biggest single
LOC block — it should at minimum be `.deferred()`.

---

## 5. ORPHAN-FINISH — serves an anchor, nobody routes to it → wire it in

Ranked cheapest-to-integrate first. These are where the vision is *closest* and
the shipped code is *furthest* from being reachable.

| Feature | Anchor | State | Cheapest integration | Evidence |
| --- | --- | --- | --- | --- |
| **`kuzushi export`** | A2/A6 | Built + e2e-tested, **uncommitted** | commit the WIP | `application/export.rs` is untracked; the `Export` variant and dispatch are present in the working tree; exercised by `tests/e2e_bounty_flow.rs`. Closes ROADMAP "SARIF export CLI-unreachable." |
| **`kuzushi measure`** | A6 | Scorer ships as a separate binary | One `Command::Measure` arm delegating to a `kuzushi_eval` lib fn | `crates/kuzushi-eval/` already does F1/oracle-match over `kuzushi findings --json`; just not a `kuzushi` verb. |
| **`recon:import`** | A5 | Built + dispatch-wired in WIP | commit + keep scope tests green | Documented in CLAUDE.md bounty-workflow; the seed plane (A5) depends on it. |
| **Patch view completes the fix loop** | A3 | WIP now parses/apply/reject/regen | keep tests green + polish UX copy | `renderer/.../patch_lines.rs:121–127`; the only fix-shipping screen can now apply a human-reviewed diff through the shared remediation helper. Completes finding→action. |
| **StrategyQueue routed from the cockpit** | A4 | Exists (uncommitted), exact `strategy` verbs work | Surface it from Hunt / the steering gate | `ui_view_models/strategy_queue.rs`, `app/strategy/mod.rs`. **The single most important finish** — it *is* the priced-sweep control plane. |
| **`engagement/` harness object** | A2/A5 | Untracked domain scaffolding + `aim` verb | Finish steering gate around Aim | `crates/kuzushi-core/src/engagement/` (229 LOC, `??`), `engagement_module`; Workbench AIM now shows harness seeded/unseeded state. |
| **MCP oracle servers beyond taint-iris-next** | A1/A4 | WIP attaches to `verify:finding`; strategy still pending | Attach to strategy paths | `verify:finding` now exposes `mcps` and `mcpToolTimeoutMs`; tree-sitter/context/Joern/CodeQL/etc. attach conditionally from target artifacts. |
| **taint-iris-next path oracle** | A4 | 14.9k LOC, experimental, composed but not leaned on | Stabilize as the reachability FP-suppressor the PRD's A4 ladder needs | `capabilities/taint_iris_next/` (62 files); the neuro-symbolic `structural<linked<path` engine. Big but central. |
| **Evidence/reasoning cluster**: Runs, RunDiff, Replay, Trace, ActorDetail, FailureHandoff | A1/A3/A6 | Honest read-only surfaces, exact-verb-only | A Workbench pane / phase-rail entry | Read-only over shared `.kuzushi/v3/runs/`; serve the "see the invisible" + audit-trail anchors but nothing routes to them. |
| **Map-phase steering surfaces**: Context, ProjectModel, KnowledgeBase, PromptsEditor, ThreatEditor | A5 | Verb-only | Route from the Aim pane / steering gate (§8 of the design spec) | They *are* the harness/typed-intent levers the design spec's steering gate promises to converge. |

**Not orphans — genuine gaps (nothing to finish yet):** `scan --until <phase>`,
`--approve`, `--when/--max/--votes` have zero presence in the CLI and are blocked
on the sweep/strategy layer *existing in core*, not on flag plumbing. KLEE (the
PRD's proposed "proven" symbolic tier) is **absent from the tree** — greenfield,
not orphaned.

---

## 6. REDUNDANT-FOLD — a newer flow already covers it

| Feature | Folds into | Evidence |
| --- | --- | --- |
| **Home cockpit view** | Workbench | Workbench is the default landing (`run_shell::open_start_view`) and degrades to lines in plain mode (`routing.rs:86`); Home is a second line-based cockpit carrying no fallback duty. |
| **Recommend view** | Workbench recommend pane | Recommendations already render in `workbench/panes.rs:173`. |
| **Threat STRIDE / Stories / Scope / Summary text pages** | Workbench center + `/scene` DFD | The DFD was folded into the Workbench center (`sast_task_row.rs:281`); the text pages duplicate the same threat-model artifact. |
| **SastTasks view** | PlanningPicker | The phase walker now owns task selection. |
| **ModuleRun transcript view** | Activity / Workbench | `run` auto-opens Activity; Activity + Workbench own run feedback (`tool_runner/run_tool/dispatch.rs:59`). *(CLAUDE.md lists module-run transcript as an intentional asymmetry — see conflict below.)* |
| **`modules` + `tools` CLI** | one JSON listing | Two overlapping registry listings (`command.rs:149–160`); keep one for headless `run` discoverability. |
| **Attack-tree viz page** | (drop with exploit-chain) | Sole feed is the LEGACY-CUT `exploit-chain:scan` (§3.3). |
| **exploit-chain engine** | — (LLM-narrative prototype) | `scan/engines/exploit_chain/` (868 LOC, last 05-12); ROADMAP P4.3 calls it "an LLM-narrative prototype." Standalone; feeds only the attack-tree page. Fold or mark experimental. |
| **offense-review:threat-hunt ≈ carlini-threat-hunt:run** | carlini (composed) | Prior audit flagged a near-duplicate; carlini is the umbrella-composed one. **Verify the overlap before folding** — I could not fully confirm behavioral equivalence this pass. |
| **Tune view** | Options view | Shell agent judged Options covers the knobs. **CONFLICT:** CLAUDE.md lists `tune` as an intentional interactive-only asymmetry, and the PRD's headless table wants a `kuzushi tune` verb. Needs an explicit decision, not a silent fold. |

---

## 7. Summary table (feature → bucket → anchor → footprint)

Footprint = the touchpoints a cut/fold/finish crosses, per CLAUDE.md's
"adding a shell view" steps (view variant · command spec · renderer · reducer/keys ·
plain output · routing/screen_context · tests · docs · mode-parity matrix).

| Feature | Bucket | Anchor | Footprint |
| --- | --- | --- | --- |
| pwn (module+view) | LEGACY-CUT | — | executor + descriptor + `Pwn` view + renderer + `KUZUSHI_REVNG_*` env + tests + docs |
| uaf-hunt | LEGACY-CUT | — | executor + descriptor (already deferred) + tests |
| offense | LEGACY-CUT | — | executor + descriptor (already deferred) + tests |
| chrome-rce | LEGACY-CUT | — | executor + descriptor + tests |
| vendor-assessment | LEGACY-CUT | — | executor + descriptor + tests |
| `kz` duplicate binary | LEGACY-CUT | — | WIP removes `src/bin/kz.rs` and the duplicate `[[bin]]` target |
| Catalog/Module/ModuleRun/Tools views | LEGACY-CUT | — | 3–4 view variants + command specs + render arms + routing + tests + mode-parity |
| Story view | LEGACY-CUT | — | view variant + verb + `session_story.rs` + tests |
| LangChain default deps | LEGACY-CUT | infra | `package.json` deps→optional; keep bridge |
| `github:allsmog/*` specifiers | LEGACY-CUT | — | `package.json` optionalDeps + deferred plugin modules |
| `src/copilot/print.ts` | LEGACY-CUT | — | **complete**; implementation lives in `src/modules/print.ts` |
| Home view | REDUNDANT-FOLD | A2 | view + verb + renderer + back-nav |
| Recommend view | REDUNDANT-FOLD | A4 | view + verb + renderer |
| Threat text pages (4) | REDUNDANT-FOLD | A1 | view sub-modes + verbs + renderer |
| SastTasks view | REDUNDANT-FOLD | A4 | view + verb + renderer |
| ModuleRun view | REDUNDANT-FOLD | A1 | view + renderer + **mode-parity entry** (asymmetry) |
| `modules`+`tools` CLI | REDUNDANT-FOLD | — | one dispatch arm |
| Attack-tree viz page | REDUNDANT-FOLD | A1 | `VizPage` variant + `viz_data` builder + renderer |
| exploit-chain engine | REDUNDANT-FOLD | A1 | engine + `exploit-chain:scan` descriptor + snapshot cache + tests |
| offense-review threat-hunt | REDUNDANT-FOLD? | A3 | verify overlap first |
| Tune view | REDUNDANT-FOLD? | A5 | **decision needed** (asymmetry vs PRD) |
| `kuzushi export` | ORPHAN-FINISH | A2/A6 | commit the working tree |
| `kuzushi measure` | ORPHAN-FINISH | A6 | one `Command` arm |
| `recon:import` | ORPHAN-FINISH | A5 | WIP dispatch wiring; commit + preserve tests |
| Patch view apply | ORPHAN-FINISH | A3 | WIP parses footer verbs and applies reviewed diffs |
| StrategyQueue routing | ORPHAN-FINISH | A4 | cockpit/gate entry + commit |
| engagement harness | ORPHAN-FINISH | A2/A5 | WIP Aim verb + Workbench status; gate surface pending |
| MCP oracles | ORPHAN-FINISH | A1/A4 | WIP verify attachment; strategy attachment pending |
| taint-iris-next | ORPHAN-FINISH | A4 | stabilize/lean on |
| Runs/Replay/Trace/ActorDetail/FailureHandoff | ORPHAN-FINISH | A1/A3/A6 | Workbench/rail entry |
| Context/ProjectModel/KB/Prompts/ThreatEditor | ORPHAN-FINISH | A5 | steering-gate entry |
| src/modules TS SDK | LEGACY-CUT? | — | **decision: real external-author audience or cut** (4.7k LOC, no live consumer) |

---

## 8. Ranked action lists

### CUT / FOLD, by removable LOC (biggest surface reduction first)
1. **pwn cluster** — ~2,730 LOC + view + env path (biggest single block; at minimum `.deferred()`).
2. **uaf-hunt** — ~2,357 LOC (already deferred; delete or keep quarantined).
3. **exploit-chain + attack-tree page** — 868 + part of `scene`'s 1,955 LOC.
4. **vendor-assessment** — 884 LOC.
5. **chrome-rce** — 467 LOC.
6. **src/modules + src/testing TS SDK** — 4,664 LOC *if* no external-author audience (decision).
7. **Catalog/Module/ModuleRun/Tools + Home/Recommend/Threat-text/SastTasks views** — the bulk of the catalog-era + folded TUI surface (per-view LOC in `kuzushi-tui`).
8. **`kz` duplicate binary** — fixed in WIP by removing the second bin target and wrapper source.
9. **`offense`** — deferred; small.
10. **`src/copilot/print.ts`** — removed; `src/modules/print.ts` is the supported SDK surface.

### ORPHAN-FINISH, by cheapest-to-integrate (fastest vision wins first)
1. **`kuzushi export`** — commit the working tree (one commit; closes a ROADMAP item).
2. **`kuzushi measure`** — one `Command::Measure` arm over the existing `kuzushi-eval`.
3. **`recon:import`** — WIP dispatch wiring; keep the bounty-flow tests green.
4. **Patch apply verbs** — WIP parses and handles the three verbs the footer advertises.
5. **StrategyQueue cockpit routing** — surface the exact-verb queue from Hunt (**highest product value**: turns the control-plane scaffolding into a usable room).
6. **Evidence cluster + map-phase steering surfaces** — add Workbench/steering-gate entry points (no new engines).
7. **MCP oracles beyond taint-iris-next** — WIP attaches them to verify; strategy remains.
8. **engagement harness + taint-iris-next** — WIP Aim verb/status plus deeper A4/A5 stabilization.

---

## 9. Cross-cutting: env-var doctrine violations (not a feature, a cleanup)

CLAUDE.md forbids product-behavior env vars (scanner binaries, MCP/CodeQL/Joern
tuning) — those belong in declared options/config. Found reading `std::env::var`
in domain code:

- `KUZUSHI_RIPGREP_BIN` (`code_nav/ripgrep/ripgrep_binary.rs`) — scanner binary.
- `KUZUSHI_REVNG_IMAGE` / `_NATIVE` / `_CONTAINER_RUNTIME` (`modules/pwn/mod.rs`) — dies with pwn (§4).
- `KUZUSHI_JOERN_TIMEOUT_SECS`, `KUZUSHI_CODEQL_QUERY_SUITE`, `KUZUSHI_CODEQL_TIMEOUT_SECS`
  (`capabilities/taint_iris_next/application/*`) — exactly the MCP/CodeQL/Joern
  tuning CLAUDE.md names; should be declared options on the oracle path you're
  finishing anyway.

---

## 10. How to read this

- **This report produces recommendations, not facts.** The bucket of every row
  is a bet on product intent. Where I flagged "decision needed" (Tune, the TS
  SDK, offense-review overlap), I could not resolve it from code alone — those
  are genuinely yours.
- **It corrects three prior-memory claims** with evidence (§3): the shadow
  catalog is not monolithic, the control-room views are ORPHAN-FINISH not
  legacy, and the visual plane is 1-page-weak not "3 of 5 filler."
- **The cheapest wins were already-built-but-unwired** (export, measure,
  recon:import, patch apply). In this WIP, export and recon are wired, patch
  apply is implemented, and measure remains. The deepest win is routing the StrategyQueue/engagement
  scaffolding into a room, which is what separates "a catalog with a phase
  chip" from "a control room."
