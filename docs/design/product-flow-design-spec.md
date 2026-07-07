# Design spec — Kuzushi end-to-end product flow

> **Status:** proposal, awaiting review.
> **Companion to:** [`docs/plans/product-flow-prd.md`](../plans/product-flow-prd.md)
> (the *why* and the requirements) and
> [`docs/plans/cannon-port-plan.md`](../plans/cannon-port-plan.md) (the code seams).
> This document is the *how it looks and behaves* — screens, states,
> signifiers, keybinding grammar, and headless parity for the five-phase flow.
> Mockups are illustrative; exact widths/glyphs follow the shipped `kuzushi-tui`
> theme and Ratatui layout.

---

## 0. Design goals

The product is a **control room for non-deterministic scans**: a *control plane*
to steer where the non-determinism spends and how hard to corroborate, and a
*visual plane* to see the otherwise-invisible agent reasoning. Every screen
serves one of those two planes.

1. **The screen is the map.** At any moment the operator can see which phase they
   are in, what phase reality is (from artifacts on disk, not the viewed page),
   the running **cost**, and the single most useful next action.
2. **Steering lives at the phase boundary.** The control-plane levers — model
   tiers, prompts, budget, **strategy**, **engines**, the **harness/focus**, and
   verify config — are surfaced *together* at the moment you advance a phase, not
   scattered across 92 commands.
3. **Signifiers are honest by construction.** One glyph = one meaning. Terminal
   states are terminal. Cost and corroboration are always on screen. Nothing
   renders that phase reality doesn't support.
4. **Depth on demand.** The catalog — the 42 modules (composable *parts*, not a
   catalog to shop) and the MCP oracles — is one keystroke away, never the
   default path.
5. **Parity is structural.** Every interactive gate has a headless equivalent
   (`scan --until <phase>`, `run <tool>`, `--approve`, `--when/--max/--votes`,
   `--engines`, `--focus`, `findings seed`).

---

## 1. Information architecture

```
Shell (kuzushi)
├── Cockpit  ......... the home surface; phase rail + phase pane + steer + prompt
│   ├── Aim pane ......... attack surface / engagement folder
│   ├── Hunt pane ........ proposal queue (priced sweeps) + live activity
│   ├── Confirm pane ..... findings list with proof markers + verify config
│   ├── Fix pane ......... patch + re-verify
│   └── Report pane ...... export targets (SARIF / markdown / ledger)
├── Steering gate  ... modal-ish overlay at each phase boundary (model/prompts/
│                       budget/strategy/verify) — the one place levers converge
├── Finding detail ... proof ladder, evidence, sources[], corroboration, votes
├── Advanced catalog . the 42 modules as composable parts, grouped by phase
│                       (was the tile home + Recommend/Module/ModuleRun)
├── Activity ......... live DAG + output deck (auto-opens on run/scan)
└── Utility views .... logs, help, config, replay/trace, KB, threat views
```

The **Cockpit replaces the catalog as home.** `Catalog` / `Recommend` /
`Module` / `ModuleRun` collapse into the **Advanced catalog** (§7), reached by
`catalog` / `tools` or from the steering gate's "advanced" affordance.

---

## 2. The Cockpit (home surface)

Wide terminal (≥ ~100 cols):

```
┌ Kuzushi · acme-api · Node/Express · LIVE ······················ 崩 hunt 2/5 ┐
├────────────────────────────────────────────────────────────────────────────┤
│ 組 aim ✓   崩 HUNT ▸   作 confirm   掛 fix   ▪ report                        │  ← phase rail (reality-derived)
├──────────────────────────────┬─────────────────────────────────────────────┤
│ HUNT — proposal queue        │ ACTIVITY                                     │
│                              │                                              │
│ ▸ P-001  incomplete-fix hunt │  ⠿ taint-iris:hunt  src→sink  12s           │
│   commits · $0.40 · yield .82│  ⠿ semgrep         running    3/7 rules     │
│   [k]eep [s]kip              │  ✓ context-snapshot           done          │
│                              │                                              │
│   P-002  SSRF reachability   │  OUTPUT ▸ 2 candidates, 0 confirmed          │
│   threatmodel · $0.30 · .74  │  ─────────────────────────────────────────  │
│   [k]eep [s]kip              │  ◇ SSRF  webhook.ts:47   candidate           │
│                              │  ◇ IDOR  users.ts:31     candidate           │
│   P-003  dep footguns        │                                              │
│   intel · $0.15 · .40  [k/s] │                                              │
│                              │                                              │
│ budget: $0.85 / $2.00  ▓▓▓░░ │                                              │
├──────────────────────────────┴─────────────────────────────────────────────┤
│ NEXT ▸ approve sweeps, then `next` to fire   ·   steer: [m]odel [p]rompts   │  ← next-action + steer
│ [budget] [strategy: stride ▾]                                                │
├──────────────────────────────────────────────────────────────────────────────┤
│ > _                                                          / for commands   │  ← prompt (always focused when non-empty)
└──────────────────────────────────────────────────────────────────────────────┘
```

Compact terminal (< ~80 cols) collapses toward the review path (phase pane +
prompt), exactly as the current Workbench does, so findings/detail stay readable.

**Top bar** `Kuzushi · <project> · <target-facts> · <LIVE?> ······ <phase chip>`.
- `LIVE` lights only on real run activity (`has_run_activity`), never on view.
- The phase chip (`崩 hunt 2/5`) and rail are **derived from engagement reality**
  (`journey.rs`), not the viewed page. **With no target, there is no chip and no
  rail** (target-gated) — the fabricated-chip bug is designed out.

**Phase rail** shows the five phases with honest state glyphs:
`✓` done · `▸` current · (dim) not started. Exactly one `▸`. Done never
regresses to current.

**Phase pane** is the body; its content is the current phase's working surface
(§3–§6).

**Steer strip** exposes the levers relevant to *this* phase inline, and opens the
full steering gate (§8) on `next` or on the named key.

**Prompt** is a distinct focus (§9): when it holds text, keystrokes go to the
prompt, never to view hotkeys.

---

## 3. Aim (組) — map the target, generate the engagement folder

```
│ AIM — engagement/acme-api                                                   │
│                                                                             │
│ attack surface (map/)          threat model (threat-model.md)   [edit]      │
│   3 routes · 2 untrusted        STRIDE · 6 elements · 4 threats             │
│   POST /auth/login  public                                                  │
│   GET  /api/users/:id  IDOR?    strategies/                       [edit]     │
│   POST /api/upload  no-type     stride  ·  deep  ·  quick                    │
│                                                                             │
│ sources fed → context ✓  x-ray ✓  entry-points ✓  design-doc ○ (attach)     │
│                                                                             │
│ NEXT ▸ review & edit the folder, then `next` to open Hunt                   │
```

- **`aim`** synthesizes/refreshes the editable `engagement/` folder
  (`profile.toml`, `threat-model.md`, `map/`, `kb/`, `strategies/`, `prompts/`,
  `context/`, `authorization.md`) from existing producers. The
  provenance-tagged source bundle (context / prior threat-model / x-ray /
  entry-points / design-doc / seeds, each an `<untrusted-source label kind path
  sha256 truncated>` block) is what feeds the model — already in flight for
  `threat-model:build`.
- Every folder artifact is **editable in place** (`[edit]` opens the prompt/KB
  editor or the file). Editing calibration before Hunt is the whole point of the
  phase — no spend happens here beyond the map build.
- **`aim` seeds the harness.** A recon/discover pass pre-populates
  `engagement/harness.toml` — ranked focus areas (`{entry, input_surface,
  rank}`), detected toolchain/build system, an input vocabulary, and the default
  strategy/oracle. This is the mutable scan config the operator edits and the
  Hunt sweep fires (PRD §7). A fuzzer is never handed `main()`.
- **Prepare engines here, where cost is a one-time build.** `cpg:build` /
  `codeql-db:build` are surfaced as Aim actions with their build cost, so the
  scoped Confirm pass can enable the CPG oracle instantly (§8 steering gate).
- Empty state (no map yet): a single guidance line — *"run `aim` to map the
  target"* — never dummy content.

---

## 4. Hunt (崩) — signal-driven proposal queue

The static 22-task walker is replaced by a **priced, ranked, budget-gated
proposal queue** (see cockpit mockup §2). Behavior:

- Generators (`commits`, `threatmodel`, `intel`, `evolve`) emit `Proposal`s.
  Each row shows: id · generator · price · yield-score · `[k]eep`/`[s]kip`.
- A **budget bar** shows spend/cap. Proposals gate *between* firings; a single
  in-flight proposal that overshoots the cap is **surfaced** (`⚠ P-002 ran
  $0.05 over cap`), never hidden — honest about cannon's known edge.
- `next` fires the kept sweeps as a bounded fan-out with per-round checkpointing;
  Activity (right pane / auto-opened view) streams the live DAG.
- **Detectors and imports feed one ledger.** Live `native_scanners`
  (Semgrep/CodeQL) and `findings seed <sarif>` both write the *same* row via
  `sources[]`; the OUTPUT deck shows corroboration as it accrues.
- Headless parity: `scan --until hunt --approve P-001,P-003 --budget 2.00`.

---

## 5. Confirm (作) — proof, configurably

```
│ CONFIRM — findings (12)                    verify: when≥high · max 8 · votes 2│
│                                                                              │
│  ✓ SSRF   webhook.ts:47   critical   confirmed   proof●●●●  sources: 2       │
│  ◇ IDOR   users.ts:31     high       candidate   proof●●○○  sources: 1       │
│  ? XSS    render.ts:88    medium     unverified  proof●○○○  votes 1/2        │
│  ! ReDoS  parse.ts:12     low        rejected    (human)    ← sticky         │
│                                                                              │
│  NEXT ▸ [enter] inspect · [v] re-verify selection · steer verify at the gate │
```

- **Every list row carries its proof marker** — `✓` confirmed / `◇` candidate /
  `?` unverified / `!` rejected — plus a proof-ladder mini-meter and the
  `sources[]` count. This is the §8 signifier contract: confirmed-vs-guess is
  visible in the *list*, not just detail.
- **Verify is configurable at the steering gate:** `when severity>=X`, `max N`,
  `votes K`. Bare scan still verifies nothing. The header echoes the active
  config so the operator always knows what will be proven.
- **Human verdicts are sticky.** A row triaged by a human (`triaged_by="human"`)
  shows a `(human)` tag and is never overwritten by an AI re-run.
- **Detail view** (`enter`) shows the full proof ladder, verified evidence
  (span + content hash), `sources[]`, corroboration count, and — when votes ran —
  the per-lens verdicts (reachability / exploitability / mitigation) with the
  MCP-oracle reachability sentence (hedged: oracle, not ground truth). MCP-absent
  is an explicit named state, never a silent pass.

---

## 6. Fix (掛) & Report

**Fix.** Patch synthesis over a confirmed finding, re-verified against the same
ledger row. The diff is shown tied to the finding's evidence; re-verify updates
the proof state in place (never fabricating a higher proof than the re-run
supports).

**Report.** One explicit exit, reachable from the phase rail's `▪ report` and
from both surfaces:

```
│ REPORT — export evidence                                                     │
│   SARIF (CI / Code Scanning)      → ./acme-api.sarif        [export]          │
│   Markdown bundle (bounty)        → ./report/               [export]          │
│   Ledger (audit, JSON)            → engagement/findings.json [export]         │
│   CSV / JSONL                      → …                        [export]         │
```

- The friendly verb `findings export <path> <format>` honors **all five** formats
  and accepts a **directory** for the markdown bundle (closes the current gap).
- Headless: `workspace:export-findings {"format":"markdown-bundle","path":"…"}`
  and the first-class `kuzushi export` verb produce byte-identical output.

---

## 7. Advanced catalog (the reframed home)

The full registry stays reachable — legible, not a wall. The 42 modules read as
**composable parts** (detectors · analysis oracles · signal generators ·
verifiers, §6 of the PRD), grouped by the phase they serve:

```
│ CATALOG — 42 modules · ~67 tools                   [/] filter   [tab] complete│
│                                                                              │
│ AIM ── map & model                                                           │
│   context        build the context snapshot                                  │
│   threat-model   STRIDE/PASTA/DREAD threat model                             │
│   x-ray          entry points, invariants, data-flow                         │
│ HUNT ── find                                                                 │
│   taint-iris     source→sink taint hunt                                      │
│   semgrep/codeql live pattern + dataflow scanners                            │
│   variant-hunter lift a finding to a signature, hunt variants                │
│ CONFIRM ── prove                                                             │
│   triage · verify · exploit-chain                                            │
│ … (OFFENSE · INTEL · GOVERNANCE · ADVANCED show the rest)                    │
│                                                                              │
│ hidden-but-runnable: carlini-threat-hunt, tob, shinsa, recon … (type name)   │
```

- **Grouped by phase, then category**, with headers — never flat alphabetical.
- Each row uses the human-readable `name` field with a plain-language one-liner
  (retire circular descriptions).
- **Tab-completion is advertised:** the `completion_preview()` ghost-text (dead
  code today) renders inline; `[tab] complete` shows in the affordance bar.
- The 7 plumbing modules are hidden here (still runnable by exact name); the
  ~11 `.deferred()` capabilities are listed under an explicit
  "hidden-but-runnable" line so power users know they exist.

---

## 8. The steering gate (phase-boundary overlay)

The one place the scattered levers converge. Triggered by `next` (advancing a
phase) or by a steer key. It is the interactive equivalent of the headless flags.

```
┌ STEER → entering HUNT ─────────────────────────────────────────────┐
│  model      find:mid  triage:cheap  verify:deep     [change]        │
│  strategy   deep  ▾   (quick · deep · pr-review)                    │
│  engines    cpg ✓ (~40s/scan)  codeql ○  clangd-lsp ○   [toggle]    │
│  harness    focus: request handlers · seeds: 2 · oracle: reach      │
│  focus  ›   "focus on sqli"________________________              ↵  │
│  runs × variants   2 × {default, aggressive}   → 4-round sweep      │
│  prompts    engagement/prompts/ · 2 overrides · base sha 9f3a…      │
│  budget     $2.00 cap    ▓▓▓░░ $0.85 spent   · ~$0.75/round         │
│  verify     when≥high · max 8 · votes 2         (Confirm phase)     │
│  sweeps     P-001 ✓  P-002 ✓  P-003 ○                               │
│                                                                    │
│  [enter] fire   [e] edit a lever   [a] advanced catalog   [esc] back│
└────────────────────────────────────────────────────────────────────┘
```

- **Model tiers** route per role — cheap models for triage/dedup/classify, deep
  models for verify/patch/PoV. Each pick flows through the layered option store
  and is validated against the runtime here (no `anthropic:` model on a codex
  backend passing silently). No silent fallback: an incompatible pick is rejected
  in the gate with the reason.
- **Strategy** is the composed recipe = the sweep's variant axis (`deep = pattern
  + iris-taint + review×2 + invariant`); picking it expands into the sweep matrix.
- **Engines** toggles the analysis oracles for *this* pass (Joern CPG, CodeQL DB,
  clangd LSP) with a **cost/latency estimate shown before commit** — artifact-
  gated and honest; a missing prerequisite refuses with a build hint, never a
  silent degrade. The analysis-depth ladder (`structural → linked → path →
  proven`) drives which engine is needed.
- **Harness / focus** is the mutable scan config (§3): recon-seeded focus areas,
  seeds, oracle. Typing intent — *"focus on sqli"* — re-ranks focus areas, sets
  the oracle CWEs, and biases seeds for the next sweep.
- **Prompts** shows the 3-level resolution (`project override → variant → base`)
  and the base sha — provenance the operator can trust and diff.
- **Budget** prices the approved sweep; the cap is enforced between proposals with
  a self-calibrating `$/round`; a single-proposal overshoot is surfaced.
- **Verify** config shows only in/entering Confirm.
- Everything here has a headless twin: `--model`/`MODEL_<ROLE>`, `--strategy`,
  `--engines`, `--focus`, `--prompts`, `--budget`, `--when/--max/--votes`,
  `--approve`.

---

## 9. Interaction model & keybinding grammar

Fixing the audited interaction defects is part of this spec, not a follow-up.

**Prompt focus is distinct (fixes the empty-prompt hotkey trap).**
- The prompt is its own focus. When it holds text, *every* keystroke edits the
  prompt. View hotkeys fire only when the prompt is empty **and** the view has
  focus, or via an explicit modifier.
- A persistent affordance shows the mode: `> _   / for commands`. The `/`-escape
  to command mode is advertised, not hidden.
- Result: typing `config` / `cancel` / `demo` on the cockpit never fires
  `c` → exploit-chain and then inserts the rest.

**One scroll grammar.**
- `j`/`k` and `↑`/`↓` **both scroll the focused pane's content.** Command-history
  recall moves to the prompt context only (e.g. `↑` in an *empty* prompt), so
  arrows in Logs/Help/Activity scroll instead of silently recalling history.
- `g`/`G` = top/bottom everywhere (retire the `PlanningPicker` `g`=rebuild
  collision — move rebuild to an explicit key).
- `Tab` cycles pane focus, `Shift+Tab` reverses it **consistently** across
  Cockpit and Activity (retire the re-toggle divergence).
- Scroll-on-re-entry: **restore** last scroll in scrollable views, uniformly.

**One glyph = one meaning (fixes the DAG legend lie & state glyphs).**
- The DAG legend names exactly what rows render (if rows show a braille spinner
  for active, the legend says spinner, not `● active`). `●` is retired as a
  multi-meaning glyph.
- Task states: `⠿ running` (spinner) · `✓ done` · `× canceled` · `! failed`.
  **Canceled is terminal** — a late-finishing worker cannot flip `×` → `✓`
  (the `mark_task_done` guard includes `Canceled`).
- Proof glyphs (`✓ ◇ ? !`) and focus glyphs are each single-meaning and shared
  across views via the theme.

**Cancellation.** Two-stage Ctrl+C stays (it's honest today). Per-task cancel is
added where per-task `enter`/`f`/`o` already exist, so a runaway proposal can be
killed without aborting the sweep.

**Command grammar.** Converge on one grammar (`verb [subverb] [--flags | json]`);
retire the alias sprawl (`studio`/`cc`/bare-`/`) and the unconditional
single-letter `y`/`n` parse when no plan is pending.

---

## 10. First-run & empty states (keyless path)

The fresh-launch sequence is designed so value precedes credentials.

```
first launch, no key, no target
        │
        ▼
  TargetPicker ──(pick / defer)──► Cockpit (Aim, empty)
        │                                │
        ▼                                ▼
  ModelPicker  ── offers: providers  ·  ▶ demo (offline, no key)  ·  local
        │           incompatible pair rejected here, with reason
        ▼
  AuthPicker  ── paste API key (in-session) · OAuth (in-session)
                 never "set ENV and relaunch"
```

- **`demo` is a first-class choice** in the model picker and on every relevant
  empty state — *"no key? run `demo` to see a finding now (offline)"*. It runs
  the *same* deterministic secret-scan + iac-scan the CLI `demo` runs (not the
  full `sast:scan` umbrella), so its no-key/no-scanner promise is true.
- **Empty Cockpit** (no target/model) points at `demo` and `target`, not at
  `scan`/`next` (which need both).
- **`target <path>`** runs the *same* onboarding phase as the picker (model →
  auth), so both entry paths converge.
- Every empty phase pane draws **one guidance line** with the exact next verb —
  never dummy content, never a bare blank.

---

## 11. Headless & CI parity (the same flow, no TTY)

Every interactive gate maps to a flag so the flow is identical in `scan`/`run`:

| Interactive | Headless |
| --- | --- |
| `aim` (build engagement folder) | `run context:build` / `threat-model:build` → `scan --until aim` |
| Hunt proposal approve | `scan --until hunt --approve P-001,P-003 --budget 2.00` |
| Steering gate model/prompts | `--model … --prompts engagement/prompts` |
| Confirm verify config | `--when severity>=high --max 8 --votes 2` |
| Report export | `workspace:export-findings {"format":"…","path":"…"}` / `kuzushi export` |
| Measure/Tune | `kuzushi measure --against x.sarif --gate` / `kuzushi tune` |

Contract fixes required for CI (from the devEX audit):
- **`recon:import` reachable** (wired into dispatch — standing blocker).
- **`--target` one rule** across `scan`/`run`/`findings`/`finding`/`shell`;
  `kuzushi --target . scan` works; every subcommand's `--target` has help text.
- **`run` errors are always a JSON envelope** (prepare-errors included) so `jq`
  never hits empty stdout.
- **Export honors format + directories** through the friendly verb.

---

## 12. Terminal robustness

- **Palette degrades:** detect `COLORTERM`; downsample the truecolor `Color::Rgb`
  palette to 256-color when truecolor is absent, so semantic colors survive on
  macOS Terminal.app. `NO_COLOR` and `KUZUSHI_THEME=high-contrast` still honored;
  `KUZUSHI_REDUCED_MOTION=1` still pauses the spinner.
- **Unicode-aware width:** layout math uses display width (not one-cell-per-char)
  so the phase chip (`組/崩/作/掛`), CJK, and emoji don't misalign tables or spill
  the footer. The adaptive footer wraps below 70 cols (already good) — keep it.
- **Frame-rendered pages fall back to text:** the 3D terrain and box-drawing
  diagrams degrade to line/plain output off-TTY (heatmap data already exists; the
  terrain needs the text fallback wired).

---

## 13. What we explicitly keep (do-not-cut)

From the audits, these already tell the truth — preserve them through the reframe:
- Two-stage Ctrl+C (honest, consistent).
- No anonymous spinner — every spinner bound to a named subject.
- `journey.rs` phase derivation (refuses to forge Done) — the reframe builds *on*
  it, replacing execution, not derivation.
- `doctor` WARN/FAIL always names the problem + a `Next:` remediation — the gold
  standard for every new error message in this flow.
- `scan --fail-on` exits 3 (distinct from 1/2), CI-safe.
- In-session API-key paste (already fixed) — make it the advertised path.
- `NO_COLOR` respected through every theme fn; out-of-scope refusal names the
  file + edit.
- Machine output (`--json`/`--ci`/`--sarif`/`--fail-on`) is solid — parity work
  extends it, doesn't disturb it.

---

## 14. Open design questions

Mirrors the PRD's §12, framed for design:
1. Does the steering gate render as a full-screen view or an in-cockpit overlay?
   *(Recommend overlay — keeps the phase pane visible for context.)*
2. In Confirm, is the proof-ladder mini-meter (`proof●●○○`) or a numeric level
   (`L2/4`) clearer at list density? *(Recommend the meter; numeric in detail.)*
3. Advanced catalog: phase-first grouping (as drawn) or category-first? Phase-first
   matches the flow but splits OFFENSE across phases.
4. Hunt: show all generator proposals at once, or paginate by generator? At high
   proposal counts a flat list may overflow the pane.
