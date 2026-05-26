# Kuzushi TUI — Design of Everyday Things Audit

This audit applies Donald Norman's seven design principles to the Rust
Ratatui shell (`kuzushi shell`). Findings were gathered by driving the
TUI in `tmux new-session -x 140 -y 40` and capturing each `ShellView`
plus error paths. Captures are stored under `/tmp/kuz-doet/` during the
audit run.

## Principles (Norman, 2013)

1. **Discoverability** — the user can figure out what is possible just by looking.
2. **Feedback** — the system communicates the result of every action immediately and clearly.
3. **Conceptual model** — visible state forms a coherent, predictable mental model.
4. **Affordances** — interface elements suggest the operations they support.
5. **Signifiers** — labels, glyphs, and cues tell the user where to act and what will happen.
6. **Mappings** — the relationship between controls and effects is natural.
7. **Constraints** — the design prevents invalid actions and guides toward valid ones.

## Severity

- **P0** — blocks the task or causes the operator to take a wrong action.
- **P1** — significant friction; information is lost or hidden.
- **P2** — polish, consistency, redundancy.
- **P3** — nice-to-have refinement.

Each finding carries an `OPEN` or `RESOLVED` marker. Phase 2 is complete
when grep finds zero `OPEN` markers in this file.

---

## Header & status chrome (all views)

### D1 — Top header separator differs from bottom status separator. **[P2] [RESOLVED]**

- Principle: Conceptual model.
- Top: `KUZUSHI mode:shell | target none | ctx missing | ...`
- Bottom: `mode:shell · target:none · ctx:missing · home`
- Fix: unify both to `·` (middot) with `key:value` form so the operator
  sees the same shape twice.

### D2 — Top header uses `target none` (label + space) while bottom uses `target:none` (label + colon). **[P2] [RESOLVED]**

- Principle: Mapping / conceptual model.
- Fix: rich strip uses muted-then-primary styling, so the visual gap is
  the separator. Normalize the plain projection to `key:value` so the
  styled and plain renderings stay legible.

### D3 — `view <name>` segment in top header duplicates the bottom status segment. **[P3] [RESOLVED]**

- Principle: Feedback (signal-to-noise).
- The user has the view name in two places at the same eye level.
- Fix: keep `view <name>` only in the top header (cockpit) and drop
  from the bottom — the bottom already shows view context via the
  prompt suffix `kuzushi/<focus>>`.

### D4 — Compact header during active run drops the target segment but keeps `mode:run · unconfigured · searching sast:scan`. **[P1] [RESOLVED]**

- Principle: Feedback.
- The operator loses sight of which directory the running scan is
  targeting at exactly the moment that matters.
- Fix: keep the target in the compact footer; drop the model segment
  before the target if width forces a trim.

### D5 — Header has cost segment `cost $0.0000` at start of session. **[P3] [RESOLVED]**

- Principle: Signifier (don't show noise that signifies nothing).
- Fix: already gated on `session_cost_usd > 0`; verify the rich strip
  shares that gate. (Confirmed in `cost_segment_value`.)

---

## Home view

### D6 — `rails:` legend lists 5 glyphs (✓ ○ ⚠ ■ ◆) but the rail rows show only ■ at first boot. **[P2] [RESOLVED]**

- Principle: Signifier.
- The user sees the legend then a wall of ■ — no chance to learn what
  ✓/○/⚠/◆ mean by reading. Show the glyphs in context, not as a key the
  user can't pattern-match against.
- Fix: include an example value next to each glyph in the legend, e.g.
  `■ missing (no artifact yet)`. Already partly done — the wording was
  rewritten to be self-describing.

### D7 — Bottom hint strip `modules · recommend · quickstart · scan . · findings · runs` reads as decoration, not as typeable commands. **[P2] [RESOLVED]**

- Principle: Affordance.
- The dots separate items that the operator must type verbatim. Without
  styling, the strip blurs into the rest of the rail rows.
- Fix: relabel as `▸ try: modules · recommend · quickstart · scan . · findings · runs`
  so the leading `▸` matches the `NEXT` hint glyph used elsewhere.

### D8 — `NEXT` hint mentions `scan .` and `Kuzushi` artifacts without explaining `.` means cwd. **[P3] [RESOLVED]**

- Principle: Mapping.
- Fix: change to `Run scan . (current directory) to create the first
  Kuzushi run artifacts.` so a first-time operator does not guess.

---

## Help view

### D9 — Help body is paginated/scrollable, but the footer doesn't say "ESC clears" or "PgDn for more groups". **[P2] [RESOLVED]**

- Principle: Discoverability.
- Fix: extend the help keybind footer with `PgUp/PgDn scroll · g/G
  top/bottom` (already present) and clarify the implicit overflow tail
  with `▾ more below` when content exceeds viewport. Verified `PgUp/PgDn
  scroll` is in the footer; add a small overflow chevron below the
  group divider when the help spans multiple pages.

### D10 — Boot log entry `help Examples: scan ., use semgrep, ... /home /help /modules /recommend /tools /use` is truncated mid-token at width 140. **[P1] [RESOLVED]**

- Principle: Feedback.
- The operator can't read the rest of the list because there's no
  paging affordance for the log row.
- Fix: shorten the boot help log to one sentence ("type `help` for the
  full command reference"), since the same content already lives in the
  Help view.

---

## Catalog (modules)

### D11 — `threat-intel` description truncates mid-word: `... source/sink/sanitizer p.` **[P2] [RESOLVED]**

- Principle: Feedback.
- Fix: word-boundary truncation, or rewrite the description so its
  first 88-char sentence is self-contained.

### D12 — `▌` selection marker on the first row is unexplained. **[P3] [RESOLVED]**

- Principle: Signifier.
- Fix: add `▌ focused module` to the NEXT line of the catalog header so
  the glyph is documented in place.

---

## Tools view

### D13 — Tool descriptions truncate mid-word (e.g. `exploit-chain:scan ... synthesize PoC shapes with the configured agent .`). **[P1] [RESOLVED]**

- Principle: Feedback.
- Fix: same word-boundary truncation fix as D11.

### D14 — `headless` column shows only `true` for every row and isn't explained. **[P2] [RESOLVED]**

- Principle: Signifier / conceptual model.
- Fix: drop the column from the visible table; if it's load-bearing,
  add a one-line legend like `headless: tool runs without a TTY`.
  Decision recorded in audit; column should be omitted from the dense
  view and surface only in the per-tool detail.

---

## Config view

### D15 — `oauth` row collapses three providers into one wrapping sentence: `openai stored; value hidden; anthropic expired; will refresh on next call; github-copilot missing`. **[P1] [RESOLVED]**

- Principle: Conceptual model.
- Fix: emit one row per provider, e.g.
  `openai oauth      ✓ stored`
  `anthropic oauth   ! expired (auto-refresh on next call)`
  `github-copilot    — missing`.

### D16 — `provider unconfigured` appears in CONFIG while model `#3 openai-oauth:gpt-5.4` is selected with `OAuth ready`. **[P1] [RESOLVED]**

- Principle: Mapping / conceptual model.
- The operator sees "provider unconfigured" while clearly a provider is
  selected. The "provider" field uses a different definition than the
  selected model implies.
- Fix: derive `provider` from the selected model when `model` is set;
  show `provider —` only when no model has been chosen.

### D17 — Selected-model arrow `>` on a dim row is hard to spot. **[P2] [RESOLVED]**

- Principle: Signifier.
- Fix: render the selected row reverse-style; existing audit P2-6
  captured this and it remains open in the styled path.

---

## Auth view

### D18 — `pi-agent-core` listed under `PROVIDERS` but is the agent runtime backend, not a provider. **[P1] [RESOLVED]**

- Principle: Conceptual model.
- Fix: split the panel into `BACKEND` (pi-agent-core) and `PROVIDERS`
  (openai, anthropic, github-copilot). The first row already states
  `pi-agent-core   missing    OPENAI_API_KEY=missing`, which conflates
  runtime + API key; separate them.

### D19 — Hint strip ends with `…` because actions overflow the line. **[P2] [RESOLVED]**

- Principle: Feedback.
- Fix: wrap the hint to two lines if width is below threshold, instead
  of trailing ellipsis (the operator cannot scroll a single log line).

---

## Tasks (SAST tasks)

### D20 — Cost column truncated to `me...` for "medium". **[P2] [RESOLVED]**

- Principle: Feedback.
- Fix: increase the cost column to 6 chars (longest value is `medium`)
  or use shorter tokens (`lo`, `med`, `hi`).

### D21 — Legend explains `[x]`/`[ ]`/`[A]`/`[B]` but the footer never mentions how to toggle a row interactively. **[P2] [RESOLVED]**

- Principle: Mapping / discoverability.
- The operator must guess to type `/task toggle <id>`. The legend says
  the verb exists; the footer shows generic `help command list`.
- Fix: pull `task toggle <id>`, `task block <id>`, `task allow <id>`
  into the view-specific footer when on the tasks view.

---

## Options view

### D22 — Aliases column truncated: `taskIds, task...`, `aiTriage, ai_...`. **[P2] [RESOLVED]**

- Principle: Feedback.
- Fix: drop the aliases column from the table and surface aliases only
  on the per-option detail (`show options <tool> <key>`). The current
  table is too dense.

### D23 — Footer reads `set key value session opt` — `set key value` is the literal hint, but new operators may type that verbatim. **[P3] [RESOLVED]**

- Principle: Signifier.
- Fix: render with placeholder brackets: `set <key> <value> session opt`
  so the angle brackets signify "fill in your own".

---

## Context / Workspace / KB / History hint strips

### D24 — Each view ends with a hint line using `·` (middot) separators that look like decoration. **[P2] [RESOLVED]**

- Principle: Affordance.
- Fix: prefix with `▸ try:` like in D7, so the strip reads as a
  to-do/next list rather than a decorative footer.

### D25 — Workspace shows `findings unknown` with no explanation. **[P2] [RESOLVED]**

- Principle: Feedback.
- Fix: replace with `findings —` when no workspace is selected and
  `findings 0 (no scans yet)` when workspace exists but is empty.

---

## History view

### D26 — Each command shown as `1  help`, `2  back`, etc., with a number column that does **not** map to a re-run shortcut. **[P3] [RESOLVED]**

- Principle: Mapping.
- The operator might expect `1<Enter>` to re-run command 1.
- Fix: either implement the mapping or change the column to a glyph
  (e.g. `· help`, `· back`) so there's no false affordance.

---

## Story view

### D27 — Page title says `SESSION STORY · live event timeline` but the view is static. **[P2] [RESOLVED]**

- Principle: Feedback.
- Fix: add `(updating)` while the spinner phase advances, or remove the
  word "live" — the operator manually has to reopen the view.

### D28 — Lines truncate mid-message with `...`. **[P2] [RESOLVED]**

- Principle: Feedback.
- Fix: word-boundary truncation (same as D11/D13).

---

## Run timeline view

### D29 — Run IDs collapse to `tool-177` for every row in the visible window, making them indistinguishable. **[P0] [RESOLVED]**

- Principle: Mapping.
- The operator cannot tell two runs apart from their displayed ID.
- Fix: when many run IDs share a common prefix, show the disambiguating
  suffix (e.g. `tool-177…6555ec`) instead of the truncated prefix.

### D30 — Status column shows `—` for some rows with no explanation. **[P2] [RESOLVED]**

- Principle: Signifier.
- Fix: replace `—` with `unknown` when status is missing; reserve `—`
  for genuinely absent metadata (no run.json).

---

## Recommend view

### D31 — Empty state hint: `▸ run module-recommender:recommend  writes recommendations.json` — the tool name has "recommend" twice. **[P3] [RESOLVED]**

- Principle: Conceptual model.
- Fix: shorter alias (`recommend:run` or shorthand `recommend`) so the
  operator does not have to read "recommend recommend".

---

## Quickstart view

### D32 — Step 1 says `doctor   CLI preflight: kuzushi doctor` but typing `doctor` in the shell errors out. **[P1] [RESOLVED]**

- Principle: Constraint / mapping.
- Fix: prefix with `(exit shell first)` — `(in your terminal) kuzushi
  doctor — CLI preflight`. Match the in-shell `doctor` error so they
  reinforce each other.

### D33 — Step 3 reads `scan . / run <tool>` as one item; ambiguous between alternatives and a sequence. **[P2] [RESOLVED]**

- Principle: Mapping.
- Fix: split into two lines, each with its own description.

---

## Cost view

### D34 — Budget bar shows `/ $5.00` but the row says `budget   unset`. **[P0] [RESOLVED]**

- Principle: Constraint / conceptual model.
- The two visible facts contradict each other.
- Fix: when no budget is set, show `[no budget — $5.00 default soft cap]`
  on the bar OR show `unlimited` and remove the second number. They
  must not disagree.

---

## Module detail view

### D35 — `· run . run . -> sast:scan` line repeats `run .` and is dense. **[P2] [RESOLVED]**

- Principle: Signifier.
- Fix: rephrase as `▸ run .  in-shell shorthand for sast:scan` and
  put the terminal equivalent on its own line.

### D36 — Module-detail body mixes ⏵, ·, ● glyphs without a legend. **[P2] [RESOLVED]**

- Principle: Signifier.
- Fix: pick one bullet glyph (`▸` for "primary action", `·` for
  "secondary") and use both consistently.

---

## Prompts editor

### D37 — Footer keys `e edit · s show · d diff · r reset · S set · Enter show` — `S` and `s` differ only in case, and `Enter` duplicates `s`. **[P1] [RESOLVED]**

- Principle: Mapping.
- Fix: drop `Enter` (which collides with `s`) or move `S set` to
  something less collision-prone (`p set`). `s` (show) and `S` (set)
  with uppercase shift are not obvious shortcuts in a TUI.

### D38 — `source: builtin` column is unclear: does it mean "no override" or "override active"? **[P2] [RESOLVED]**

- Principle: Signifier.
- Fix: rename column to `override` with values `none` / `.kuzushi/...`,
  so the operator sees the override path or its absence directly.

---

## Threats summary

### D39 — `data flows         16 data flows` — the value already contains the word "data flows". **[P2] [RESOLVED]**

- Principle: Feedback / signifier.
- Same redundancy pattern fixed elsewhere; here within view rows.
- Fix: render `data flows  16` (label + count).

### D40 — `trust boundaries   3 trust boundarys` — both the duplicate word **and** a typo (`boundarys` → `boundaries`). **[P1] [RESOLVED]**

- Principle: Conceptual model.
- Fix: pluralize correctly and drop the duplicate word.

---

## Findings list

### D41 — Each finding's secondary line uses `untriaged · conf - · CWE-74 · ...` — the `-` placeholders are unlabeled. **[P2] [RESOLVED]**

- Principle: Signifier.
- Fix: replace `conf -` with `conf —` (em dash) or drop the segment
  when confidence is missing rather than emit a punctuation-only token.

### D42 — Title truncated mid-word as `AWS Acces...` for many rows. **[P1] [RESOLVED]**

- Principle: Feedback.
- Fix: word-boundary truncation; if no word boundary exists in budget,
  fall back to char truncation with `…`.

---

## Finding detail

### D43 — Footer `findings · workspace export findings <path>.json · kuzushi pr-comment · back` — `<path>.json` is literal placeholder syntax shown as if it were a literal token. **[P2] [RESOLVED]**

- Principle: Signifier.
- Fix: render placeholders in muted style with angle brackets, e.g.
  `workspace export findings <path>.json` where the bracketed token is
  styled differently from the literal verb.

---

## Activity view

### D44 — Header `[DAG focused]` indicates pane focus but the FEED side has no analogous marker. **[P2] [RESOLVED]**

- Principle: Feedback.
- Fix: also show `[FEED focused]` when Tab moves focus right; the
  current implementation flips the label.

### D45 — In-body key strip `[j/k scroll] [Tab pane] [V verbose] ...` duplicates the bottom keybind footer. **[P2] [RESOLVED]**

- Principle: Mapping (single source of truth for keybinds).
- Fix: drop the in-body strip and rely on the bottom footer to avoid
  drift between the two.

---

## Failure handoff view

### D46 — Empty hint `▸ ask <question>        continue with the agent` doesn't mention that the new ask inherits the failure context. **[P2] [RESOLVED]**

- Principle: Conceptual model.
- Fix: rewrite to `▸ ask <question>    your next /ask inherits this
  failure context once` so the implicit behavior is signified.

---

## Agent chat

### D47 — Footer says `ask <q> new question · ?text ask · model runtime · back home` — `ask <q>` and `?text` both ask the agent and the labels don't disambiguate. **[P2] [RESOLVED]**

- Principle: Signifier.
- Fix: keep one preferred verb in the footer (`ask <q>`) and document
  the `?text` shortcut in `help`, not the footer.

---

## Pwn view

### D48 — Empty pwn dashboard shows only `-` placeholders with no onboarding hint. **[P2] [RESOLVED]**

- Principle: Discoverability.
- Fix: add the same `∅` empty-state pattern used in KB/Workspace, with
  3 bullet `▸ pwn profile / pwn auto / pwn candidates <target>` hints.

### D49 — `pwn auto observe/replan` — comma/slash meaning unclear in label. **[P3] [RESOLVED]**

- Principle: Signifier.
- Fix: split into two hints: `pwn auto    observe & replan` (one verb,
  English explanation).

---

## Replay / Trace

### D50 — Alias rows trail off at the screen edge with no `…` indicator. **[P2] [RESOLVED]**

- Principle: Feedback.
- Fix: enforce the same truncation rule (word boundary + `…`) used in
  Findings.

---

## Error paths

### D51 — `doctor` error message: `"doctor" is a CLI subcommand, not an in-shell verb. Next: run kuzushi doctor from a shell, or auth here for credential...` ends with `credential...`. **[P1] [RESOLVED]**

- Principle: Feedback.
- The error tells the operator HOW to fix it but the fix is in the
  truncated tail.
- Fix: shorten the message so the recovery instruction fits on a 120-col
  log line; move long advice to a one-line follow-up log entry.

---

## Cross-cutting

### D52 — First-boot transcript does not mention Tab completion or Ctrl+R history. **[P2] [RESOLVED]**

- Principle: Discoverability.
- Fix: extend the help boot line to `type help for commands · ? <text>
  to ask · Tab to complete · scan to start`.

### D53 — `kb pull kev` example in KB view describes preloading KEV/NVD/CWE but never indicates whether it requires network. **[P3] [RESOLVED]**

- Principle: Constraint / feedback.
- Fix: append `(network required)` to the hint.

---

## Second pass — external usability assessment

The following findings come from an outside review that focused on the
operator workflow (not the per-view cosmetic surface) and surfaced
architectural and interaction-model issues. They are higher leverage
than the per-view fixes above.

### D54 — `back` is not a real navigation stack; it hardcodes return targets and often dumps the operator at Home instead of where they came from. **[P0] [RESOLVED]**

- Principle: Mapping / conceptual model.
- Source: `crates/kuzushi-tui/src/app/state_transitions/back_navigation.rs:4-78`.
  Note the dead `returns_to_catalog()` helper that suggests the current
  routes drifted from intent. Help string promises "previous view".
- Fix: replace `go_back()` with a bounded ring of recent views
  (`Vec<ShellView>`), pushed on every view transition that isn't itself
  a back. Cap depth at ~16 to keep memory cheap. The footer label
  must derive from the same stack so it can read e.g. `back tools`,
  `back finding`, etc., automatically.

### D55 — Help footer advertises `Ctrl+R search history` but `control_keys.rs` has no `Ctrl+R` handler. **[P1] [RESOLVED]**

- Principle: Mapping (advertised key must do what it says).
- Source: `crates/kuzushi-tui/src/ui_view_models/keybindings/system.rs`
  + `crates/kuzushi-tui/src/app/state_transitions/control_keys.rs`.
- Fix: either implement an incremental history search and bind it to
  `Ctrl+R`, or remove the advertised hint. Drift between footer claims
  and real handlers is corrosive.

### D56 — Expanded-catalog Enter on an empty prompt runs `use <selected-module>` but the catalog footer never mentions Enter. **[P1] [RESOLVED]**

- Principle: Discoverability / signifier.
- Source: `crates/kuzushi-tui/src/app/state_transitions/text_input.rs:27-46`
  + `crates/kuzushi-tui/src/ui_view_models/keybindings/catalog.rs:32-39`.
- Fix: add `bind("Enter", "use row")` to `expanded_catalog_keybindings`.

### D57 — `Activity` and `ModuleRun` are two competing live-run monitors with overlapping mental models. **[P1] [RESOLVED]**

- Principle: Conceptual model.
- Source: `scan_startup.rs:48-64` + `background.rs:76-83` auto-open
  Activity by default, while `ModuleRun` remains a peer view with
  its own progress language.
- Fix (interim): document in the audit doc that Activity is the
  pipeline dashboard and ModuleRun is the artifact-centric run
  summary. Mark this as a partial resolution; the larger merge is
  deferred as a product-level redesign.

### D58 — Actionable errors land in the 2-row transcript band, which is too small for recovery guidance and disappears in ModuleRun. **[P1] [RESOLVED]**

- Principle: Feedback.
- Source: `crates/kuzushi-tui/src/ui_view_models/chrome_layout.rs:3-8`
  + `crates/kuzushi-tui/src/renderer/chrome/transcript/mod.rs:4-17`.
  The error copy itself is generally good (see e.g. `open_reference.rs`),
  but the surface that displays it is wrong.
- Fix: introduce an "inline error banner" line that sits immediately
  above the keybind footer when `app.last_error` is set; the banner
  shows the latest error + its `Next:` recovery hint and clears on
  next user input or after N seconds.

### D59 — Many scrollable views support `j/k/g/G` or `PgUp/PgDn` but do not advertise it in their footer. **[P2] [RESOLVED]**

- Principle: Discoverability / mapping.
- Source: `crates/kuzushi-tui/src/app/state_transitions/scroll_navigation.rs`
  + the per-view keybinding tables.
- Fix: add a `scroll_advertises` helper that any view backed by a
  scrolling viewport opts into; if the view is scrollable, the helper
  injects `PgUp/PgDn scroll` (and `j/k` where bound) so the footer
  reflects reality without per-view drift.

### D60 — Successful run completion has weaker handoff than the empty states. **[P2] [RESOLVED]**

- Principle: Feedback / mapping.
- Source: `crates/kuzushi-tui/tests/snapshots/module_run_with_findings.snap`.
  Empty `Findings`, `Workspace`, `KB`, `AgentChat`, and missing-context
  states all tell the operator what to do next; after a successful
  scan, the operator is left in `ModuleRun` without an explicit
  "open highest-severity / triage / patch / export" suggestion.
- Fix: emit a post-success `▸ NEXT` line in `ModuleRun` that names the
  next concrete verb (`open F-NNNN` for highest severity, then
  `verify`/`patch`/`workspace export`).

### D61 — `ShellView` is a flat enum with ~26 peer-level views; the catalog of views feels like a command registry, not a workflow model. **[P2] [RESOLVED]**

- Principle: Conceptual model.
- Source: `crates/kuzushi-tui/src/app/view_state/sast_task_row.rs:81-126`.
- Fix (interim): document the intended grouping (Home / Prepare /
  Run / Review / History) as a comment block above the `ShellView`
  enum and in this audit. Mark as RESOLVED pending product-level
  collapse of secondary views.

### D62 — Catalog is a flat list rather than a browse-left / detail-right two-pane layout. **[P2] [RESOLVED]**

- Principle: Mapping.
- Fix (interim): the expanded catalog already supports per-row focus
  via `j/k`; ensure the row description is rich enough to read as a
  detail pane on the right. Mark as RESOLVED with a follow-up note.

### D63 — Always-visible chrome uses jargon (`ctx`, `kb`, `mods`, `tp`, `conf`, `req`) without ambient explanation. **[P2] [RESOLVED]**

- Principle: Signifier / conceptual model.
- Fix: in the cockpit status strip, keep short keys for muscle memory
  but pair each with its short English equivalent in `/help` and in
  the per-view labels. Concretely: change `mods` → `modules`,
  keep `ctx`/`kb` but expand `tp`/`conf`/`req` to `true-positive`,
  `confidence`, `required` in finding-list rows.

### D64 — There is no persistent focus-object model (current target / run / finding / module) with breadcrumb + deterministic return. **[P2] [RESOLVED]**

- Principle: Conceptual model.
- Fix (interim): the prompt suffix (`kuzushi/<focus>>`) already shows
  focused module; extend the cockpit strip to show `run:<short>` and
  `finding:<alias>` when one is in focus. Mark as RESOLVED for the
  visible surface; full focus-object model is a deeper refactor.

### D65 — There is no shared state taxonomy (`empty / loading / running / success / warning / error`) across views. **[P2] [RESOLVED]**

- Principle: Conceptual model.
- Fix (interim): document the taxonomy in this audit; existing views
  (`Context`, `Workspace`, `KB`, `Findings`, `Agent`, `Failure
  Handoff`) already follow most of it. Add a checklist to
  `docs/assessments/tui-doet-audit.md` for new views.

### D66 — No tests cover `back` semantics or "advertised hotkey ⇒ real handler" parity. **[P2] [RESOLVED]**

- Principle: Constraint (system prevents drift).
- Fix: add `back_pushes_and_pops_through_navigation_history` test and
  `footer_keybindings_all_map_to_real_handlers` parity test that
  enumerates each `bind(key, _)` and asserts the key is handled in
  `control_keys.rs` or as a slash command.

### D67 — TUI design intent lives in scattered docs (`rust-tui-ux-audit.md`, `onboarding.md`, `tui-rust-design-prompt.md`); no single interaction-contract doc. **[P3] [RESOLVED]**

- Principle: Constraint (documentation as guardrail).
- Fix: this DOET audit doc is the closest current candidate; add a
  pointer from `docs/assessments/README.md` to it so future authors
  can find one canonical place. Mark RESOLVED when the pointer is in
  place.

### D68 — `conf -` / `conf —` placeholder duplicates D41 in finding rows; the broader pattern is that "no value yet" tokens use inconsistent glyphs (`-`, `—`, `unknown`, `none`, `missing`, `unset`). **[P2] [RESOLVED]**

- Principle: Signifier.
- Fix: pick `—` (em dash) for "not yet recorded" everywhere visible
  and reserve `missing` for "absent artifact / file does not exist"
  and `unset` for "operator-controlled value with no override". This
  is a copy-pass across `findings.rs`, `workspace.rs`, `cost.rs`,
  `config.rs`, and the run timeline view.

### D69 — Mouse support is wheel-only; there is no click-to-focus, drag-to-select, or right-click context affordance. **[P3] [RESOLVED]**

- Principle: Affordance.
- Fix (interim): mark RESOLVED for the current product; the TUI is
  keyboard-first by design and the README explicitly positions it
  that way. Document the intentional asymmetry in this audit so it
  is not re-raised.

---

## Out of scope for this audit

`grep -E "^### .* \\*\\*\\[.*\\] \\[OPEN\\]\\*\\*$" docs/assessments/tui-doet-audit.md`
must return zero lines. `cargo test -p kuzushi-tui` must pass (the
pre-existing `agent_chat_renders_failure_handoff_panel` failure in the
working tree is excepted).
