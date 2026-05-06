# TUI Rust Design Prompt — Kuzushi (Ratatui)

A self-contained brief to hand to **Claude Design** (or any Claude surface
running design work) to produce updated, enhanced terminal UI designs for the
Rust shell. Paste everything below the `===` line as the user message. The
brief is intentionally exhaustive on constraints so the model does not have to
read the repo to produce useful output.

---

## How to use

- Open Claude Design (or claude.ai with design skill enabled).
- Paste the prompt below as the first user message.
- Attach screenshots of the current TUI if you have them — they're optional
  because the prompt enumerates every existing view in text.
- Iterate per view. The prompt asks Claude to produce one mockup at a time so
  responses stay focused; ask "next view" to advance.

---

===

# Role

You are a senior terminal-UI designer redesigning the **Kuzushi Rust shell**, a
security-research operator console built with `ratatui 0.29` + `crossterm
0.29`. Your job is to produce **enhanced ASCII/Unicode mockups** for each
sub-view, mapped 1:1 to ratatui widgets that the engineering team can
implement without invention.

You are **not** designing a GUI. Every pixel is a monospace cell. Every color
is one of eight named theme styles. Every interaction is a keystroke or a
slash-verb typed into the prompt line.

# Surface constraints (hard)

- **Library:** `ratatui` (Frame, Rect, Paragraph, Block, Borders, Tabs, Table,
  Gauge, BarChart, Sparkline, List, Wrap, Layout::Vertical/Horizontal). No
  custom widget rendering outside ratatui primitives unless you specify the
  `Buffer::set_string` calls explicitly.
- **Backend:** crossterm. Assume true-color, but degrade gracefully to 16
  colors and to 0-color (mono). Test layouts at **80×24** (SSH minimum) and
  **120×40** (default modern terminal).
- **Charset:** ASCII + the box-drawing subset already present:
  - rule: `─`  (single horizontal)
  - separator: ` · ` (U+00B7 with surrounding spaces)
  - status icons: `●`, `⏺`, `✓`, `→`, `○`, `◆`, `■`, `⚠`, `[!]`, `[+]`
  - actor/finding markers: `★`, `✻`, `⎿`
  Only introduce new glyphs if you list them and confirm they're in standard
  monospace fonts (Iosevka, JetBrains Mono, SF Mono).
- **No Nerd Fonts.** Operators run this over SSH on stock terminals.
- **No animation past 4Hz.** No spinners with sub-100ms frames. No marquee.
- **Plain-mode equivalent required.** Every TTY view must have a plain
  (non-TTY) rendering — same lines, ANSI stripped, no boxes. Specify both.

# Theme (locked palette — do not invent colors, only reuse roles)

| Role        | Default color           | Used for                              |
| ----------- | ----------------------- | ------------------------------------- |
| `primary`   | LightBlue               | body text, default content            |
| `muted`     | Cyan                    | secondary text, hints                 |
| `subtle`    | Blue                    | rules, separators, inactive           |
| `accent`    | LightBlue               | active item, action verb              |
| `label`     | LightBlue + bold        | section headings                      |
| `heading`   | LightBlue + bold        | view titles                           |
| `success`   | Green                   | done / ok / additive                  |
| `warn`      | Yellow                  | rate limits, advisories               |
| `danger`    | Red                     | cost-cap halt, critical findings      |
| `selection` | Black on LightBlue bold | the *one* focused row/chip            |
| `severity()`| varies by severity      | finding severity tags only            |

If you want a new role, propose it with a name and explain the role it fills
that `primary/muted/subtle/accent/label/success/warn/danger/selection` does
not. Don't pick raw colors — pick semantic roles.

# Views in scope (redesign each)

The shell has one root state and a `ShellView` dispatcher. List of views,
keyed by the `ShellView` variant — design output is one mockup per view:

1. **`Catalog`** — entry view. Modules grouped into 4 categories: OFFENSE,
   INTEL, GOVERNANCE, DEFENSE. Each row = `id · description · dag?`. Today
   it's a flat table with section dividers. Goal: make the recommended next
   action obvious; show target/context status without burying it.

2. **`Module`** — per-module home. Header (id · name + 1-line description),
   TOOLS table (`tool · headless · description`), optional DAG table
   (`node · output · depends-on`). Goal: surface the most-likely next verb.

3. **`ModuleRun`** — live transcript while a tool runs. Header line uses `●`
   + target + stage + finding count + run id. Pipeline rows use `✓ / → / ○`
   for stage state. Below that, a TRANSCRIPT divider + scrolling actor lines
   (`● Tool · ⎿ result · ✻ Thinking · ★ Finding`). Goal: make it readable
   at a glance which actor is doing what and what just changed.

4. **`Findings`** — unified findings list. Filter chips today are inline
   `[all] [critical] [high] [medium] [low]` (selection is just inverted
   block). Then a table. Goal: chips must read as chips; severity must
   pop without dominating; chains (multi-finding clusters) need their own
   visual treatment (today they're just rows).

5. **`Finding`** — linear deep page for one finding. Severity strip + title,
   detail rows (alias, location, rule, tool, fingerprint), EVIDENCE block,
   optional TRIAGE block. Goal: timeline of state changes (queued → triaged
   → verified) is currently absent — design one.

6. **`Tune`** — six plain controls (severity floor, triage confidence, scan
   concurrency, …) + optional `.kuzushi/house-rules/<module>.md` block.
   Goal: turn it from a key/value dump into a control panel that suggests
   what each knob does to the run.

7. **`Threat(Dfd)`** — ASCII DFD grouped by trust zone (external →
   application → datastore). Today it's three detail rows + a one-line
   arrow diagram. Goal: an actual ASCII DFD that fits 80 cols and 120 cols.

8. **`Threat(Stride)`** — element × STRIDE heat matrix
   (S/T/R/I/D/E columns; rows = entrypoints, auth, storage, scanners).
   Today shows `low/med/high` text. Goal: heat shading via theme roles
   (success/warn/danger) without ANSI 256-color tricks.

9. **`Threat(Stories)`** — attacker narratives (A1, A2, A3 …).
   Goal: card-style layout, each story with its driving STRIDE letters
   and the element(s) it touches.

10. **`Threat(Scope)`** — criticality buckets + out-of-scope. Goal: tri-
    column or stacked layout that operators can read top-to-bottom.

11. **`Threat(Summary)`** — counts bar charts + drives + artifact paths.
    Goal: ratatui `BarChart` with `severity()` colors; minimal text.

12. **`ThreatEditor`** — full-screen editor over `.kuzushi/threat-model.json`.
    Goal: split-pane (sections list / current section content), no inline
    JSON editing.

13. **`PromptsEditor`** — per-module prompt overrides (`scan/triage/verify/
    summary` rows; source = builtin/file/inline; override path). Goal:
    show *which* prompts are overridden vs. builtin at a glance.

14. **`ActorDetail(n)`** — drill from `ModuleRun` into one actor's
    transcript. Goal: chronological log with timestamp gutter, fold/unfold
    affordances for long results.

15. **`Runs`** — past pipeline runs (`.kuzushi/runs/<runId>/`). Today: list.
    Goal: timeline-style view, status pill per run, total cost column.

16. **`Replay(runId)` / `Trace(runId)`** — read-only views over past run
    artefacts. `Replay` re-renders the summary; `Trace` streams the JSONL.
    Goal: make it visually distinct that the operator is in *historical*
    mode (not live) — borrow a style from "preview" / archive UIs.

17. **`Help`** — slash-verb reference. Today: long flat list. Goal: group
    by category (navigation, planner, prompt-editor, replay, aliases,
    failure-mode), search-as-you-type hint.

18. **`Config`** — `~/.kuzushi/config.json` view. Goal: surface model auth
    state and routing mode; today it's flat.

19. **`Tools`** — flat list of every loaded tool. Goal: filter chips by
    module, severity-of-output, headless/interactive.

20. **`Options(view)`** — per-tool option editor. Today: 6-column table
    (option/value/default/req/type/description). Goal: visually separate
    *required & missing* from the rest; today it's a single sortless table.

21. **`SastTasks`** — auto/manual task allowlist. Goal: bulk-toggle UI
    that does not require typing every id.

22. **`Context`** — context-snapshot status. Goal: visual breakdown of
    indexed vs. stale slices.

23. **`Workspace`** — workspace state. Goal: clear "is this a new repo or
    an existing one?" answer.

24. **`KnowledgeBase`** — KB artefacts + attachments. Goal: split between
    artefacts (long-lived) and attachments (per-finding evidence).

25. **`AgentChat`** — conversational agent transcript. Goal: distinct
    visual style from ModuleRun (chat vs. pipeline).

26. **`History`** — operator command history. Goal: deduplicated, with
    the per-command outcome (✓/→/✗) inline.

27. **`Story`** — operator narrative log. Goal: optional richer cards,
    one per story event.

# Persistent surfaces (design once, applies to every view)

- **Status footer** (1 row, full width). Left segments are joined with ` · `:
  routing mode, model id, target/scan stage, focused module. Right segments:
  Ctrl+C-armed warning, findings summary. Goal: stop the left side from ever
  truncating the right; today both fight for the line.
- **Keybind footer** (1–2 rows). Top row is a `─` rule; bottom row is a list
  of `(label, key)` pairs. Goal: bind groups instead of a flat list.
- **Throttle banner** (1 row, conditional, yellow). `⚠ rate limit · <source>
  · <message>`. Goal: a single tasteful affordance — keep small, keep
  pre-existing layout intact.
- **Plan card** (3+N rows, conditional, accent border). `◆ PLAN · goal`,
  summary, `+ change` rows, `! unsupported` rows, `[y] apply [n] discard`.
  Goal: clearer visual separation from the view above; today it sits inline.
- **Threat patch card** (3+N rows, conditional). Similar to plan card.
- **Cost-cap halt** (2 rows, conditional, danger). `■ COST CAP HALT · spent
  $X / cap $Y`, `[c] continue past cap [a] abort scan`. Goal: scarier than
  the throttle banner; pull operator attention.
- **Transcript** (2 rows, conditional, when the active view is *not*
  ModuleRun and there's a tool running). Goal: a 2-line ticker.
- **Prompt line** (1 row, last). `kuzushi[/<module>]> ` + cursor.

# Output format (per view)

For each view I ask for, return exactly this structure:

````
## <ViewName>

### Mockup — 120×40
```
<ASCII mockup, exact width 120, height ≤ 40>
```

### Mockup — 80×24
```
<ASCII mockup, exact width 80, height ≤ 24>
```

### Plain-mode (non-TTY)
```
<same content, no box chars, no color cues, no ratatui blocks>
```

### Ratatui widget map
- top-level: `Layout::Vertical([Length(N), Min(0), Length(1)])`
- region 0: `Block::default().borders(Borders::BOTTOM)` …
- region 1: `Table::new(rows).header(...).widths([Constraint::…])`
- (etc.)

### Theme deltas
- new role? (yes/no — if yes, propose name + role + when used)
- color use per region: `region 0 title: theme::heading()`, …

### Keybinds & focus
- `j/k` …
- `1..5` …
- `/<verb>` …

### Tradeoffs / why this design
- (3–6 bullets — what you optimized for, what you sacrificed, what
  alternates you considered)
````

# Iteration protocol

- I will name **one view at a time**: e.g. *"do `Catalog` first"*. Produce
  exactly one full block in the format above, then stop.
- After my "next" reply, do the next view I name.
- If I say *"variant: <hint>"*, regenerate the same view applying the hint.
- If a view seems too small to redesign meaningfully, say so and propose
  consolidating it with another view.
- Do **not** invent data. Use the field names listed above; if you need a
  field that doesn't exist, label it as `<placeholder: …>` so engineering
  knows it's a request, not a fact.

# Anti-goals

- Do not propose mouse-driven UI.
- Do not propose multi-window / floating-pane layouts.
- Do not propose features outside the rendering layer ("add an LLM button",
  "stream from Slack"). Stick to layout, hierarchy, color use, glyph use,
  keybind grouping.
- Do not move logic into the view ("the renderer should fetch X"). Renderer
  consumes `ShellApp` state; if a field is missing, flag it.
- Do not add a settings/preferences screen on top of `Tune` and `Config` —
  consolidate, don't proliferate.

# First task

Start with **`Catalog`**. The mockup must show:

- Context strip on top (target path, ctx status, model id, focused module).
- A single "recommended next" affordance (today this is one styled line —
  redesign it so it reads as an action, not a hint).
- Four category sections (OFFENSE / INTEL / GOVERNANCE / DEFENSE), each with
  a 1-line blurb and a table of `id · description · dag?` rows.
- The status & keybind footers + prompt line at the bottom.

Use **3–5 modules per category** as placeholders (e.g. semgrep, codeql,
randori under OFFENSE; context, sentry under INTEL; config, audit under
GOVERNANCE; triage, verify under DEFENSE).

When done with `Catalog`, stop and wait for my next view name.
