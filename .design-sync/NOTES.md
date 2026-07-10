# design-sync notes — @kuzushi/tui-kit → "Kuzushi TUI Kit"

This project syncs a **hand-authored** React kit (`packages/kuzushi-tui-kit`)
that reproduces the live Rust Ratatui shell's design language for the web. The
live TUI itself (`crates/kuzushi-tui`) cannot be synced — Claude Design renders
web React, not a native terminal binary. The kit's tokens mirror
`crates/kuzushi-tui/src/theme/mod.rs` and its primitives mirror
`design/mockups/_shared.jsx`. Keep them in step when the shell theme changes.

**Atlas reconciliation (2026-07):** kit expanded 8 → **23 components** to mirror
the Atlas cockpit. The 5 control-room components were corrected to current TUI
semantics (`ProofBadge` → confidence ladder confirmed/likely/unverified/dismissed
· success/accent/muted/dim; `PhaseRail` → journey glyphs ✓●!⊘·; `EngineChips` →
cpg/codeql/lsp ready/build/opt-in; `MeterBar` → ratio auto-tone; `ProposalRow` →
+running/failed). New chrome: `CockpitPane` (left-rail pane), `AutonomyDial`,
`NextCallout`, `StatusChip`, `ReviewQueueRow`. New diagrams: `Heatmap`,
`AttackPath`, `DataFlowLadder`, `AttackTree`, `DfdDiagram`. A `dim` tone was
added (mirrors Rust `disabled()`). The palette itself did NOT drift — HEAD's
`theme/mod.rs` colours still match the kit tokens 1:1; the Atlas theme diff was
capability-downsampling + `proof_confidence_tone`, not new colours. Which Rust
renderer each new component mirrors is documented in its `.tsx` doc comment.

## Preview authoring — width is clip-not-wrap

`cols` on `TermFrame`/`Row` (and `Heatmap`) fixes the monospace grid width but
does **not** wrap or truncate — content wider than `cols` clips at the frame
edge (and a selection band ends mid-text). When authoring a preview, budget the
frame width for the **longest** row in the stack including all trailing meta,
then add a few cells of slack. Rules of thumb learned this run:
- Wide composed rows (`ReviewQueueRow`, `ProposalRow`) — frame `cols` ~10 over
  the row `cols`; row `cols` ~2 under the frame.
- `Heatmap` has its OWN `cols` prop — set it a few cells under the TermFrame
  `cols` so padded rows land flush (each severity cell is a fixed 8-char field).
- `DataFlowLadder` / `AttackTree` / `DfdDiagram` take no `cols` prop; width is
  bounded by the longest label — keep chain/flow labels short (~<50 chars) and
  wrap in `TermFrame cols={72..80}`. `DfdDiagram` auto-sizes its boxes to the
  widest zone/node label, so one long label widens every box.
- Kanji (組/崩/作/掛) and box-drawing (`╭╮╰╯│─▶●○◆◇▣☠⛭`) render cleanly in the
  capture font (JetBrains Mono) — no tofu.

## Build / run quirks

- The kit is **isolated from the Kuzushi CLI**: it is not a pnpm-workspace
  member (`pnpm-workspace.yaml` declares no `packages:` globs) and carries its
  own npm-installed `node_modules`, so React never enters the CLI build.
- Build command: `npm --prefix packages/kuzushi-tui-kit run build`
  (`tsc` → `dist/` + `cp src/styles.css dist/styles.css`). `cfg.buildCmd`.
- Converter invocation (from repo root):
  `--node-modules ./packages/kuzushi-tui-kit/node_modules`
  `--entry ./packages/kuzushi-tui-kit/dist/index.js`
- `cfg.cssEntry` = `dist/styles.css` (package-relative; holds the `:root`
  tokens + `kz-*` classes; appended into `_ds_bundle.css`).

## Known render warns (triaged — not failures)

- `[FONT_REMOTE] "JetBrains Mono"` — styles.css `@import`s the family from
  Google Fonts. Expected: the kit ships no local `@font-face`. Designs get
  JetBrains Mono when the host has network, else fall back to `ui-monospace`
  (the monospace grid is preserved either way). Re-sync should keep ignoring it.

## Re-sync risks (watch-list for the next run)

- **Fresh clone needs a kit build first.** `packages/kuzushi-tui-kit/dist` and
  `node_modules` are gitignored. Before re-running the converter on a clean
  checkout: `npm --prefix packages/kuzushi-tui-kit install` then `cfg.buildCmd`.
  Without `node_modules`, esbuild can't resolve `react` and the bundle fails.
- **Playwright ↔ chromium pin.** This run used playwright `1.61.1`, which pins
  the cached chromium build `1228` (`~/Library/Caches/ms-playwright`). Another
  machine may need a playwright version matching whatever chromium it has
  cached, or `DS_CHROMIUM_PATH` set to a known binary.
- **Grid-width fidelity.** `TermFrame` sizes its body to
  `calc(cols ch + 28px)` so the content grid is exactly `cols` monospace cells
  (the 14px×2 padding would otherwise clip full-width rows). The status strip is
  ~100 cells of content, so strip-bearing previews use `cols={100..112}`. If the
  strip fields change, revisit those preview widths.
- **Hand-authored kit, not a published dist.** There is no upstream package —
  the source of truth is this repo. Edits to `src/*` require a rebuild before
  the converter sees them.
