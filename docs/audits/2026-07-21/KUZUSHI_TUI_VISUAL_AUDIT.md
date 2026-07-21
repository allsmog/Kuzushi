# Kuzushi TUI visual integrity audit

Date: 2026-07-21

Baseline: `ea707337e4`

Trigger: corrupted Scan view in Warp at 104 columns × 61 rows

Scope: interactive Ratatui shell, plain rendering, shared text/table primitives,
decision cards, Map/Scan phase composition, and reusable code reachable while
the alternate screen is active.

## Executive verdict

The screenshot's catastrophic-looking overlap was not caused by intersecting
Scan rectangles. It was terminal state corruption: configuration migration
warnings were written with `eprintln!` after Ratatui entered the alternate
screen. Those bytes made the terminal scroll and overwrite physical cells,
while Ratatui's diff buffer still believed the old cells were intact. The next
draw therefore repainted only its logical delta and left warning fragments,
merged words, and displaced rows behind.

The direct cause is fixed. Configuration loading is now side-effect-free;
diagnostics are returned as typed data and are presented at the owning CLI or
TUI boundary. Reusable in-process paths no longer write behind Ratatui, and
interactive child processes audited in this pass either have their output
captured, explicitly suppressed, or run outside the alternate screen. A source
ratchet protects the known interactive paths.

The audit also found and fixed independent visual defects that the terminal
corruption made harder to distinguish: character-count width calculations,
trailing table gutters, zero-progress wrapping for wide glyphs, unbounded Map
and decision-card rows, passive chrome starving approval gates, and missing
coverage for the reported viewport and density thresholds.

An isolated post-fix run of the rebuilt binary against the same target and
deprecated operator config at exactly 104×61 rendered a coherent Scan screen
with no scattered warning bytes, overwritten cells, merged labels, or clipped
actions. The target still reports `context malformed` and no terminal Scan run;
those are honest artifact states, not rendering faults.

## Method

The audit used parallel, single-purpose lenses and a final adversarial review:

1. terminal lifecycle and unsupervised output;
2. rectangle composition and density thresholds;
3. terminal-cell width, wrapping, and table allocation;
4. semantic survival under constrained height;
5. test honesty and regression coverage.

The original state was reproduced in an isolated tmux pane matching Warp's
104×61 cell viewport and the same `upgrade-inc` target. The reproduction
contained the same interleaving, including config-warning fragments inserted
inside the status and Scan rows. Rectangle tests separately proved that the
Scan layout tiles without overlap, isolating the failure to physical terminal
mutation rather than Ratatui geometry.

## Findings and disposition

### P0 — writes behind Ratatui corrupt the physical terminal

**Baseline evidence:**

- `crates/kuzushi-core/src/config/load_config_for_target.rs:153` collected a
  deprecation warning during reusable config loading.
- `crates/kuzushi-core/src/config/load_config_for_target.rs:173` emitted it
  with `eprintln!`, regardless of whether a caller owned the terminal.

**Failure scenario:** the shell enters the alternate screen, a target/config
refresh loads a legacy phase alias, stderr writes a line directly to the TTY,
the physical terminal scrolls, and Ratatui's next differential draw cannot
repair cells it believes are unchanged.

**Resolution:** config loaders now return `LoadedConfig { config,
diagnostics }`. CLI modes print those diagnostics to stderr before/after their
owned work while preserving machine-readable stdout. Interactive mode records
them in its in-memory Activity log, never the durable transcript. Plain mode
prints them on stderr before rendering. Internal CLI exit paths drain pending
diagnostics first.

Additional reusable-core `eprintln!` paths were converted to bounded runtime
diagnostics. `kuzushi-codeindex` backend failures are now data returned to the
caller, and its piped MCP stderr is continuously drained into a fixed-size
discard buffer so a noisy backend cannot deadlock on a full OS pipe. Report
reveal and campaign kill children no longer inherit the alternate screen's
output handles. OAuth is the one child that needs inherited interactive IO; a
terminal-suspension guard now leaves the alternate screen and disables raw mode
before launch, then re-enters and resets the alternate screen before Ratatui's
full-buffer redraw.

Status: **fixed and live-reproduced**.

### P1 — terminal width was sometimes measured as Unicode scalar count

**Baseline evidence:**

- `crates/kuzushi-tui/src/renderer/chrome/status/context_strip.rs:43-50`
  used `.chars().count()` to decide whether the status strip fit.
- `crates/kuzushi-tui/src/renderer/shared/text/mod.rs:240-252` could make no
  progress when one glyph occupied more cells than the requested wrap width.

**Failure scenario:** CJK, emoji, or other double-cell content passes a
character-count check but overruns the terminal row. At a one-cell wrap budget,
a wide glyph can also keep the remainder unchanged indefinitely.

**Resolution:** status, wrapping, and plain finalization use terminal display
width. An over-wide single glyph is consumed into a one-cell fallback instead
of looping. Tests cover double-width status text, wide-word wrapping, every
context-strip width below 100, and plain-output cell budgets.

Status: **fixed**.

### P1 — table helpers spent width on invisible trailing gutters

**Baseline evidence:** the shared table path appended two spaces after every
column, including the final column (`renderer/shared/tables`, baseline
`68-105`). Several callers then calculated widths independently.

**Failure scenario:** a row that mathematically fits still exceeds its pane by
two cells, or narrow columns underflow while Ratatui silently clips the proof.

**Resolution:** separators now exist only between visible columns. A shared
allocator shrinks preferred widths toward explicit minima, drops zero-width
columns cleanly, and accounts for external gutters. Campaign, catalog,
recommendations, tuning, jobs, runs, config, tools, general options, and SAST
tables use the common allocator. Tests exercise 40/60/80/104-column budgets and
sub-separator widths.

Status: **fixed**.

### P1 — decision cards could hide identity, warnings, or actions

**Baseline evidence:**

- confirmation rows were unbounded and their measured height could diverge
  from their rendered height
  (`renderer/chrome/cards/confirm_card_height.rs:69-80,107-158`);
- prerequisite headers, steps, and actions had the same mismatch
  (`render_prereq_prompt_card.rs:27-119`);
- the threat throttle source was unbounded
  (`render_threat_patch_card.rs:59-80`).

**Failure scenario:** on a short terminal the dangerous choice remains visible
while the target/tool identity disappears, or passive status chrome consumes
the only rows available for approval/refusal actions.

**Resolution:** cards derive height from the same bounded row projections they
render. Identity and final actions are pinned; omitted prerequisites and
unsupported threat notes are disclosed; success, warning, and destructive
styles remain distinct. Wide cards keep the full operator-facing choice copy,
while narrow cards preserve every action key. Interactive gates are allocated
before passive throttle chrome. A late adversarial review found one 8–19-cell
multi-prerequisite overflow; the compact branch now pins `+N` within the row,
and a two-step test checks every width from 1 through 40.

Status: **fixed**.

### P1 — Map rows composed independently bounded fragments

**Baseline evidence:**

- the scope was fitted to the full row before revision text was appended
  (`renderer/views/workbench/phase_pages/map.rs:127-134`);
- hot-module rows reserved a fixed 25-cell suffix even though counts varied
  (`map.rs:275-301`).

**Failure scenario:** long target scope plus revision overruns the context row,
or large module/finding counts collide with module identity and push the next
scan plan below the fold.

**Resolution:** scope and revision share one budget and both survive at compact
widths. Hot-module suffix width is measured from actual count text. Normal Map
metadata remains compact to preserve the established information hierarchy;
the stacked branch fits identity on one line and wraps only secondary metadata.

Status: **fixed**.

### P2 — phase composition tests skipped the reported viewport

**Baseline evidence:** the six phase profiles did not include 104×61, and
density coverage did not straddle the 78- and 120-column thresholds
(`renderer/phase_composition_contract.rs:4-6`).

**Failure scenario:** canonical snapshots pass at round-number sizes while the
actual Warp pane crosses a layout branch or clips a decision surface.

**Resolution:** tests now render the exact reported 104×61 Scan composition,
assert that its rectangles tile without overlap, and exercise widths
77/78/119/120. Decision-gate tests use a 40×12 allocation. Width tests assert
semantic tokens as well as cell bounds so Ratatui clipping cannot manufacture
a pass.

Status: **fixed**.

### PASS — Scan rectangles do not overlap

The exact 104×61 layout rectangles tile their parent surface and remain inside
their bounds. The screenshot's collision-like appearance came from terminal
scroll/diff desynchronization, not two widgets painting the same rectangle.

## Verification

The final verification set includes:

- `cargo check -p kuzushi-cli`;
- `cargo test -p kuzushi-codeindex`;
- CLI process tests proving scan/run JSON remains on stdout while diagnostics
  remain on stderr, plus plain-shell diagnostic visibility;
- reusable-core and interactive-runtime no-direct-terminal-output ratchets,
  including whitespace-tolerant macro matching and inherited-child-stdio
  detection;
- bounded runtime-diagnostic queue tests and transcript secrecy regression;
- exact 104×61 Scan composition and rectangle tiling tests;
- full renderer test sweep, including canonical phase snapshots;
- `node scripts/crap-risk-gate.mjs`;
- `git diff --check`;
- rebuilt-binary capture in an isolated 104×61 tmux pane against the same
  target and legacy config.

## Residual risks and deliberate non-fixes

- The runtime-diagnostic queue is process-global. It is count- and byte-bounded
  and safe for the single interactive shell, but concurrent embedded shell
  owners could consume one another's diagnostics. Owner-scoped queues would be
  a separate runtime architecture change, not a visual hotfix.
- Display-width handling is cell-aware but not a complete grapheme-shaping
  engine. Complex zero-width-joiner emoji sequences remain a possible polish
  edge case; they no longer recreate the diagnosed terminal-scroll corruption.
- Exact alternate-screen behavior is covered by a manual isolated tmux replay
  plus off-screen contract tests. A hermetic automated PTY integration harness
  would improve CI evidence further.
- The terminal-output ratchet is deliberately lightweight source scanning, not
  a Rust semantic analysis pass. It covers reusable core, the interactive app,
  codeindex, whitespace-obfuscated print/debug macros, common direct-stderr
  shapes, and inherited child stdio; future TUI production roots or bound
  writer aliases still require explicit audit coverage.
- `context malformed` and the absence of a terminal Scan run were not hidden or
  rewritten. They are truthful target data and require repairing/rebuilding the
  target context or running a scan, not a renderer change.

## Outcome

The corruption class is closed at its source, the reported viewport is covered,
and the surrounding width/priority defects found during the deep audit are
fixed rather than papered over with a forced full redraw. The live Warp task
must be restarted to load the rebuilt binary; the audit intentionally did not
interrupt the operator's existing process.
