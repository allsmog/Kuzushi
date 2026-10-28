# Scope boundary reading

The saved 602-file proposal exposed a reading problem in scope review. At
120 columns, a model label, the full saved context revision and input metadata
preceded the boundary rationale. At 40 columns, the tree and controls left two
rows for the entire detail document. The earlier J385 screen review recorded
both density problems. This is a presentation correction to the existing
scope workflow.

Scope review now starts with the selected name, included paths, rationale and
default workload. The future Scan context follows that decision summary;
proposal-generation metadata remains distinct. Full model, context, source and
inventory references remain in the document and exhaustive plain output.
No reference is shortened or replaced with a guessed association.

The visible `Tab read` action opens a full-width document. At 40 by 12 cells,
it supplies six content rows rather than two. Arrows, `j/k`, Page Up/Down and
Home/End read the document. Tab or Esc returns to the same tree or file.
Tree and reader scroll offsets are separate, and resize preserves the selected
boundary and stored offsets. A changed boundary or newly read file page starts
its detail at the top. A refresh of the same saved revision retains reader
state; a different proposal returns to the tree.

While reading, Enter, acceptance, planning and inventory shortcuts produce no
actions. The normal quit and cancellation contract still applies. The reader
does not accept boundaries, prepare work, change context, create jobs or revise
an allowance. Forms retain their own Tab behavior. These controls are shell
presentation; the module descriptors and persisted scope formats do not change.

## Verification record

The first two targeted tests reproduce the missing reader and late rationale.
The first implementation then exposed three incorrect test assumptions about
an unscrollable default viewport and the last wrapped row. Those failures are
retained. The first full scope test run has 71 passes and two stale paging-hint
assertions; the visible replacement is explicitly reviewed in their updates.
The first complexity check identifies two functions above the local limit.
They are split before the final quality checks.

All 84 distinct focused Rust checks pass: 74 scope application tests and ten
presentation tests. Repeated runs are counted once. TUI all-target Clippy with
warnings denied, the workspace build and the changed-code risk check pass.

The first native launch cannot access the tmux socket in the sandbox and stops
before opening the application. The next launch has 27 machine passes and zero
failures, but fails agent screen review: the reader title clips at 40 columns,
and file instructions describe inactive Enter actions without naming the tree.
Both are corrected. Final J387 has 27 machine passes, zero failures, 21 capture
pairs and four answered agent screen reviews with findings. Its raw harness
result remains `REVIEW_REQUIRED`, exit 4. Operator acceptance is not recorded.

The final frozen native SHA-256 is
`5b944d67b24650d2286ff8cf60c3410c5da82f1b940fc1f32ee2253d078d12b7`.
The wrapper and all 6,762 checked input files remain unchanged during the run.
The audit covers 120x36, 160x48, 96x89, 80x24, 60x20 and 40x12, local paging,
Enter and hidden-action input ownership, exact tree/file return, read-only
accounting and no-color restart. Eight ANSI cell replays are inspected with
Menlo 15 and a chosen background. They are not OS screenshots.

All 602 source files and the saved plan, queue, proposal revisions, context and
operator config stay unchanged. Provider transport has zero attempted requests.
The existing investigation retains two spent calls, zero remaining allowance
and unknown dollar cost. Cumulative live experiments remain nineteen.

Remaining craft findings are lengthy resource prose, repeated technical
metadata, and missing document position and pinned component labels when
scrolled. These do not prevent the named read/return path; broader reference
parity and full end-to-end acceptance remain open.

Current control evidence is retained under
`scripts/devex/artifacts/scope-detail-reading-current-20261026/control/`.
J387 reads the original paid proposal through the installed wrapper and a
frozen native binary, with provider transport denied. Its source and stored
state checks are shared with the earlier real-result audit. No new model
allowance is approved by this work.

The live proposal remains unaccepted with `workspace.json` uncovered. Its
original filename-prefix sample, inactive architecture, prior failed request
and two spent investigation calls remain authoritative. The separate filename
selection change has no live-model quality evidence. This reader adds no claim
of complete coverage, useful generated boundaries, full operator acceptance or
parity with reference terminal products.
