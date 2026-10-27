# Rejected scope output and local correction

A rejected scope proposal can now retain bounded local output for inspection
and manual correction. The original job stays failed and its request stays
spent. Saving a correction creates a separate unaccepted revision. Boundary
acceptance and scan approval remain separate actions.

This addresses a limitation exposed by the eighteenth approved live experiment.
That 602-file proposal referenced an undeclared dependency. Its response was
not retained. This change cannot recover that old response or establish useful
large-monorepo grouping. No new live request is authorized or made.

## Shared contracts

`pack:suggest-scopes` adds optional `saveRejectedOutput`, with the compatibility
alias `save_rejected_output`. Omission retains the old behavior and introduces
no descriptor default into existing frozen inputs. Newly prepared scope context
studies explicitly choose retention by default, respect an explicit false value,
and disclose the choice before preparing the plan.

Rejected candidate text is limited to 16 KiB at a UTF-8 boundary. Its separate
`rejected-scope-output.json` records original byte count, completeness and the
validation cause. Truncated or partial output is read-only. Ordinary errors
retain the bounded validation cause and storage outcome without printing the
candidate. Explicit inspection warns that the local text may contain source or
sensitive material. This is local diagnostic retention, not encryption or an
additional operating-system access-control guarantee.

`pack:scopes operation=recover` consumes the corrected `draft` and an exact
`recoveryRef`: schema version, campaign id, plan SHA-256, failed run id and the
artifact's typed content hash. Shared prepared dispatch authenticates the failed
job, frozen input and retained object, requires complete output, and checks the
original scope head and current source before publication. Existing exclusions
and shared-discovery choice must remain unchanged. Coverage and dependencies are
validated against the saved inventory. No model, retry or new campaign job is
created.

The resulting immutable revision has optional `correction` metadata linking the
failed output, original model/context and corrected-draft SHA-256. Its generation
and acceptance fields are empty. Old revisions remain compatible because the
new field is omitted when absent. Historical job lookup can find this manual
revision without converting the failed producer into a successful generation.

## Terminal behavior

The failed scope form offers explicit output inspection. `e` opens a local JSON
editor; Enter inserts a newline, Ctrl+S validates and saves, Ctrl+R resets, and
Esc keeps the draft in memory. PageUp/PageDown move through display rows, including
compact single-line JSON. Pasted text is bounded without truncating the existing
draft. Workflow letters remain text while the editor owns input. An unfinished
correction blocks the new-proposal shortcut and explains how to return.

Invalid JSON or membership keeps the text and original scope unchanged. A valid
save offers review of the manually corrected tree. An unrelated tool completion
cannot consume the pending correction; a matching background completion does
not take focus. Restart recovers a saved correction through the failed campaign.
Unsaved correction text is currently retained only within the running shell.

Later study planning recovers the original failed run's authenticated allowance.
Correction, acceptance and later boundary edits retain the same investigation,
spent calls and protected Review balance. Missing, foreign or damaged accounting
blocks planning instead of selecting a new investigation. A focused failing
regression exposed this missing consumer before the shared reader was connected.

## Qualification

Focused tests cover retained and omitted output, bounded partial text, source
drift, changed artifacts and scope heads, explicit false aliases, editor
ownership, invalid saves, unrelated results, background focus and restart.
The native J382 fixture uses one labeled intercepted response and no network
fallback, live inference or target-source execution. It does not measure model
quality. Failed attempts and final terminal judgments are recorded separately
under `scripts/devex/artifacts/scope-recovery-current-20261026/`.

There are 248 distinct passing focused Rust checks. The workspace build,
Core/TUI/CLI all-target Clippy and changed-code risk gate pass. Exactly two
descriptor digests change; the matrix consistency checks pass without adding a
tool or changing maturity. Repository summary verification has its own retained
receipt, separate from the existing signed publication receipt.

The first native attempt exposed a combined-key navigation problem in the
journey. The second exposed a product defect: the diagnostic storage notice hid
the validation cause in ordinary error formatting. The third could not open the
tmux socket inside the sandbox. These failed attempts remain recorded. The cause
and display-row paging are corrected. The fourth run completes the flow; the
fifth strengthens the fixture guard to check all five source files. The expanded
sixth run correctly refuses boundary acceptance with two uncovered root files.
The seventh explicitly includes those files, then exposes two harness mistakes:
looking for the investigation id in the passes pane and assuming unconditional
exit with a recoverable draft. These failed checks remain recorded. The eighth
reads the Total calls detail pane and completes the expanded flow.

Final J382 has 41 machine passes, zero failures, 32 authenticated capture pairs
and seven answered agent reviews with `PASS_WITH_FINDINGS`. Raw harness exit 4
remains `REVIEW_REQUIRED`, separate from those agent judgments. Twelve ANSI cell
replays are inspected, including six editor sizes, no-color restart and inherited
study accounting. They use
Menlo 15 and a chosen background, not OS screenshots or operator signoff. All
6,740 captured inputs remain unchanged during execution. Later edits finalize
five named documents. No Rust code or fixture changes after that run.

The frozen native SHA-256 is
`75e3a938db727dfa6b40c0c68953f717cd08d1b10aa65073bc0a75507b543dff`.
Independent checks retain exactly one failed fixed job, one work attempt and one
settled intercepted request. The corrected revision is separate and unaccepted.
A later explicit operator action accepts the boundaries into revision 3, then
opens scan planning with the same one-call investigation already spent. No new
scan, campaign job, allowance approval, observation or human finding decision is
created. All five source files remain unchanged and are never executed. The
manual correction explicitly includes the initially uncovered `app.py` and
`config.env` harness files. Inventory limitations still prevent a complete
repository coverage claim.

Remaining visual findings are dense and repeated accounting, long artifact
paths, generic command hints in the local error, and cramped JSON reading at
40 columns. Unsaved corrections are not durable across process restart. These
limits do not turn the recorded failure into a successful model proposal.

General model usefulness, other scanners, full investigation acceptance and
reference-product UX remain open. Live experiment consumption remains eighteen
requests with no allowance left.
