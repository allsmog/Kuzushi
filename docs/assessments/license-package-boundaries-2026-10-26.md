# Local package license boundaries, October 26, 2026

The native license scanner now compares a source header with declarations in its
nearest package directory. It previously used the first declaration in the
entire target. On an owned two-package fixture, that produced a false positive
for a matching service header and missed a different service header that
actually disagreed with its local declaration. The retained native before/after
checks demonstrate both corrections.

Each bounded manifest is inspected once and its parsed facts are shared by the
declaration, repository-license and source-header checks. A private or undeclared
package stops inheritance. Sources outside packages do not borrow sibling
declarations. When several declarations occupy the same directory, a header
matching any local declaration avoids an arbitrary mismatch. Otherwise the
first local declaration supplies the diagnostic. Required-header policy still
applies when no local declaration is known.

Descriptors, aliases, rule identifiers, fingerprint format and derivation,
enabled-rule coverage, source settlement and artifact formats are unchanged. Existing
entry/file/depth and per-file read limits remain. This does not establish an
aggregate IO or latency bound, full SPDX-expression interpretation, correct
root-license inference or legal compliance. No module tier changes.

The module check also found a Review presentation problem: scanner explanations
appeared after a long block of action instructions. The reader now presents the
scanner message before those instructions. It remains explicitly a scanner
assertion, separate from structured evidence and human decisions. The change
preserves input ownership and existing paging controls.

Evidence is retained under
`scripts/devex/artifacts/license-boundary-current-20261026/`. Six of eight new
boundary regressions fail before the correction. The final engine/native
scanner selection has 61 passing checks. Three prepared-dispatch checks include
direct matching results, an actual local mismatch through SAST, changed content
and later covered absence with the human decision retained. Thirty-two reader
checks include explanation ordering at all six widths. These are 96 distinct
focused Rust passes. Workspace build and Core/TUI Clippy pass. The existing
vendored terminal parentheses warning remains visible in build logs.

The initial tmux attempt failed before launch because the wrapper rejected the
frozen executable basename. Two later attempts failed in the independent
checker: display-field names were used for raw observations, and a concurrent
ledger read lacked the existing bounded retry. Those hard failures remain
recorded. The next complete attempt has 28 machine passes and no failures, but
its separate screen review identifies the buried explanation. No failed run is
relabeled as passing.

Final `native-attempt-5` runs only J377 through the installed wrapper. It has
30 machine passes, zero failures, 27 authenticated text/ANSI capture pairs and
two no-color captures. All five review questions are answered with State,
Intent, Honesty and Craft in `agent-review.json`. The separate agent verdict is
`PASS_WITH_FINDINGS`; raw harness exit 4 remains `REVIEW_REQUIRED`. It is scoped
agent review, not broad operator acceptance or reference-product UX parity.

The native SHA-256 is
`5dfe6fa3c1e4ab95e28b58c31718049748bcc587d4edf2dc51cbbf305643122d`.
All 6,710 recorded repository inputs and executable identities remain unchanged
during the journey on dirty `main` at
`e8b4de3ffd167ead3a9f3b23b9b2c24f7952078f`. Captured ANSI cell replays use
Menlo 15 and a chosen dark background; they are not OS screenshots.

The owned local Scan, Review and Report slice retains:

- Five explicitly launched local scans: two matching results and three
  repetitions of one local mismatch, with no automatic follow-up work.
- Three raw observations, one stable finding, one scripted human deferral,
  zero provider reservations and zero investigation model-work attempts.
- The original source excerpt and decision after the later matching scan.
  Comparison shows differing content hashes, unknown Git revisions and an
  explicit statement that absence does not establish a fix.
- A JSON report retaining the deferral and absence limitation, then the same
  history after no-color restart. Report discloses incomplete repository
  coverage and unavailable workspace spending.
- Exact owned source hashes except the two deliberate fixture header edits.
  No package scripts or target source execute. No model request is added; the
  cumulative live experiment count remains 17 with no remaining allowance.

The compact comparison is readable by page five, before the review action
instructions. Long observation references, repeated source guidance, clipped
secondary hints and weak recurrence visibility remain friction. Unknown
revision fixtures do not qualify cross-SHA fix adjudication. Context acceptance,
larger monorepos, aggregate resource limits, every ecosystem and the broader
investigation acceptance remain open. Local checks are draft evidence, not a
clean signed publication receipt.
