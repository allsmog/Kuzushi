# Exact relationship selection and readable receipts, October 25, 2026

Relationship review now preserves the selected record when a saved decision or
explicit refresh changes latest-activity order. Native review also exposed two
keyboard defects: arrows did not select relationships, and compact PageDown
skipped part of the receipt. Both are repaired. Source provenance still has
separate gaps described below; this does not close the broad investigation goal.

## Operator behavior

The reader keeps one recorded relationship, identified by its stable ID. A
newer cached revision takes precedence; a stale or empty page retains the known
saved receipt with an explicit disclosure. Loading and error states block
selection-dependent actions. An off-page selection appears before controls.
Explicit navigation selects a visible row, and a page change clears the anchor.
A background save updates the matching anchor without changing the active view.

The writer now retains the typed shared-dispatch receipt. It compares the entire
returned selection with the reviewed records using the existing domain review
operation. Missing or mismatched output restores the exact form and reason.
It never acknowledges an unrelated pair or silently advances a captured revision.
Batch freshness checks and independent finding verdicts remain unchanged.

Unmodified Up and Down use the existing j/k path in Navigate mode. Prompt and
form ownership remain separate. Compact controls show paging, refresh and batch
review. Counts explicitly refer to the current page.

The existing relationship page-size projection now includes the browser's actual
rendered height. Group and batch readers retain their own heading-aware sizes.
PageDown and PageUp no longer fall back to a fixed step larger than the compact
body. A reducer regression and native receipt check cover complete endpoint IDs
and recorded run names at 40x12.

## Source and relationship experiment

J366 clones the existing owned two-commit bundle. It creates no commits. The
source revisions are `7cac9e253984e19ccc6aaeee3eb157de049ba667` and
`c557cdbf94b931ecc250b33d33d793f79036a908`. Sixty-one loose fixture files contain
the documented public example string, with no active credential. Both checkouts
are dirty because of those files. Source hashes include the loose files.

Two fixed, direct shared-dispatch source scans use the local secret scanner.
The first inspects 61 explicit paths. The second deliberately omits
`book/001.env`, inspecting 60 paths after the checkout changes. This tests
absence under different coverage; it does not test nondeterministic discovery
or establish complete repository coverage. No target code is executed.

An explicitly invoked test hook creates 60 labeled grouping proposals through
the real store, then one proposal for later observations. These are scripted
fixture proposals, not model inference. Actual operator decisions use the
shared prepared-dispatch boundary. No finding verdict is recorded.

Accepting the oldest baseline pair reduces the grouped queue from 61 to 60.
The later observations make that exact old edge inactive, restoring 61 groups.
The omitted path remains a candidate rather than becoming fixed. The operator
opens a recorded generation, returns to the held pair, and removes only its old
link. Separately accepting the fresh pair yields 60 groups; unlinking it restores
61. Both removed links retain exact endpoint IDs, run IDs and revision 3.
No observation, identity or verdict is merged or erased.

## Verification and retained failures

There are 27 reported Rust passes: 25 behavior checks and two existing conditional
fixture hooks that do no work when their environment is unset. One new ignored
fixture writer is invoked explicitly by J366. Nine new behavior checks cover
reordering, off-page selection, stale caches, deliberate navigation, malformed
receipts, compact identity, arrows and contiguous paging. Three initial red
regressions reproduce the selection defect. TUI all-target Clippy, workspace
build and the changed-code risk proxy pass. Summary gates are recorded separately.

Final J366 has 35 machine passes, zero failures, 35 live text/ANSI pairs and four
pending formal operator judgments. Its native SHA-256 is
`67715140e2d101a7597258296435007c98ce11ccb1eccd25968f9043b8bd285d`.
All 6,614 repository inputs and 14 frozen programs stay unchanged during the run.
Nineteen ANSI cell replays were inspected across all six sizes, receipt paging,
recorded-generation provenance, pair decisions and no-color restart. These are
cell replays with a chosen font and background, not OS screenshots.

The raw result remains REVIEW_REQUIRED. Four separate agent answers cover State,
Intent, Honesty and Craft. They qualify this selection and receipt workflow;
they do not replace operator judgments or establish reference-product parity.

Earlier attempts remain retained: setup assumptions about list IDs and source
files, an unsupported fixture directive, unhandled arrows, the wrong finding
on restart, and a blank immediate resize capture. A later 35-pass run also
retains an agent FAIL because visual review found skipped receipt rows. Final
capture waits are bounded and prove stable rendered content, not absence of a
brief resize flash. The corrected native receipt check is explicit.

## Report and source provenance still incomplete

A real shared-dispatch JSON export retains all 61 findings and all 61 distinct
relationship records: 59 proposals and two removed links. Endpoint tuples remain
exact. Every finding remains an unreviewed candidate. The ledger retains 121
observations, 61 current identities, zero rekeys and zero finding decisions.
The source files and previously prepared lesson draft remain unchanged.

The canonical run receipts identify the correct baseline and later Git SHAs.
Direct inspection nevertheless finds unknown Git SHA on the snapshots referenced
by all 121 observations in this ad hoc scan case. The export retains run
references but embeds neither source SHA; its omitted-fields list is empty.
This does not qualify immutable observation snapshot binding or self-contained
report provenance. Those are concrete follow-up investigations, not passing
source-authentication checks. Existing fixed-study bindings are not qualified
or contradicted by this ad hoc case.

No provider request, source execution, new allowance, module promotion or broad
milestone closure is added. The cumulative real-model experiment count stays 16.
Publication remains a separate action from this draft.

Evidence: `scripts/devex/artifacts/relationship-selection-20261025/`.
Final native run: `native-attempt-8/native/J366/20261025-070451/J366`.
See `repair/relationships-paging.log`, `native-attempt-8/independent-check.json`,
`source-provenance-gaps.json`, `agent-assessment.json` and `visual/ansi-replays/`.
