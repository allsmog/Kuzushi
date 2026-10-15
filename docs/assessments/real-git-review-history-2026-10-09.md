# Recorded Git source history, October 9, 2026

The [October 13 rerun](tui-integration-recovery-2026-10-12.md#source-history-and-compact-phase-controls-october-13)
verifies this owned history flow on the current binary, repairs compact phase
control ownership and updates the journey's reader and ledger checks. It records
42 machine passes and six open human judgments. The evidence below remains the
original implementation checkpoint.

Shared review reports now include nullable `sourceGit` in the decision basis
and its later observation. The fields retain the recorded full SHA, branch and
dirty state. They are read from bounded, target-matched run metadata, never
from the checkout at export time. Invalid, missing, foreign or unread metadata
stays null. The reader retains its 128-revision window and does not repair
historical run files. These additions do not strengthen a finding's verdict.

JSON, JSONL and SARIF carry the shared structured basis. Markdown bundles
display the recorded Git states and retain the complete basis in their
manifest. The manifest previously omitted that basis while prose described
applicability; an existing field-coverage test caught the mismatch. CSV and
external scanner row contracts remain unchanged and disclose the omitted
basis. Rust struct constructors require the additive optional field; the
migration is recorded in RELEASING.md.

The Markdown exporter now separates filesystem writing and manifest building
from README, finding, review and text formatting. Existing hostile-content,
field-coverage, filtered-selection and bundle contract tests remain in place.
The focused risk gate passes for eight presentation/projection files. The
complete risk gate also passes for all 510 changed code files, including the
native lifecycle and receipt changes.

Eighty-five distinct focused checks cover source enrichment, invalid metadata,
the reader window, decision attribution, Markdown rendering, confirmed SARIF,
omission metadata, TUI source readers, hydration, nondeterministic absence,
completed-receipt reconciliation, exact and scoped native execution,
partial/stopped work, legacy rescan behavior and recorded scan comparisons.
The workspace build passes. Three new source checks also run within the six
applicability checks and are counted once. One ignored SARIF fixture preparer
is excluded from the passing count.

Evidence root: /tmp/kuzushi-git-review-history-20261009.

J144 uses an owned temporary Git repository, one labeled imported immutable
context and four fixed native static scans. The documentation-example
credential-shaped value is not a real credential. Source is never compiled
or executed. A human confirmation is entered through the TUI on the first
observation. A later committed revision changes another file while keeping
the cited file identical. Another scan sees changed cited content at the same
SHA with a dirty worktree. A new TUI deferral binds to that observation. The
fourth scan no longer observes the documentation example; its absence must
retain the finding and decision, with no fixed or removed lifecycle state.
Provider requests are zero; this does not qualify live-model discovery.

The first native attempt refused the fixture's overly broad root ignore rule,
which hid trackable workspace policy. The fixture now uses Kuzushi's existing
workspace ignore policy and commits that policy in the owned test repository
before the baseline scan. No commit is made in the product checkout. The
second attempt retained the new deferral but timed out because its assertion
assumed the reader would jump to the top. The test now explicitly returns to
the top and pages far enough at 40x12 to inspect the later source. Failed
receipts remain retained.

The third native attempt reached the new dirty-source decision and an empty
completed scan, then found no observation-gap event. Native completion had
checked for absence before its coverage receipt existed. Native primitives now
defer reconciliation to the owning SAST module after the real scope and engine
receipt is durable. Both receipt and ledger must be completed. Regression
checks cover empty results, retained human decisions, repeated settlement,
scoped empty results and a scoped positive control. The latter also prevents
an early whole-target fallback from marking unscanned findings absent.
Public primitive signatures and the existing explicit ledger-finalization API
remain compatible; migration guidance explains the deferred behavior.

The fourth native attempt showed why direct dispatch checks were insufficient:
the CLI's outer artifact manifest was still finalizing when SAST tried to
reopen its own newly saved coverage. Reconciliation now receives the exact
coverage data the prepared executor just persisted. The ledger checks completed
receipt/run state and matching target, then applies its existing engine and
path rules. This avoids depending on an unfinished outer manifest. Historical
comparison still authenticates persisted receipts when reading them later.
An additional real CLI empty-scan check now records the gap and preserves the
human deferral through the actual outer artifact wrapper. Its receipt is
terminal-gap-check.json in the evidence root.

Final J144: /tmp/kuzushi-git-review-history-20261009/final-tui/20261009-125212/J144.
It records 38 machine passes, no failures, six operator questions and 35 live
captures across all six sizes, narrow paging and no-color restart. Every capture
authenticates native SHA-256
5ccdfa1fe7ccde535235132548deee7d0ee1af12b5a30f228c7afa8a41139aba.
ANSI and text projections agree. Thirty-two frames match the previously read
run after timestamp/hex-identity normalization; three changed/new frames were
read separately. Six scoped agent judgments pass; operator approval remains
false and raw REVIEW_REQUIRED is retained. The last Report check waits for
settled counts and scope rather than accepting its loading frame. Ledger and
source checks retain exactly four scans, three observations and two human
decisions, with no extra discovery on restart. The recovered open-command
capture can precede command completion; it is not used to certify command
completion. Restarted ledger and settled Report are the recovery evidence.

All ten final quick-verification gates pass in verify-final.json in the
evidence root, including formatting, all-target workspace checking, model
safety, architecture, documentation and risk. The dirty-worktree receipt stays
explicit; passing checks do not establish a clean committed tree.

Remaining: full live three-pass discovery, complete model accounting, large
monorepo scope enforcement, filesystem changes during source capture,
complete module qualification and reference-product TUI usability remain
unproven. Passive refresh can recover a replaced generation by returning to
the first page; continuity across many findings needs further investigation.
Recorded Git state and captured file equality do not establish complete
repository coverage or current-checkout applicability. All broad milestones
remain open. Work is uncommitted on main.
