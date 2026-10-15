# Exact observed-source receipts for saved decisions

October 11, 2026. Manual decision saves previously promised carry-forward
without describing the observation behind the decision. A source metadata read
after a successful write also needs a distinct outcome from a failed save.

## Change

The shared workspace application boundary now returns a saved-decision receipt.
It reads the exact committed decision by id and resolves source at that decision's
read watermark. A later observation or human decision cannot change this receipt.
Legacy decisions without provenance disclose unavailable source. If the source
read fails after commit, the result remains saved with a source-read error.
The shell does not count it as a failed write or invite a duplicate submission.

CLI and TUI use the same source presentation. The save notice names its recorded
observation; plain output and logs include available snapshot, full commit and
clean/dirty state. CLI JSON retains existing fields and adds version-1
`sourceReceipt` and `currentCheckoutApplicability=not_assessed`. Existing ledger
formats and public decision-writing APIs remain compatible. Suppression save
copy also stops promising carry-forward; suppression behavior is unchanged.

Native compact reading exposed another issue: a painted frame could use actual
terminal dimensions while page controls retained an earlier viewport. Each draw
now synchronizes the measured frame size before rendering. This does not reload
source, move focus, or change draft, cursor or scroll. A focused test verifies
that 40x12 Review pages advance six visible body rows without a resize event.

## Native experiment

J197 clones the owned inert public-documentation fixture and reuses the existing
source commits `f29dc288e0660ad20d074fc219c025f98ef7d155` and
`30baa1f1a56bae4cbb431ba0d453a59a8108a71b`. Six fixed native scans produce four
observations. One scripted TUI false-positive decision records the first SHA.
Two later real CLI decisions record clean source at the second SHA while the
checkout contains dirty changes and narrower discovery has not reobserved the
finding. Their receipts explicitly leave current checkout applicability unassessed.
No target source is built, imported or executed; no model or new commit is used.

Earlier captures under `native` and `reading-native` exposed skipped compact
source rows. A temporary geometry probe confirmed the expected six-row paging
when viewport dimensions were synchronized and was removed. `final-native`
retains one failing journey checkpoint that expected commit text after paging
past its correct page. The final journey asserts the commit on that page and
the source excerpt on the following page. No journey or fixture was edited
while its process was running.

The runtime suite also exposed an outdated assertion that `/scan` opened the
legacy picker. Its regression now expects the finite scan form and still proves
that release/repeat Enter events cannot launch work. Failed diagnostics remain.

## Evidence and limits

Final J197 is
`/tmp/kuzushi-decision-receipts-20261011/qualified-native/20261011-063508/J197`.
It records 17 machine passes, zero failures and 17 authenticated text/ANSI
captures across 120x36, 160x48, 96x89, 80x24, 60x20 and 40x12 plus no-color
restart. Native SHA-256 is
`08ee4c9e6a8d8e19cf1cd71154e2cadeb282f6e6208289c098e714395f593db8`.
Capture dimensions and native hash agree; no-color captures contain no color SGR.
Runner target-at-start metadata is unavailable. Separate fixture source receipts
check the actual owned SHA and unchanged source files. Assistant screen judgments
are stored separately; native status remains `REVIEW_REQUIRED` and operator
approval remains false.

At 40x12 sequential pages expose the observation gap, human decision, source
warning, recorded run, abbreviated commit and clean state, then the source
excerpt. Wider layouts keep the decision source beside the finding. Tall layouts
still contain unused space and some chrome truncates. Restart preserves all
four observations and three human decisions, with zero provider reservations,
work attempts or allowance revisions. The original live fixture retains four
reservations, six attempts, three observations and one decision.

79 distinct focused Rust checks, workspace build and the 232-file changed-code
risk proxy pass. Tests cover exact decision identity, source cutoff, unavailable
legacy source, post-commit source-read failure, stale-write refusal, draft and
focus preservation, compact paging and terminal event ownership.

All ten repository summary gates pass. The local receipt is
`/tmp/kuzushi-decision-receipts-20261011/precommit-verify-receipt.json`.
It records a dirty tree and drift during verification, so it remains unsigned.
Final documentation receives a focused contract check. Verified work is staged
on main with no commit or push.

Recorded-source receipts do not supply a separately captured current-source
decision or establish a fix. Complete live Review quality, guided investigation,
tool qualification and reference-product UX acceptance remain open. No module
is promoted or retired and no delivery milestone closes.
