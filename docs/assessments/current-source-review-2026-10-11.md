# Explicit human review against captured current source

October 11, 2026. Observed-source receipts preserved history, but an operator
could not attach a separately reviewed current checkout to a decision.

## Change

`findings:review-source` adds descriptor-backed capture, read and decide
operations through shared prepared dispatch. Each needs explicit operator
authorization. There is no model requirement, source execution, discovery pass
or automatic follow-up. Capture and read do not advance Review.

Capture binds target, exact finding generation, ledger cutoff, snapshot,
content identity and available Git state in an immutable bounded CAS object.
The existing identity walk is cancellable and excludes ignored and symlink
material. It caps each walk at one million files and 16 GiB; this separate
identity operation does not change repository inventory's smaller inspection
limits. It stores identity metadata rather than a complete code copy.

Decide requires an explicit human verdict and reason. Current source content and
Git metadata must still match the capture. The shared writer rejects intervening
finding/decision changes and future ledger cutoffs before appending. It records
the selected capture with the decision in one event. No observation is fabricated,
prior verdict rewritten or fix inferred. Read authenticates historical metadata
without claiming current applicability. `matched_before_save` names the
pre-save comparison rather than a lasting current-checkout verdict.

The exact source is read from the decision's projected event and survives replay.
Existing `DecisionWrite` literals remain compatible; exhaustive consumers of
`DecisionCommand` must handle its new source-qualified variant. Projected row ids
can change during replay, while the event hash remains stable. JSON/JSONL,
SARIF and Markdown retain the explicit source separately from observation-derived
`reviewDecisionBasis`. Generic SARIF also names unassessed current applicability.

## Operator flow

The selected finding header exposes `Y` to draft the canonical capture command.
It preserves an existing draft and cursor, starts no work, and submits through
the shared authorization gate. The action can be remapped or unbound. Narrow
headers retain `Y · source review`. The actual completed reference can be read
in Logs and in the saved result. Decisions use the tool's declared options.

Review distinguishes the explicitly reviewed source from the prior observation.
It displays capture time, commit and dirty state; full content and snapshot
identities remain in provenance. Its warning leaves current-checkout assessment
and fix status unclaimed. A dedicated verdict editor and captured current-code
reader remain open, so this is not full reference-product UX acceptance.

## Verification

J198 uses the owned inert public-documentation fixture, its two existing source
commits and six fixed native source scans. The original false-positive decision
retains the first SHA. A real TUI capture binds the later dirty checkout. A
temporary owned note changes content at that same SHA, and a real headless save
refuses it. After restoring the captured content, an explicit human deferral is
saved through shared dispatch. Review and no-color restart show the selected
dirty source separately from the prior clean observation. Source files are never
built, imported or executed; no new source commit or provider request is made.

Earlier native failures are retained under `native` and `visible-native`. They
exposed a hidden shortcut label and an incorrect checkpoint expecting the
capture receipt in the resting Review page. The persistent header now exposes
the action, and the receipt check uses its actual Logs surface. `activity-native`
also retains a completed run whose result-reading checkpoint was too weak;
its capture metadata was real, but that screen was still Review. The final
journey explicitly checks the reference in Logs and pages to the dirty commit.
No journey or helper is edited while its journey is live.

Focused verification includes nine real registry/source tests, existing source
hydration and export regressions, input preservation, keymap remapping and
collision checks. The replay test originally assumed stable projected row ids;
it now verifies the original event hash and rebuilt source record. A zero-test
export invocation is retained but provides no evidence; the corrected export
suite exercises 83 tests. Native export checks compare the exact capture in
JSON, JSONL, SARIF and Markdown. Source review creates no observation or billable
reservation, and failures append no human decision.

The tool is a bounded manual review capability. Its usefulness evidence covers
source association and durable reading on owned fixtures. It does not establish
general finding quality, current-code inspection quality, monorepo throughput,
complete guided investigation or operator acceptance. No existing module is
promoted or retired and no broad delivery milestone closes.

## Final evidence

Final J198 is
`/tmp/kuzushi-current-source-review-20261011/final-native/20261011-072753/J198`.
It records 18 machine passes, zero failures and 18 authenticated text/ANSI
captures across six sizes plus no-color restart. Native SHA-256 is
`7bb59dd460f983b88f7436760f1aacf3c555ae14dbad7d53cfcba15ce52eb4ac`.
Capture dimensions and native hash agree; no-color has no color SGR. Runner
target-at-start metadata is unavailable, so separate fixture source receipts
verify the actual owned source. Assistant screen judgments are separate;
native status remains `REVIEW_REQUIRED` and operator approval remains false.

The reference is readable in Logs. At 40x12, successive page steps reach the
reviewed commit and dirty state. Restart and all four exports retain four raw
observations, the original decision and the explicit source-qualified decision.
No provider reservation, work attempt or allowance revision is created. The
original live fixture still has four reservations, six attempts, three
observations and one decision.

121 distinct focused checks, the final locked workspace build, the 252-file
changed-code risk proxy and all ten repository summary gates pass. The receipt
is `/tmp/kuzushi-current-source-review-20261011/precommit-verify-receipt.json`.
It records a dirty tree and drift, so it remains unsigned. Final documentation
receives a focused contract check. Tested work is staged on main with no commit
or push. The native catalog now has 112 tools, with scoped evidence for 73 and
39 still unassigned, including eight excluded actions.
