# Neutral comparison across recorded source changes

October 11, 2026. The TUI distinguished covered absence from unassessed work,
while CLI plain output still printed "Resolved" for a legacy deterministic
absence class. A recorded decision was also shown as "carry forward" without
checking the source that supplied that verdict.

## Change

Core adds a pure observation-presence projection independent of legacy classes.
It distinguishes newly observed, seen again, not observed in covered work,
not reassessed and unknown. Neither observations nor coverage determine a
finding verdict. Existing comparison classes remain compatible.

CLI plain output now leads with neutral counts and the absence caveat, then
shows finding titles, source paths, identities and missing coverage evidence.
JSON adds versioned neutral counts and per-finding presence with an unassessed
fix status. Legacy counts and fields retain their values with explicit
compatibility notes. The existing carry-forward counter is labeled as having
no source-approval meaning.

CLI and TUI decision summaries now describe recorded decisions and differing
snapshot verdicts. They direct the operator to source review before reuse.
The TUI no longer computes its unused private carry-forward counter, and empty
decision summaries no longer displace real comparison evidence. No finding,
human decision or observation is rewritten.

## Native source experiment

J196 clones the owned inert public-documentation fixture and reuses existing
commits `f29dc288e0660ad20d074fc219c025f98ef7d155` and
`30baa1f1a56bae4cbb431ba0d453a59a8108a71b`. It makes no new commits and does not
modify the original live fixture. Credentials are absent. Target source is
never built, imported or executed.

Three fixed native scans at the first SHA retain three observations of one
public example. A scripted human false-positive decision is recorded against
the third run. One scan at the later SHA sees the same identity again. A dirty
temporary omission of that public example produces covered absence; restoring
the example and scanning only an owned note directory produces unassessed
scope. Those are two different content snapshots at the same later SHA.
All six source-bound run receipts are real scanner output; no completed run,
coverage receipt or finding observation is injected.

Review retains the original verdict and source SHA, names the later observation
and requires reassessment. Comparison separates seen again, covered absence
and uncovered paths. JSON export retains the original decision basis, later
recorded SHA and source summaries. It establishes no fix and no human verdict
for the current dirty checkout.

The initial CLI test invocation targeted a binary with no matching tests. Its
zero-test receipt is retained but provides no validation. The corrected library
regression failed on the missing neutral contract before the implementation.
Two later CLI assertions expected legacy reasons; structured legacy reasons
remain, while plain output now names the shared coverage blocker. One renderer
assertion expected the old conflict label and now checks the precise snapshot
label. Focused diagnostics remain under
`/tmp/kuzushi-source-transition-20261011`.

The first native captures exposed that End belonged to the composer and did
not page the document. The journey now uses its advertised Page Down controls
and explicitly checks the compact scope reason. Subsequent capture review
identified the misleading carry-forward label and prompted the summary repair.
Earlier captures remain under `native` and `final-native`. No journey, fixture
or protected runner was edited while its process was active.

## Evidence and limits

Final J196 is
`/tmp/kuzushi-source-transition-20261011/qualified-native/20261011-045131/J196`.
It records 29 machine passes, zero failures and 22 authenticated text/ANSI
captures across six sizes plus no-color restart. Native SHA-256 is
`f47705df57c3a0dc70324d8b15a6e751b4e28ccb61cb40cc3e0d711f9732eb18`.
Raw status remains `REVIEW_REQUIRED` and operator approval remains false.
Assistant screen judgments are recorded separately beside the captures.

The smallest opening retains counts, the caveat and source-tab access; Page
Down reaches the actual uncovered-path reason. Wider layouts show the reason
beside the finding, and Sources retains full SHAs and content hashes. Tall
layouts still have substantial empty space. Recorded-decision summaries no
longer grant reuse permission. Restart retains the original human decision,
four observations and zero provider requests, allowance revisions or work
attempts. The original live fixture retains its four reservations, six attempts,
three observations and one human decision.

48 distinct focused checks, workspace build and the 220-file changed-code
risk proxy pass. Checks cover neutral presence, legacy compatibility, failed
and incomplete coverage, missing artifacts, source reading, rendered decision
notes and input ownership. New product labels pass register lint.

All ten repository summary gates pass. The local receipt is
`/tmp/kuzushi-source-transition-20261011/precommit-verify-receipt.json`.
It records a dirty tree and drift during verification and remains unsigned.
Final documentation receives a focused contract check. Tested work is staged
on main, with no commit or push.

These are native policy signals on an owned public documentation example.
Live model finding quality, current-revision human adjudication, the complete
guided investigation and reference-product UX acceptance remain open. No module
is promoted or retired, no new live allowance is approved and no broad delivery
milestone closes.
