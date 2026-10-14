# Context history browser, October 9, 2026

The shell now provides keyboard selection of immutable context revisions,
exact inspection, baseline comparison and explicit activation/restore. This
closes the typed-id interaction gap observed in J140. It extends the existing
Threat Models route and shared dispatch; no investigation scheduler, tool
option, model allowance or persisted context format is added.

Browsing consumes the cached immutable manifest. Inspection uses an exact
`threatModelRef`; comparison sends the two selected revision ids to
`threat-model:diff`. Activation and restore use their existing prepared tools.
The three result types add a canonical target field for consumer ownership.
Exact read/diff receipts must match target, model, revision and content digest.
Missing objects remain retained errors with explicit retry. The active pointer
and discovery context cannot be changed by selecting or inspecting a row.

`6 MODELS` and `threats models` open the same browser. Its controls name local
inspection, baseline selection, comparison and writes. Summary and complete
document views retain separate scroll positions. Wide layouts use list/detail;
narrow layouts stack them and expand inspection/comparison into the full body.
Reader titles and line counters fit 40x12. Escape restores the original threat
projection and scroll. Paste returns to that composer without submission.
Background completion preserves navigation and the draft. Captured labels
survive manifest refresh, and write receipts name their original subject after
cursor movement. The legacy m/M shortcut is explicitly labeled activation.

## Verification

Evidence root: `/tmp/kuzushi-context-history-20261009`.

Sixteen direct history checks pass, including real shared-dispatch inspection,
comparison, activation and restore; target/digest rejection; missing-result
errors; late completion; reader positions; draft/paste ownership; the visible
history shortcut; source-independent selection; plain document retention; and
named receipts after cursor movement. Eight existing workspace-history checks
pass in the same test selection. Eight core diff checks, four keymap collision
checks and twelve paste regression checks also pass. The locked workspace build
and CRAP-risk gate pass. All ten quick gates pass in
`/tmp/kuzushi-context-history-20261009/verify-complete.json`.

Final J141:
`/tmp/kuzushi-context-history-20261009/final-tui/20261009-063428/J141`.
It records 24 machine passes, no failures, seven operator-review questions and
27 authenticated live captures. All captures use native SHA-256
`32d355de15b40a6a9556b401101df53be927f20159b788d7a2706ad1afb21a6c`.
Actual/requested sizes match at 160x48, 120x36, 96x89, 80x24, 60x20 and 40x12.
Three no-color restart captures contain no color SGR. The capture verification
record retains the exact executable, dimensions and live alternate-screen facts.

The fixture seeds three explicitly labeled contexts through real local tools.
TUI comparison/read checks exclude seed run ids, so setup output cannot satisfy
native execution assertions. Original objects and comment-only source remain
unchanged. A missing copy object is retained outside the store, restored and
read again through the same exact reference. Explicit activation selects Alpha;
restore appends a new active Alpha revision while preserving the original
selected revision and baseline. Restart shows all four revisions. No finding
observations, campaign plan, work attempt or provider reservation is created.
No model, scanner or target-source execution runs.

Sequential J140 compatibility regression:
`/tmp/kuzushi-context-history-20261009/compatibility-tui/20261009-063607/J140`.
It records twelve machine passes, no failures, five operator questions and
fourteen live captures against the same final native binary. Typed commands,
text comparison, activation, restore, adoption, exact inactive reads and restart
remain available. The new history browser does not own a Map result.

## Retained failures and limitations

An initial rapid Escape/Home sequence left the reviewed copy selected; its
activation receipt correctly identified that actual selected object. The native
journey now waits for the list, verifies the intended selected Alpha row and
then activates it. An early generic `source` wait captured old catalog metadata;
final inspection requires the unique completed summary, complete document and
post-seed receipt. A real 40-column rendering check caught a clipped Back hint.
Controls were shortened and the check now requires the complete hint. Tests
also exposed a dropped temporary fixture and target alias/canonical-path
differences; fixtures retain their lifetime and request receipts bind the
canonical path captured once at browser entry.

Sandboxed summary verification failed during pnpm bootstrap before its first
gate. The focused private-context rerun passed using the working runtime. Three
formatting failures were then corrected. The verifier conservatively sets
`driftedDuringRun: true` for every dirty worktree, including unchanged dirty
worktrees (`scripts/verify-repository.mjs` lines 156-168). This receipt therefore
proves the ten commands passed while retaining the uncommitted-state limit; it
does not authenticate one clean Git tree. The native capture hash is verified
independently. No commit was created to bypass this honest qualification.

Raw REVIEW_REQUIRED and operator approval false remain explicit. Agent screen
judgment is scoped to these owned fixtures. Full TUI reference parity, large
history-store latency/cancellation, richer structural/DFD comparison, complete
semantic equivalence and live-model investigation acceptance remain open.
Browser baseline, selection and reader positions are session state. Restart
preserves immutable history and the active pointer; it does not restore those
transient browser choices. Source applicability shown by an exact read describes
that inspection and does not establish that a finding was fixed at a newer SHA.
The per-tool matrix remains 44 qualified entries and 65 unassigned entries;
all broad delivery milestones remain open. Work is uncommitted on main.
