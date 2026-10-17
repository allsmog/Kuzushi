# Offline context qualification and draft recovery

Context tests now supply finite, ledger-backed allowances through their scripted
runtime. Each query reserves a call before execution. Successful replies settle
their reported cost; failed queries keep unresolved reservations. Dedicated
checks refuse extra calls and model changes, and preserve unknown cost. The
deterministic pipeline still needs neither a model nor an allowance. Production
dispatch and spending policy are unchanged.

The inventory integration test now verifies the partial-result contract when a
tracked directory is replaced by a link outside the repository. The excluded
file is named in the omission receipt, the context and scope draft disclose
partial coverage, and accepting that draft cannot replace existing accepted
scopes. Coverage tests distinguish 10,001 distinct latest rows, which exceed the
read limit, from 10,001 historical rows for one scope, which collapse to one
latest row. Reads preserve database bytes and claim no source freshness.

The CLI autonomy fixture exercises a runtime-free Review action so a missing
model cannot mask its posture refusal. Its blocked result, terminal receipt and
exit code agree. The environment audit also names the existing test-only fleet
fixture adapter; it introduces no production environment read.

Context recovery now checks optional snapshot content and selected rows before
rendering or restoring them. Missing content and stale selections display
recovery guidance, retain local text and start no work. Cursor movement also
handles an outdated maximum index without overflow. Valid recovery retains its
existing multiline preview and cursor.

Verification records:

- Context: 249 passes, including all 34 previously allowance-blocked cases.
- Inventory and coverage integration: 7 and 8 passes respectively.
- Environment boundary and CLI autonomy: one pass each.
- Context editor and recovery: 16 passes; terminal panic boundary: one pass.
- Workspace build, risk gate and all ten quick summary checks pass.
- Native J255: 30 machine passes, zero failures, 25 capture pairs and three
  pending human UX judgments. It covers an owned process crash, no-color
  restart, six terminal sizes, exact text/cursor recovery and explicit discard.

The final native executable has SHA-256
`193bac0572a6198a907c9db81a1e44d0fb9f328b17738590f4319a9a2aa42b39`.
The recorded 4,230 source inputs, 686 runtime inputs and 13 copied binaries
remain unchanged through qualification. Local logs and captures are retained
under `/tmp/kuzushi-context-recovery-safety-20261015`; context and integration
logs are under `/tmp/kuzushi-context-fixture-accounting-20261015`.

The quick receipt is a draft: `dirty=true` and `driftedDuringRun=true`. The
receipt conservatively marks every dirty-tree run as drifted, even when the
separate source hashes agree. It cannot authorize signing or publication.

No provider request or source execution was added. Fourteen cumulative live
experiment requests remain spent, with no further live allowance. The earlier
full-suite failures in other scanner fixtures, TUI tests and snapshots still
need qualification. No snapshot differences or human UX judgments were accepted
automatically, and none of the nine broad delivery milestones is closed.
