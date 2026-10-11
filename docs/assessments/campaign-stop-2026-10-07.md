# Campaign Stop and authenticated partial recovery

The Campaign deck now requests Stop without blocking the shell. The dispatcher
settles supervised children, parks unstarted work and saves a partial Scan
result. The completed observation, original context bindings and unresolved
reservation survive restart. This is a bounded increment on main. The full
implementation plan and its nine milestone checks remain open.

## Behavior and source authority

A held child handle and its original target/campaign identify the dispatcher.
The request carries the active dispatcher's session identity, so an old request
cannot stop a later launch. The dispatcher checks the request before claiming
another job and forwards Stop to active child supervisors. The shell keeps the
handle until exit and reaps it during its normal tick. Pending Stop removes
Launch from the action strip and preserves the composer draft and view.

Children already had parent-death process-group guards. The old hard kill
bypassed queue and result settlement. Stop now preserves those boundaries.
Interruption recovery binds the host's result to the root tool call. Nested
engine results remain missing when they were never produced.

A second native failure showed that an interrupted job's source snapshot lived
only in memory. New SAST calls persist a producer-scoped start-source artifact
before model work. The lifecycle permits this specific artifact from its running
SAST producer; other artifacts and canonical results retain terminal ordering.
Source reading authenticates the reference, indexed snapshot and content-store
objects. Altered start artifacts and altered results fail closed. Historical
runs are not rebound to current source. The additive reader migration is in
RELEASING.md.

Report identifies how many attempted jobs have engine details. Missing details,
unavailable dollar cost, failed/pending work and separate context recurrence
remain visible. No absence or interruption establishes a fix.

## Native evidence

Final J113: `/tmp/kuzushi-campaign-stop-20261008/tui/20261007-190724/J113`.
The raw result is REVIEW_REQUIRED with exit 4: 17 machine passes, zero failures
and six review questions. Separate `manual-review.json` records six scoped
passing judgments. `ansi-review.json` records all fourteen live frames,
including 40x12 report paging and no-color restart. The driver is unchanged.

The real executor runs on owned greeting source. Every transport request is
intercepted and returned observations are labeled synthetic. No live inference
or target-source execution occurs. This is transport/control validation, not a
finding-quality or live-model acceptance claim.

`exact-work-check.json` and the fixture checks establish:

- The original nine jobs remain fixed, with one worker and two attempts.
- One pass completes, the next is interrupted and seven jobs never start.
- One raw observation remains and its finding still needs review.
- Two calls are accounted within four approved calls; one remains unresolved.
- Two protected review calls remain. Unknown dollar cost stays unknown.
- Both start-source artifacts authenticate the same inspected source tree.
- Source bytes and the globally active context mirror remain unchanged.
- One partial Scan result is explicitly acknowledged and retained after restart.
- Owned transport children are gone. Restart starts no further work or requests.
- The operator draft is visible both while Stop is pending and after exit.

The native binary SHA-256 is
`a5590e872bd1d8530788f8e980ab0af786dd9ae214da96516171525e0edc082b`.
This increment exercises 120x36 and 40x12. It does not close the complete
viewport matrix or the reference-quality TUI requirement. Global phase chrome,
all module failure paths, monorepo scope editing and learning still need their
own acceptance evidence.

## Verification and retained failures

Evidence root: `/tmp/kuzushi-campaign-stop-20261008`.
Focused dispatch tests pass 73 cases. Lifecycle tests pass 88 with one ignored
fixture; history recovery passes 19, source snapshot passes four and report
presentation passes fourteen. The source-authentication recovery case verifies
missing engine membership and rejects tampered source/result artifacts.
Campaign TUI tests pass 47 cases. A sandbox-denied process-group test passes in
its isolated permitted rerun. Native build and workspace checks pass. The final
summary receipt records the repository gates after documentation closeout.

The first native run retained two failures: a mistaken two-millisecond echo
threshold and missing correlated interruption result. The second reached a
partial result but correctly refused source acceptance. Later review-required
runs added missing-details disclosure, narrow paging, an unambiguous initial
deck checkpoint and a settled-draft checkpoint. Their raw results remain intact.

The first final summary failed the whole-repository synthetic-secret fixture
check because new tests changed its approved file hash. All original URL fixture
lines are unchanged and the diff adds test lines only. The reviewed digest was
refreshed without changing detection rules. The focused nine-test secret suite
passes; the review receipt and failed summary are retained.
