# Actual Review execution and recovery

The operator approved one source-only Review job over the retained owned public
example, using existing OpenAI OAuth and GPT-6 Luna, low reasoning, one
worker and one attempt. The six-total request allowance included four settled
requests and at most two further provider requests, including retries. Dollar
cost was unknown. No target source was executed, built or imported.

## What the real request established

The campaign `live-owned-review-raw-20261010` consumed exactly one actual
provider request in `live-owned-review-raw-20261010-review-001-a1`. Its recorded
model is unchanged, and its latency is 3481 ms. The original attempt is failed:
the runtime returned an opinion, but the executor incorrectly treated storage
policy's deliberate refusal to overwrite a human decision as a persistence
failure. The original result contains no successful classification. It remains
unchanged; this assessment does not relabel that paid attempt as successful.

Two earlier native attempts exposed admission and resume defects before any
provider request. Dispatcher preflight used Discovery capacity instead of the
approved Review category, so protected Review calls could not be used. The
shell also omitted `--resume` for parked Review/context studies. Both are fixed
through the existing shared accounting and campaign dispatcher.

## Repaired behavior

Triage retains an unapplied model opinion in its durable run response when
storage policy returns a deliberate no-op. Additive `decisionApplied=false`,
`applicationStatus=not_applied` and `unappliedOpinions` distinguish classification
from an applied ledger decision. Actual storage errors still fail. Cached,
identity-wide, local and duplicate paths preserve human authority. Unapplied
FP opinions cannot count as automatic removals. Unknown provider cost is named
as unknown; estimates never claim the provider reported a zero charge.

Fixed campaign controls distinguish parked work from ended plans. An ended plan
cannot launch through the TUI, including its defensive `L` binding. Primary
controls, compact controls, key hints and navigation notices explain that new
work requires a new approved plan. Existing legacy campaign behavior remains.

The retained ledger has five provider reservations, seven work attempts, three
raw observations and one human decision. Five of six total calls are committed,
one Review call is used, and no reservation is unresolved. Dollars remain
unknown. The human FP reason, source-decision basis and accepted context manifest
remain identical. Source stays clean at
`f29dc288e0660ad20d074fc219c025f98ef7d155`; a later missing observation never
establishes that a finding was fixed.

## Verification and limits

239 distinct Core/CLI/TUI checks pass: 158 Review-related Core tests, one exact
work-category preflight test, seven CLI allowance tests and 73 campaign/keymap
tests. The opt-in native source-fixture hook returns without work when unset.
The campaign process-group check initially hit sandbox permission limits; its
focused permitted rerun passes. Locked workspace build and the 338-file risk
proxy pass. Summary verification and native capture receipts are recorded below.

All ten final repository summary gates pass. The receipt is
`/tmp/kuzushi-review-recovery-20261011/settled-verify-receipt.json`; it records
dirty/drifted state and local-platform/CI omissions, so it remains unsigned.
Earlier failed documentation verification remains retained; its focused rerun
passes after using the public model label while keeping exact runtime selectors
in machine receipts.

The first read-only J209 had 12 machine passes but captured Report before its
study data settled. The next had 20 passes and retained a blank resize frame;
it also exposed the generic launch hint. Both receipts remain as qualified
predecessors. The final journey waits for rendered finding/job content and
settled Report accounting, checks consumed-job refusal, pages compact source
identity, exports within the owned workspace, and restarts without new calls.
Raw native human-review requests remain distinct from assistant screen judgments.

Final sequential J209 is
`/tmp/kuzushi-review-recovery-20261011/settled-native/20261011-154136/J209`.
The frozen native SHA-256 is
`4c12ffd799e9614e1ba3cd492869e0cc7347003847d3777589ed446f794cbfb5`.
It records 30 machine passes, no failures and 27 nonempty authenticated
text/ANSI capture sets over six viewports and no-color restart. Exact target
HEAD, source status and tree match before and after. Compact paging reaches the
human decision's original commit and branch. Settled Report names five of six
calls, one protected Review call remaining and unknown dollar cost. Three
scoped assistant judgments remain separate from native REVIEW_REQUIRED and
operator approval false. This establishes recovery for this owned fixture;
it does not establish successful repaired real-model Review or UX equivalence.

At this assessment's checkpoint, live successful execution of the repaired
opinion path remained pending. The later
[preserved actual Review assessment](preserved-live-review-2026-10-11.md) records
the approved successful execution and six settled requests. Proposal evidence
is retained at
`/tmp/kuzushi-review-recovery-20261011/follow-up-proposal/proposal.md`, with digest
`sha256:576f7f233c1993413a068a77ad7d33ccedc7ef12c6457b5dda59420229941bcd`.
It keeps the six-total ceiling and old failed receipt. Preparation approves or
executes nothing. The first job's consumed attempt cannot authorize this new job.

The broader acceptance remains open: unbound legacy model allowance admission,
real verdict usefulness, retry/cancellation timing, complete per-tool readiness,
large-repository performance, live AI division, context experiments and learning,
physical-terminal accessibility and full reference-product UX acceptance. No
module is promoted or removed, and no broad delivery milestone closes.
