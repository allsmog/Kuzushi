# Manual decision responsiveness, October 6, 2026

Interactive verdict and dismissal saves now run in one bounded background worker
using the same Core record service, captured target, finding identity, read
watermark and review session. No second write is queued. The Review title names
the saving finding, the body says it is awaiting a result, and the existing
recorded decision remains independent of the pending request. Typing keeps
ownership of its draft. Exit waits for the accepted save result. A worker with
no result does not increment saved counts or retry automatically.

Target switches retain the accepted write on its original target. Its result
names that target without changing current rows, review counters or navigation.
Later interaction suppresses old presentation continuations; the current query
refreshes through the existing bounded reader. Session closure matches the
captured session id, so a later open is retained. A newer human decision or
observation is still rejected by the shared watermark guard.

The work exposed a paging regression in suppression: a row excluded by its new
decision remained the refresh anchor. Suppression now starts a fresh query
window and resolves aliases through the policy-aware complete ledger. A pending
verdict save also refuses suppression. Suppression-rule writes remain
synchronous; they are further responsiveness work. No module, model, provider,
artifact format or persistence invariant is replaced.

Eight dedicated worker checks, 182 focused findings checks, 12 review-decision
checks and 28 keyboard checks pass. The workspace build and CRAP-risk gate pass
for 89 changed code files. Raw failures are retained: initial test-import errors
and the excluded-row suppression regression. Native J103 at `205551`
stopped before any writes: explicit opening resolved an omitted identity but
kept the cockpit on its first loaded row. Unfiltered explicit opening now
loads the anchor page before finalization through the guarded background reader.
An additional focused opening check and 12 background-refresh checks pass. Evidence root is
`/tmp/kuzushi-experiment-main-20261006/`. Final native J103 at `tui/20261006-212152/J103` has 30 machine passes,
six passing ask judgments and five passing related layout judgments. Raw exit 4
and `REVIEW_REQUIRED` remain separate from `manual-review.json`. Twenty-five
captures share native SHA256
`fa4a098559599eef62bbc6655d400f5a09de9e607250a2a5f7b3f7471f292233`.
Six 2-second SQLite locks provide bounded real commit contention without changing
rows. Echo samples are 74, 72, 74, 74, 75 and 75 ms within 300 ms. These samples
do not establish worst-case latency or write throughput. Restart's source
comparison was still loading, while the recorded decision and excerpt were
visible. Final layout/repository checks are recorded separately.

Additional predecessors are retained: `210709` committed one decision before
the pending-state observation missed it; `211156` committed five decisions before
the submit helper refused a command that could not fit at 40 columns; `211617`
committed six decisions before a long previous receipt hid the tiny content.
The recipe now uses supported raw typing for the same complete command. New
saves clear their previous owned receipt, and tiny receipts keep full detail in
history. Every failed report remains unchanged. Timeout diagnostics disclose
missing provenance sidecars. Final verification checks exactly eight explicit
human writes on one identity, from 1,048 to 1,056 decisions, with all 2,000
observations and source hashes unchanged. Total native predecessor/final writes
in this increment are 20, from 1,036 to 1,056 decisions.

No provider request or target-source execution is made. Native work uses the
existing owned, labeled 1,000-finding fixture and an explicit eight-write recipe.
The underlying journal/authentication and query cost are unchanged. Real Git
transitions, wider scale, platform/accessibility coverage, complete functional
module evidence, accepted lessons and the complete finite investigation/report
still need acceptance. All nine implementation milestones remain open.
