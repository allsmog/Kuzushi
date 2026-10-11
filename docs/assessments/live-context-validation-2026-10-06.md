# Live context validation and inspection recovery

October 6, 2026. Work is on `main`, based on `bed5fcb757`. Local `main` was
fast-forwarded to existing investigation commits; no new commit or push was
performed in this experiment.

The previously prepared diagnostic had an actual operator approval at allowance
revision 3. Its one fixed source-only job used normal OpenAI OAuth, GPT-6 Luna
with low reasoning, one worker and one attempt. The total limit was ten provider
requests, including two protected for Review. The current ledger was checked
before execution rather than relying on the older eight-request snapshot.

## Actual model outcome

`live-luna-context-diagnostic-context-001-a1` completed using one provider
request. Seven total requests are now settled; none is an unresolved request
reservation. Two Review requests remain protected and one unused request remains
available for separately approved discovery work. Dollar metering is incomplete;
neither observed zero fields nor settled request counts establish a zero charge.
No source was executed or changed, no transport was intercepted, and no model
fallback was used. The operator's ordinary model configuration stayed unchanged.

The immutable draft contains three DFD nodes, four flows, one boundary, two
threat candidates and three open questions. Manual source comparison found its
function descriptions, ownership contract and cited checks consistent with the
two-file fixture. It leaves caller reachability, upstream validation and storage
behavior unknown. This is a useful draft on a labeled fixture, not a production
precision or recall result, a verified vulnerability, or complete coverage.

The initial failed request and this successful request have the same recorded
model and first-request prompt fingerprint:
`blake3:4dfd263db176f7117338d9f285cc6e229c0f83f0c5ab454b4ce48c216a7d6d3c`.
The operator input changed only by enabling rejected-output retention. The
earlier call failed schema validation even after a repair; this call passed
without repair. The binaries were built at different revisions, and the earlier
raw response was lost. These observations do not prove that a code change fixed
generation or that identical full runtime conditions were reproduced. They do
show why one successful response cannot establish reliability.

Source identity:
`tree:6ad7885ccadf2ffc8028f4c83ce0756810e82e39978fa9fae19b09b49343b52e`.
Context identity:
`sha256:6e09d82decf312ddbc4fc705a7a72fed93007f4f757487bd40bdea9436b6bcf7`.
The diagnostic plan remains
`sha256:4c099b3164da2fa9bfbb4974ce0795e2eee39600308559e00023c678904cf580`.
Original and new results, call receipts, source fingerprints and execution logs
are retained under `/tmp/kuzushi-live-model-ua7rhauw/` and
`/tmp/kuzushi-experiment-main-20261006/`.

## TUI defect found through real receipts

“Enter inspect” removed the completed context form's saved state. Returning from
the diagram and then closing the inspector landed in the study form, losing the
result origin, options view and scroll position. A focused regression failed
with `left: None` for the original `StudyContextGeneration`.

The inspector now retains its originating result and restores it on Back.
Explicit context selection still proceeds to the study form. The fix preserves
the draft, cursor, generation options, scroll and allowance. It adds no provider
request, artifact format or dispatch path.

J96 retains its failed setup expectation for an omitted optional `active` field,
its wrong diagram-title expectation and the actual return-origin failure.
The final run is
`/tmp/kuzushi-experiment-main-20261006/tui/20261006-113921/J96/`:
21 machine passes and seven separate passing screen judgments, with raw
`REVIEW_REQUIRED` unchanged. It covers all six sizes, actual 40x12 detail paging
to rows 40-45/45, source-bound pending Map, explicit acceptance, actual exit and
no-color restart. Source, global active context, allowance, seven requests and
five work attempts stayed unchanged through UI inspection. Native SHA-256:
`58e401ec5475615461188a89dd1429c9bd9e1f66f789c2b847abd93da65eb186`.

This acceptance is stateful: the live fixture's Map is now selected. Replaying
the pending-selection assertions requires a separate historical-reader scenario,
not resetting its ledger. Physical contrast, motion and reference parity remain
open. J96's source-inventory chrome still said “context not built” while the
exact accepted threat model was present. The later
[accepted-context reader checkpoint](accepted-context-reading-2026-10-06.md)
fixes those labels and reading defects on `main` at `799bfa2870`. Missing
inventory and unknown grounding remain disclosed.

Eighteen context-generation regressions, twelve context-picker regressions,
workspace build and changed-code CRAP-risk pass. The failed pre-fix navigation
test remains recorded. The final quick verification receipt is stored separately
after documentation is frozen. No complete delivery milestone follows from these
narrow checks.

## Prepared next experiment

`live-luna-accepted-context-three-passes` is drafted but unapproved and unstarted.
All three jobs inherit the exact accepted context, one worker and the unchanged
source. Its canonical source-only settings keep automatic triage, verification,
execution and patching disabled. The old context-omitted study remains separate;
its observations cannot be counted as equivalent trials of the new conditions.

The proposed ceiling is 21 total requests: seven already spent, twelve available
for this discovery plan and two protected for Review. That adds eleven to the
current ceiling of ten. The earlier completed pass used four requests; new
context may change consumption, so twelve is an allowance rather than a promise
of completion. Dollar cost remains unavailable. The exact plan and proposal are
reviewable in `/tmp/kuzushi-experiment-main-20261006/context-scan-review.md` and
`context-scan-allowance-proposed.json`. Specific approval is pending. Preparing
the draft did not change consumption or create a dispatcher queue.
