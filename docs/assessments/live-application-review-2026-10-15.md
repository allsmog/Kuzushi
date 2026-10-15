# Bounded application Review: execution works, source grounding remains limited

The operator separately approved one source-only Review of an exact observation
from the completed fourteen-file application Scan. The prepared plan selected
`generation:7469188942355798651`, the third pass's observation, with the same
immutable inactive context and frozen context text. It used stored OAuth,
GPT-6 Luna, low reasoning, one worker, one job, one attempt,
one vote and the explicitly selected standard strategy. Model deduplication,
identity propagation and dataflow tools were disabled.

Standard Review evaluates the supplied evidence and context. This test did not
approve deep code-reading triage, source execution, exploitation, reproducers,
vulnerability patching or follow-up jobs. The owned source is an inert library
without a deployment. Its finding does not establish deployed exposure.

## Outcome and accounting

`live-application-review-20261015-review-001-a1` completed once with one actual
provider request. Its call receipt records the exact selected model and
`callAttempted: true`; the result is uncached, with one successful classification
and no persistence failure. The model returned `needs_review`, confidence 0.25,
because the supplied observation contained paths and claims without source
excerpts. This is an honest insufficient-evidence outcome, not successful
vulnerability validation. The next product improvement is source-grounded
evidence delivery and clear Review preparation guidance.

The ledger retains three discovery observations and adds one automatic
`needs_review` decision. It records no human decision. Report keeps one open
finding, zero completed reviews, zero confirmed findings and 3/3 discovery
recurrence. The TUI identifies the opinion as automatic and keeps
`needs-runtime` evidence visible. Recurrence does not settle the verdict.

Approval revision 2 reduced this investigation's shared ceiling from eight to
five requests: the three settled Scan calls plus at most two new Review calls.
Two calls were protected for Review. After execution, four total requests are
settled, including one Review request, with no unresolved reservation. Twelve
requests have been used across all experiments, below the separately approved
thirteen-request ceiling. The single Review job is finished. Its unused request
capacity approves no new work or repeated attempt.

Dollar cost remains unknown. `providerSpendUnresolved: true` describes missing
charge evidence, while the ledger's zero unresolved calls describes settled
request reservations. The legacy numeric `observedCostUsd: 0` must be read with
that missing-cost flag; Report and the allowance expose unavailable cost. The
historical stage tag `haiku` also remains in the result. It is not the model:
the actual call and stage model fields record GPT-6 Luna.
Presentation cleanup of that tag remains open; no model fallback occurred.

## Native verification

Evidence is retained under
`/private/tmp/kuzushi-live-application-20261014/review-proposed-20261015`.
The authorization, exact approval input, frozen draft, controller exit and
provider/ledger invariants are recorded there. The controller reached terminal
exit 0; it was not relaunched.

Final J282 is `tui-v3/20261015-075535/J282`: 27 machine passes, zero failures,
19 text/ANSI capture pairs and four pending human judgments. It reads the
completed Review job at six sizes, inspects the original three-pass recurrence
and automatic opinion, exports Report and recovers both completed plans after
no-color restart. The helper verifies unchanged fourteen-file source, operator
and fixture configuration, inactive context, three observations, one automatic
decision, no human decision and exactly four requests. It dispatches no product
tool and starts no job. The initial reader stopped on an incorrect test caption;
the final assertion matches `recorded: needs_review · auto`. Neither reader run
made a provider request. The driver is unchanged.

The private-context gate caught a repeated developer home path in the reader
helper. The helper now uses the existing fixture owner binding. The focused
gate passes and the final native rerun covers those corrected helper bytes.

The installed wrapper used the frozen native bundle from the preceding Setup
checkpoint, SHA256
`4359ed886769d9cfcc90c01d86042d23fb7db91a40054604bc7f02e79ccc27ae`.
All 4,212 recorded crate/build inputs remain unchanged from that tested build;
all 673 runtime/test inputs remain unchanged during the final reader run.
This increment changes test/evidence files only, with no new Rust implementation.

The nine audit dimensions for `triage:run` now include this case without a
maturity promotion. Deep/gate-deep strategies, stronger source grounding,
classification usefulness, remaining failure paths and broad interface/module
qualification stay open. Four human visual judgments remain pending. No broad
delivery checkbox, full Rust-suite, platform, release or reference-parity claim
is established by this scoped success.
