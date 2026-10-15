# Frozen code reader and explicit source-review form

October 11, 2026. Source-qualified decisions worked through shared dispatch, but
the TUI required a copied JSON reference and lacked a captured-code reader.

## Change

The Review header opens one source-review form. It presents bounded capture
terms, frozen code, source metadata, verdict choices, a multiline reason,
an explicit save review and a durable receipt. The composer, cursor and Review
origin stay separate. Code/source tabs and page controls remain available in
narrow terminals. Required-reason feedback clears after editing. The shared
Unicode field editor owns paste and cursor movement; code display preserves
indentation and grapheme boundaries and renders control bytes as text.

Capture can store one complete cited text file, up to 256 KiB. Its bytes must
match the authenticated captured tree entry before installation in the content
store. Missing/excluded, oversized, binary or invalid-text files disclose no
code. Reads authenticate the saved object and byte count, without reading a
mutable checkout. Existing metadata-only captures remain readable. The declared
`maxCitedSourceBytes` option flows through shared prepared dispatch, and the
original public capture helper remains available with the maximum default.

The form uses one cancellable worker and the shared manual application adapter.
It does not create discovery jobs, call a provider, switch model or advance a
phase by opening. A decision still checks source and ledger drift before writing.
Earlier decisions and raw observations remain. Escape during work requests
cancellation, closing preserves the draft, and a completion outside the form
emits a notice without stealing focus. Worker shutdown joins safely. Missing
durable ids cannot be shown as saved decisions.

## Native experiment

J199 reuses the owned inert public-documentation fixture, its two existing
commits and six fixed native source scans. The original human false-positive
decision remains at the first SHA. The TUI captures the later dirty source,
reads its real file bytes, inspects the full SHA and content identity, selects
Deferred, rejects an empty reason, accepts multiline paste and saves one explicit
decision. No JSON entry or headless decision is used for this save. Restart
retains the source-qualified decision and code object, with four observations,
two human decisions and zero reservations, work attempts or allowance revisions.
Target source is never built, imported or executed and no new commit is made.

Initial native captures are retained under `native`. Screen review exposed
whitespace normalization in the generic prose wrapper and stale reason feedback.
The final code wrapper preserves literal whitespace, and editing clears the
message. The final journey additionally exercises reason editing at all six
sizes and compact receipt paging before the save. No journey or helper is edited
while its process is live.

## Evidence and limits

Final J199 is
`/tmp/kuzushi-source-review-form-20261011/final-native/20261011-081750/J199`.
It records 31 machine passes, zero failures and 28 authenticated text/ANSI
captures across six sizes plus no-color restart. Native SHA-256 is
`4ec3295ea09f45366f551891a6d458c674721334ae06f4b3e952d961459e2ca6`.
Capture dimensions and native hash agree; no-color has no color SGR. Runner
target-at-start metadata is unavailable, and fixture receipts separately verify
the actual owned source. Assistant screen judgments remain separate; native
status is `REVIEW_REQUIRED` and operator approval is false.

The 40x12 code and reason views keep controls visible. The compact confirmation
can be paged to the full commit and dirty state before saving. Long finding
titles still truncate in narrow headers; short files leave empty space at tall
sizes. Large-file throughput and historical source-view navigation remain open.

32 distinct focused checks, locked workspace build, the 265-file changed-code
risk proxy and all ten repository summary gates pass. Tests cover authenticated
code after source change, oversized and damaged objects, one explicit form save,
stale-source refusal, cancellation/focus, draft preservation, Unicode and literal
whitespace. The receipt at
`/tmp/kuzushi-source-review-form-20261011/precommit-verify-receipt.json` records
a dirty tree and drift and stays unsigned. Final documentation receives a focused
contract check. The original live fixture retains its four reservations, six
attempts, three observations and one decision.

Tool qualification stays 73 of 112, with 39 unassigned including eight excluded
actions. This completes the bounded source-review form on the owned fixture;
it does not establish general finding quality, full live Review, monorepo scale
or complete reference-product/operator acceptance. No module is promoted or
retired and no broad delivery milestone closes. Tested work is staged on main
without commit or push.
