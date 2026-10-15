# Inspect the context projection before spending

The saved context document and the threat-model text supplied to agentic scans
were different operator surfaces. Execution already shortened sections and
lesson fields, but context review showed the complete document. An operator
could therefore review text that the scan would not receive without an easy
way to inspect the difference.

## Implemented behavior

Exact `threat-model:read` adds `data.scannerContextPreview` with schema version
1, a named projection, rendered text/hash, shared limit values and explicit
item/lesson omissions. It calls the existing agentic/triage digest renderer;
execution prompt text and its limits are unchanged. A complete saved document
with no renderable digest sections returns an explicit empty projection.

The context browser adds `p` and a visible action-menu entry. Summary, complete
document and scanner projection are mutually exclusive text views. The scanner
view leads with its purpose, source qualification, consumer limits and omissions
before included text. Its title remains pinned while reading. `Tab` opens the
complete document; `p` returns from the scanner view to summary. `Home`/`End`
and Page Up/Down navigate all context text views. Existing action-menu choices
retain their order.

Reading preserves selection, study settings, active context and composer state.
It creates no scan job, accepted Map, model request or spending approval. A late
source-check result cannot replace a reader that switched projection. Missing,
unknown or checksum-mismatched preview receipts show a reread action instead of
substituting another context or the complete document.

This projection covers the threat-model digest used by agentic scans and model
triage. It is not a complete request preview or a promise about every engine.
Source files, supporting context and prompt overrides remain separate. Runtime
repeats source and lesson eligibility checks and can add a warning or refuse
execution. The digest hash does not authenticate source bytes or the entire
prompt. Context references, documents, accepted plans and model choices remain
unchanged. The new text-view enum is transient shell state, with no persisted
checkpoint migration.

## Verification

Evidence root: `/tmp/kuzushi-tui-integration-20261012`.
Native runtime SHA-256:
`813d5490be911ab7f6ab43c666ea51b2e54b8ad5df235269e2399d51ff13c9f2`.
Thirteen runtime executables and one fixture test executable were frozen
read-only. The helper creates an explicitly synthetic owned observation and
scripted confirmation, then uses real prepared native dispatch to save, accept
and select a lesson into an inactive context copy. These test decisions are
separate from operator visual approval or real vulnerability evidence.

The lesson has 2,329 text characters. Its full immutable document retains the
tail; its execution projection contains the first 2,048 characters and explicitly
discloses 281 omitted. Native reads verify the digest hash and accepted lesson
eligibility. Source stays unchanged, the original active context remains active,
and provider reservations, work attempts, discovery jobs and phase attempts
remain zero. The one synthetic observation and scripted finding decision remain
unchanged. No target code is imported, built or executed.

Final J271 is
`scanner-preview-verified-tui/20261014-204548/J271`: 27 machine passes, zero failures
and 23 live text/ANSI capture pairs. It covers inspection prerequisites, the
visible menu action, six sizes, compact End/Home reading, complete-document
switching and no-color restart. Raw status remains `REVIEW_REQUIRED` with three
human judgments pending. Qualified assistant content review and capture hashes
are recorded separately; physical contrast, hardware latency, operator delight
and reference-product parity remain unapproved.

Forty-six focused Rust tests pass: 11 exact-context, seven existing digest,
20 context-browser and eight source-check tests. They cover shared dispatch,
omissions, Unicode, empty projections, malformed receipts, source/goal isolation,
composer state, view switching, six-size navigation and late-result ownership.
The locked workspace build passes. A short-name `--exact` invocation selected
zero tests; it is excluded from those counts and was replaced by the real
eight-test source-check run.

Earlier terminal attempts remain available. One script incorrectly expected
inspection to switch back to summary; preserving the requested scanner view was
the correct behavior. Another sent Escape and a printable key in one batch,
which the terminal combined rather than closing the menu. The final journey
uses the menu's documented Enter action. Its first green capture also exposed
a repeated heading/hint that consumed all three compact reading rows. The final
build moves that chrome into the fixed title and controls; first-page body rows
now show source qualification. No running helper or journey was edited. The first repository summary stopped at module declaration ordering;
the focused format check passed after that correction.

The fresh complete J121 at
`scanner-preview-fresh-complete-tui/20261014-205643/J121` passes 109 machine
checks with 87 authenticated capture pairs on the same final runtime. Setup,
the three-job Map producer, accepted inactive context, bounded Scan passes,
limit/partial handling, scripted FP and deferral, partial export, specific
allowance revision, completed report and no-color recovery all execute through
the real shared boundaries. Four provider requests use fully intercepted
transport. Every Map and Scan job completes in one attempt, and Review remains
protected. This is workflow evidence, not real model usefulness. Its 15 human
judgments remain pending separately from J271's three.

That run followed interrupted observations against a separate original fixture.
The original Map jobs were already terminal when an old `3 job(s)` assertion
missed the current `Jobs: 3` header. Continuations consumed those recorded jobs,
reached partial Review/Report, and completed only the still-parked Scan job after
the explicit revision. A second old assertion missed the new pinned Report
format label. A resumed session correctly exited immediately because it had no
unsaved drafts, unlike the original fresh journey. Read-only restart then
verified the completed original ledger and missing-context recovery with four
intercepted requests total and no repeated job. Raw failures remain retained.
The four canonical Campaign/Report assertions now name the actual labels;
the fresh 109-pass run establishes the corrected uninterrupted path.

One-off continuation source copies are retained under
`scanner-preview-one-off-continuations` for evidence. They are not shipped as
duplicate copies of the canonical journey. Original source, queue, accounting
and run receipts remain in the interrupted fixture.

All ten repository summary gates pass, including 391 Node tests, locked
workspace/all-target checking, model safety, architecture, documentation and
the CRAP-risk proxy over 788 changed code files. Final documentation contracts
also pass. The saved local receipt is dirty, drifted during documentation work
and unsigned. It does not attest a clean commit, full Rust suite, release build
or CI host matrix. Work is staged only.

## Remaining acceptance

This qualifies the exact-context reader and its current agentic/triage digest
projection narrowly. Complete request rendering, other engines' context,
legacy/scoped read variants, every cancellation race, large-workspace resource
behavior and actual model usefulness remain open. No module promotion or
retirement follows. The separate six-request live Scan still awaits its own
approval; no additional live provider request was made. Broad implementation
milestones remain open and work remains uncommitted on main.
