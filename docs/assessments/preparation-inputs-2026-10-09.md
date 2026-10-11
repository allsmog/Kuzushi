# Bounded preparation inputs, October 9, 2026

The readiness audit found preparation paths that could stall before an operator
could approve a study. Automatic SAST selection used an unbounded Cargo advisory
version probe. Comparison identity collection recursively walked cache and
override directories without aggregate entry or byte limits. A configured
Semgrep executable also escaped the intended executable fingerprint: the
comparison record described the PATH executable instead of the selected file.

## Changes

Cargo advisory checks invoke the standalone executable through the existing
bounded process adapter. The probe has a two-second deadline and 64 KiB limits
for stdout and stderr. Missing dependencies remain optional skips in automatic
selection. Failed or stalled installed dependencies refuse preparation. Filtered
automatic selection does not probe a disabled Cargo advisory task. The public
boolean availability helper remains compatible and bounded.

Executable, CPG cache and override files share a 100,000-entry and 512 MiB budget
per comparison capture. Engine files have a 128 MiB limit; override files retain
16 MiB. Traversal is iterative, rejects symlinks and special files, and opens
contained regular files without following aliases. Reads respect the remaining
byte budget, verify size and modification time, and check a 30-second deadline
between reads. Missing directories remain distinct from malformed roots and
dangling links. Existing sorted content digests are preserved.

The deadline cannot interrupt a blocked filesystem call. Source identity and
managed CodeQL database authentication remain separate operations. Multiple
cases repeat capture, so these limits do not constitute a total study IO
allowance or a strict dollar ceiling. Cancellation throughout every preparation
operation remains broader acceptance work.

Explicit Semgrep binary paths now identify their actual content. A focused
frozen-child test accepts the original comparison and refuses changed executable
bytes before scanner execution. This is comparison evidence, not certification
of the executable or its dependency closure. Affected old plans need a new draft
and approval; artifact readers remain compatible.

The Source panel presents recorded executable and cache facts before the full
scan-option document. It distinguishes missing, incomplete and located facts,
deduplicates repeated case facts, and describes the current limits. It does not
call a located executable ready or infer useful coverage. Actual dependency,
target, credential, allowance and output readiness still need their own checks.

The native failure audit also exposed a stale form status. Preparation failed
and saved its error correctly, but the temporary banner expired after twenty
seconds and the retained form still said Preparing. The form now owns that
terminal reason until dismissal or explicit retry. Error paging and Escape
controls use the same state. Cancellation retains its stopped reason. Plain
output consumes the same presentation projection. Dismissal keeps the selected
row, investigation identity, call limits and composer; retry clears the error
and only prepares the next shared dispatch. No artifact format changes.

## Evidence

Evidence is retained under `/tmp/kuzushi-preparation-inputs-20261009`.
Nine equivalence tests cover deep and wide trees, symlink roots and cycles,
aggregate bytes, per-file limits, expired deadlines, preserved legacy digests,
configured executable changes and frozen-child drift refusal. Three real process
probe tests distinguish missing, failed and stalled dependencies. Three default
selection tests retain optional skips and explicit selections. Three study
receipt tests retain fixed jobs, immutable bindings, tamper refusal and restart
reading. Two Source fact tests preserve honest states and deduplicate case data.
Existing batch regressions pass; an earlier broad test filter also matched three
unrelated blob-materialization tests, which are not credited to this increment.
Five focused failure-state tests exercise actual tool events, timed banner
expiry, blocked launch before dismissal, preserved draft settings, explicit
retry and cancellation. Three rendering tests include all six viewports and
plain output. Five study-action regressions retain shared dispatch, approval,
frozen options, restart and return navigation.

J136 uses owned version helpers and comment-only source. It exercises two real
preparation failures, verifies that no complete campaign or scan queue is
published, and prepares an explicit three-job plan using an owned metadata-only
executable. It then inspects the recorded facts and restarts without color.
No scanner or model request is executed. The extended run records Source-panel
paging across the same six sizes used for the failure reader.

Retained failures include a formatting trait mismatch, a filtered-selection
return mismatch, a noncanonical temporary root, excessive view-model complexity,
input typed while the composer owned focus, and overscrolling past a heading.
Production fixes are separate from fixture and navigation corrections. The
journey driver stays unchanged. The final native run is
`/tmp/kuzushi-preparation-inputs-20261009/tui/20261009-012802/J136`:
sixteen machine passes, no failures, five human questions and fifty-three
authenticated live text/ANSI capture pairs. Both failures remain visible after
a twenty-two-second wait. Four no-color restart captures contain no color SGR
sequences. Native SHA-256:
`efb2b984ba41302451f7c0f87447735a4cd214a0034ef7bf1eb0926e7a4584e3`.
`scoped-review.json` records three passing and two partial implementation
judgments. Raw exit 4 remains REVIEW_REQUIRED and operator approval is false.

The partial judgments are actual product debt: at 40x12 the form leaves only
two detail lines, dismissal guidance repeats, and twenty pages are needed to
reach the engine inspection limits. Functional reachability is established;
reading comfort and full reference interaction parity are not. The earlier
final-source run preserves the transient-error failure. A later wrapper startup
failed because its fixture PATH excluded Node; the settled run uses the native
binary directly and does not claim wrapper-path validation.

All ten quick gates in `verify-recovery.json` pass, including workspace checking,
formatting, model policy, docs and the CRAP-risk proxy. Native build and the
focused tests pass separately. The receipt preserves dirty main and
`driftedDuringRun: true`; the verifier conservatively records that flag for any
dirty checkout. This is local working-tree evidence, not clean-commit or release
verification. An invalid verifier argument attempt is retained separately.

The complete module usefulness audit, target-specific readiness, complete
context and monorepo acceptance, real OAuth validation and broad reference
parity remain open. No module is promoted or retired by these checks. The
earlier authentication failure grants no additional provider request.

## Detail reader follow-up

The two partial screen judgments above prompted a second implementation pass.
The visible z read control now expands the selected explanation into the form's
full body. At 40x12 this gives six detail lines instead of two. The heading names
the selected setting or Preparation details. Arrows scroll the document;
PageUp/PageDown, Home and End reach its full text. z or Escape returns to the
same selected setting and original form scroll. A retained failure keeps Escape
as dismissal, with its draft intact. Separate reader scrolling preserves the
form position. Resize and no-color output retain the selected section. Plain
output projects that section exhaustively when its reader is open. Preparation
errors no longer append an unrelated field explanation, and the next-step text
no longer repeats the Escape instruction.

Five reader tests cover layout bounds, independent scrolling, return navigation,
line scrolling, resize and retained-error dismissal. Four rendering tests cover
all six sizes, controls, number editing, retained errors and selected-section
plain output. The five preparation-failure regressions still pass. A first
complexity check rejected a five-branch key handler; a named return helper now
keeps that responsibility within the required limit. Native build and all ten
gates in `verify-reader.json` pass on the dirty working tree.

The settled reader run is
`/tmp/kuzushi-preparation-inputs-20261009/tui/20261009-014235/J136`:
twenty-two machine passes, zero failures, five human questions and forty-five
authenticated live capture pairs. Five no-color frames have no color SGR
sequences. Native SHA-256:
`f523a529f47d8c4f151fd407ae350ce7b06927c74a75639baf70f5cdcc1ac88c`.
The 40x12 error can be read in two frames. Source facts and inspection limits
are reachable in six page advances, compared with twenty in the earlier form.
The script captures eight advances to include the following options document.
Return and restart preserve the same unapproved plan, actual selected executable
and unchanged source. No model request or scanner job runs.

Four scoped screen judgments now pass and one remains partial: long paths,
repeated qualification and the raw options document still make Source verbose.
Raw REVIEW_REQUIRED and operator approval false remain unchanged. This closes
the observed transient-status and narrow-reading defects; it does not establish
full interaction parity, all preparation cancellation paths or any module's
live-model usefulness. The earlier raw failures and reviews remain retained.
