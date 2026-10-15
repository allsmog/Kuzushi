# Frozen source input for standard Review

The actual application Review returned `needs_review` because the supplied
observation lacked source excerpts. This increment adds an explicit bounded
source input to standard Review. It does not rerun that completed job or spend
its unused capacity. Twelve cumulative experiment requests remain recorded.

## Behavior and limits

`triage:run` declares optional `sourceEvidence`, `maxSourceEvidenceBytes` and
`sourceEvidenceRef` options through the shared registry. Existing inputs keep
their behavior. Selecting cited input requires the standard strategy explicitly;
deep strategies retain their existing source tools. The form never switches
strategy as a side effect of selecting source.

`campaign:review-study` freezes complete primary files only when the producing
observation's authenticated snapshot tree matches the preparation snapshot.
There is one shared source-byte allowance, default 32,768 and maximum 262,144,
across selected observations. Changed or unverifiable source, excluded or
missing files, binary text and files exceeding the remaining limit stay visible
as omissions. Dependencies are not read automatically. Zero captured bytes
refuses cited-plan approval rather than silently approving metadata-only work.

The version 1 document is stored in the existing content store and its opaque
reference becomes part of the fixed job input digest. Rereading authenticates
target, generations, primary paths, snapshot, tree, file hashes and byte counts.
Membership and producing-run metadata are reused across the selection. Bounded
reads constrain evidence and metadata loading. Approval and execution require
unchanged source; historical reading retains the frozen bytes. Matching source
bytes do not determine finding correctness or prove that a later SHA is fixed.

Each standard vote receives its selected source through the shared untrusted
repository wrapper in the user prompt. Original discovery evidence is unchanged;
later triage updates its projection and records a separate durable decision.
The adapter caps compact finding messages at 2,000 characters, so source is
delivered through the full prompt template. An adapter check proves that a long
encoded record survives and decodes to its complete original bytes. That is
transport evidence, not a new live-model validation or prompt-injection guarantee.

The Review form exposes `e` for source selection and `v` for the frozen input.
The reader leads with numbered source lines, then source identity and accounting.
Home, End and paging reach the complete document; Tab returns to exact options.
Reading uses a two-line navigation footer so forty-column terminals retain room
for code. Source wrapping preserves indentation, spaces and Unicode graphemes.
Raw source bytes and formatted model source-block bytes are reported separately.
Dollar cost remains uncertain and no enforceable dollar ceiling is claimed.
Preparation grants no calls, retries, attempts or follow-up jobs.

## Verification evidence

Evidence is retained under `/tmp/kuzushi-review-source-evidence-20261015`.
Focused checks cover exact source delivery to multiple admitted votes, retained
observations, changed source, forged references, primary-path substitution,
aggregate byte limits, binary omissions, pre-cancellation and invalid options.
Compatibility checks cover existing Review preparation and approval, manual
source reading, content-store authentication and recorded-source metadata.

The reader test visits every source line at all six terminal sizes and in plain
output. Initial checks caught two test assumptions: a document that fits at
96x89 needs no scroll, and raw source markers are encoded inside the canonical
wrapper. A compatibility check also retained an obsolete footer caption. The
corrected assertions retain exhaustive line, exact-byte and visible-action checks.
The retained logs distinguish those failures from passing reruns.

Native J283 uses owned inert text and one explicitly synthetic observation with
an authenticated producing-run receipt. Source is never executed. The helper
seeds fixture data only; visible TUI controls create the actual Review plan.
It asserts unchanged source/configuration, one unapproved fixed job and zero
allowance approvals, attempts, decisions and provider requests before and after
restart. This fixture qualifies reading and preparation, not scanner quality.

Final focused verification passes 78 distinct Rust checks and a workspace build.
The CRAP-risk proxy passes all 29 changed code files. Final J283 is
`tui-v9/20261015-091606/J283`: 27 machine passes, zero failures, 24 text/ANSI
capture pairs and three pending human judgments. The initial native run exposed
the cramped reader footer; its retained v7 captures precede the final layout.
The driver and journey bytes stayed unchanged during both runs.

The installed wrapper uses the frozen final native bundle, SHA256
`5ea1c9845ca1552cf7c805a01cf43bbc5b352bcb246f9f4080ef623f8cf8eb6a`.
All 4,222 frozen crate/build inputs and 675 runtime/test inputs stayed unchanged
through the final verification. The immutable fixture test executable uses the
same core implementation; later Rust changes affect TUI presentation and test
assertions only. Human judgments remain separate from machine assertions.
The registry matrix retains all 116 tools, adds the
three declared options and appends evidence to all nine triage audit dimensions
without promoting maturity or deleting implementations.
All ten repository quick-summary commands pass. The receipt retains the four
documented CI/platform and excluded-command limitations; focused tests and the
separate workspace build do not remove those limitations.

Live source-grounded usefulness, deep strategies, full interface qualification,
active cancellation timing, large selection responsiveness and human acceptance
remain open. Exploit development, reproducers and vulnerability patching remain
excluded. This increment closes no broad delivery milestone and establishes no
full-suite, platform, release or reference-UX parity claim.
