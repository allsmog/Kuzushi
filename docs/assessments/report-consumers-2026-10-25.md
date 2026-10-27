# Report consumers and canonical review counts, October 25, 2026

A later human FP removed a repeated finding from confirmed SARIF while its trend
still counted the earlier observation as confirmed. The CLI gate could also lose
a confirmation carried to a new observation row. The consumers now use the
existing effective-review policy over the current canonical finding projection.
Human priority, local decision scope and explicit reopening remain unchanged.

## Supported behavior

Campaign status reads narrow canonical subjects and their decisions in one
projection snapshot. The TUI carries those global counts independently of list
filters and pages. A background snapshot refresh updates an open trend strip
without replacing its spend or moving focus. Missing review data remains unknown.
SARIF and the CLI gate use the same recorded-review policy for current findings.

Legacy observation-row helpers and the public compatibility SARIF selection keep
their behavior. Cached legacy triage alone does not manufacture a decision-ledger
count. No raw observation, human decision, source identity or context is rewritten.
No descriptor, option, maturity tier or public artifact field changes.

An empty floating-point sum previously displayed as negative zero. Exact zero is
now normalized without clamping nonzero values or clearing unresolved-spend flags.
The campaign trend uses primary text so current figures can be read against the
dark background. Existing historical trend snapshots remain unchanged and may
contain the earlier observation-based counts. They are not recomputed history.

## Actual artifact consumers

The earlier owned CLI probe at `consumer-probes-attempt-3/result.json` establishes
canonical report selection on the preceding source cut. An implicit analysis
report is refused when only operational runs exist. Explicit selection of
`consumer-confirmed` produces the correct canonical Markdown report. Its FP
export retains the exact recorded source reference while Git stays unknown.
That probe exposed the trend defect addressed here; its original outputs remain.

Current native J368 drives the real shell dismissal and headless SARIF, campaign
status and CLI consumers. One confirmation survives two observations. A later
human FP produces zero confirmed, one decided, one rejected FP and a 100% FP rate.
Cost per confirmed finding has no denominator. Both observations remain byte for
byte unchanged; both human decisions remain. Source hash and all these results
survive no-color restart. No provider, scanner or target-source execution occurs.

## Verification and terminal reading

Evidence root: `scripts/devex/artifacts/report-consumers-20261025/`.
Source is dirty main based on `e9905abf1d8e865f17085197318fe09eeaf8614f`.
The final frozen executable SHA256 is
`81ed686e3a0a62dff8036394ae444233b61c63a2448efe77bf7226c08982f382`.

Final journey:
`trend-native-attempt-2/native/J368/20261025-112400/J368/`.
It records 23 machine passes, zero failures, 24 authenticated capture pairs and
four formal operator questions. All six viewport sizes are captured in color and
no-color. Direct Escape reading frames assert the visible control, FP rate and
zero-confirmed count at 40x12 before paging. Positive zero is asserted live.
The 6,631 repository inputs and all frozen programs stayed unchanged during it.

All four questions have separate State, Intent, Honesty and Craft agent answers
in `trend-native-attempt-2/agent-review.json`. Six ANSI replay PNGs were viewed
directly. They reconstruct terminal cells; they are not OS screenshots. Raw
`REVIEW_REQUIRED` and formal operator approval false remain explicit.
Current figures are clearer. The legacy campaign reader still has crowded
breadcrumb/footer copy and very little document area in prompt mode at 40x12.
Reading mode works, but reference-level comfort is not accepted by this audit.

Focused evidence includes ten actual SARIF consumer tests, six effective-policy
tests, a real campaign-status test, ten coherent/paged TUI projection tests,
nineteen campaign behavior tests and eight actual CLI library gate tests. The
last single-worker trend run has 24 Core, three TUI and one CLI passes, including
local scope, human priority, reopening, legacy caches, zero and unknown spending.
These groups overlap; their counts are not added as distinct tests. The workspace
build and Core/TUI/CLI all-target Clippy pass. The unchanged vendored terminal
warning remains. The final draft repository gate is recorded separately and
cannot attest a clean new commit until publication approval and verification.

## Retained failures and limits

The initial shared-dispatch regression failed with one trend confirmation after
FP, proving the defect. A CLI launcher filter selected zero tests and gets no
credit. The corrected library test exposed a stale test-only report path; it now
uses the canonical report-path helper. The fixture uses the same canonical path.
A 46-line snapshot reader failed the risk gate; narrow review-read and watermark
helpers corrected it. The current static gate covers twelve changed code files.

J368 attempt 1 has fourteen machine passes and two hard navigation-helper
failures. It also records negative zero and overly dim figures. The next journey
uses the reader's actual visible control, plus stronger counter checks, rather
than changing the protected harness. The earlier J139 follow-up retains its
obsolete-title failure and final fifteen-pass cut. Its corrected assertion checks
finding identity, path, confirmation and actual detail controls.

One preparatory command stopped before edits because host Python lacks tomllib.
A later link failed from disk exhaustion. Only inventoried regenerable compiler
objects in this checkout were removed; executables, receipts, source and frozen
evidence remained. Sequential one-worker verification then passed. The unrelated
mutation-test checkout was not stopped or modified.

Large-ledger throughput and cancellation, every option combination, external
SARIF interoperability, current-checkout applicability, full reference UX and the
remaining module qualifications stay open. The runtime-free fixtures do not
establish detector precision or general model usefulness. No broad delivery
checkbox or module maturity is promoted. This draft adds zero model requests;
the historical sixteen-request allowance remains exhausted.
