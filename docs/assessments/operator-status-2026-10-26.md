# Operator status and repository-index freshness

## Literal result wrapping

The compact-message audit exposed a separate defect. Logs wrapped each message
at the timestamp width, joined those fragments with spaces, then wrapped them
again at the continuation width. This inserted spaces into long paths and
collapsed meaningful whitespace. Plain output also treated three repeated-space
gaps as a table row and could truncate the same evidence.

Two Logs regressions and one plain-output regression fail on the old behavior.
Logs and long plain rows now use the existing document wrapper, preserving
printable spaces and complete graphemes. The shared wrapper accepts distinct
first/continuation widths; existing fixed-width callers retain equal widths.
Prefix sizes use terminal cells. The plain-output control sanitizer and
right-padding cleanup are unchanged. Compatibility notes are in RELEASING.md.

Evidence is in `scripts/devex/artifacts/literal-log-wrap-20261026/`, including a
J375 repeat on an owned nested repository whose name contains two spaces.
The earlier J375 proves stored canonical bindings and compact operational copy;
it is not accepted as proof of literal rendering.

The final source passes 387 distinct focused TUI checks and three serial
performance checks, plus TUI Clippy, workspace build and formatting. This count
deduplicates 352 wrapping/renderer checks and 35 target, startup and shared
background-dispatch checks. The risk proxy covers 104 changed code files.
Prior evidence for 113 Core checks applies to 3,180 unchanged non-TUI crate and
Cargo files; those checks are not claimed as newly executed here.

Final J375 records 50 machine passes, zero failures and 21 authenticated no-color
captures against thirteen frozen programs and 6,692 unchanged source inputs.
Native SHA-256:
`028a806781c2837148e6e1a09bbdd36b33916f4afea03dcff7304c41f158c0bb`.
Seven reader captures cover 42 contiguous rows. An independent observer matches
the complete raw result, permitting only trailing cell padding, and verifies
both literal spaces in the repository name. Canonical session/run targets, raw
results, the fixture Git index and one auxiliary run survive restart unchanged.
No provider call, target execution or investigation job occurs.

The first repeat failed because the observer did not recognize timestamped
continuations. The second passed literal-result matching but captured a resized
terminal before the draft's frame was painted. Both raw failures remain. The
final observer waits for two consecutive bottom-row draft observations at the
requested dimensions; the journey harness is unchanged. These observer repairs
are separate from the production wrapping correction.

All three visual questions receive State, Intent, Honesty and Craft answers,
with an agent verdict of `PASS_WITH_FINDINGS`. Raw exit 4 remains
`REVIEW_REQUIRED`. Ten directly inspected ANSI cell replays cover the six sizes,
literal reader and settled restart; they are not OS screenshots. Short-screen
status visibility, repeated diagnostics and broader reference-level UX remain
open. Final repository summary checks are recorded separately with this draft.

## Concise operational labels

Startup and tool-launch messages use the existing compact target label. Launch
copy derives it from the run's captured target binding. Tool evidence is not
rewritten: canonical session/run targets and the exact raw result remain the
source record. The formatter uses platform path components, preserves root and
parent-path identity, and labels empty input unknown. Unix literal backslashes
remain part of a name. Windows-specific checks are present but not run on this
host.

All 320 focused TUI checks, three serial performance checks, TUI Clippy,
workspace build and formatting pass. The baseline formatter fails the empty
target regression, and the earlier native transcript fails the new concise-copy
check while retaining its original canonical bindings. Current native and final
summary evidence is recorded under
`scripts/devex/artifacts/concise-target-logs-20261026/`.

## Compact-header followup

When vertical room permits, compact headers use two bounded rows. Orientation
stays on the first; cost, index freshness and model remain whole fields on the
second. Cost has priority, including an unknown-metering label. Overlong model
fields are omitted whole. Displayed models retain their authentication qualifier.
An ellipsis indicates omitted detail when it fits. Short content areas retain
the existing one-row order and stage behavior. Logs replaces a blank header
row, preserving its reading height.

Two regression failures established the original clipping. Broader renderer
checks then caught the first implementation's changed short-area order; that
behavior is restored. Current followup verification is recorded separately in
`scripts/devex/artifacts/compact-header-20261026/`. Earlier J373 evidence below
belongs to its recorded source cut. Overall reference-level UX remains open.

Native review also caught partially painted Map-to-Logs frames. The first J374
run has 41 machine passes but fails visual review; the second retains a hard
machine failure even though its settled restart is coherent. The terminal now
wraps each paint in Crossterm synchronized output, closing the update even when
painting returns an error. Focused writer tests protect both paths. Navigation
checks wait for the completed Logs composer and retain a second settled frame.
The original harness remains unchanged. These captures and protocol checks
remain separate evidence; terminal support determines synchronized presentation.

The rebuilt source passes 332 focused TUI checks and three serial performance
checks, plus TUI Clippy, workspace build, formatting and the risk proxy over 99
changed code files. Warm internal 120x36 fixtures measure input-to-paint p95 at
4.5 ms, prompt single-key p95 at 6.3 ms and prompt-burst p95 at 8.7 ms, within
their 50/25/50 ms limits. These timings exclude real terminal and model latency.

Final J374 records 49 machine passes, zero failures and fourteen authenticated
no-color captures. Its 6,690 inputs and thirteen frozen programs remain unchanged
during execution. Native SHA-256:
`c6609dd007eb5f3927dcac94d6f3c877fdc103c108b38314150ad87738ed3b4b`.
Both visual questions receive State, Intent, Honesty and Craft answers with an
agent verdict of `PASS_WITH_FINDINGS`. Raw exit 4 remains `REVIEW_REQUIRED`.
Eight directly inspected ANSI cell replays cover the six viewport sizes and a
240-column settled restart view. The same source, Git index, snapshot
and single auxiliary result survive restart without a provider call or accepted
Map. Logs density, diagnostic chrome and short-screen status visibility remain
open. Final summary verification is recorded separately with the draft.

## Original status correction

The wide header read an obsolete `present` state. Current, stale and unverified
repository indexes therefore appeared as `ctx:not built`; the compact header
already had the correct labels. A first index build also appeared unbuilt.
Both layouts now use the same existing view-model caption. An index remains
separate from accepted Map context and does not advance the investigation.

Two focused regression tests fail on the old wide renderer and pass with the
shared caption. They cover current, stale, unverified, malformed and first-build
states. The method is visible only within the crate; no artifact, model policy
or public interface changes.

The identity guard required the obsolete `KUZUSHI route:<m>` comment. It now
checks the actual compact brand expression beside its existing full-header
brand check. The failing summary and focused docs retry are retained. This
validation-only change follows the native run and changes no runtime input.

Routing labels now say `Commands`, `Module selected`, `Plan`, `Run active` or
`Agent active`. Desktop-notification diagnostics say `Desktop alerts unavailable`
or, in compact chrome, `No desktop alerts`. Their state predicates and in-app
notices are unchanged. Component counts use singular `manifest` and `lockfile`
when the corresponding count is one. Plain-output truncation recognizes the
structured status prefixes without treating arbitrary command text as chrome.

All 61 distinct focused TUI checks pass. The retained test logs distinguish
the two actual regression failures from test-setup compilation failures and a
stale assertion for the old routing label. TUI all-target Clippy, workspace build,
format and the risk proxy pass. Final repository summary checks are recorded
separately with this draft.

The owned fixture uses staged metadata in an unborn Git repository. It builds
a real four-file index in the native journey; it creates no commit, executes no
target program and needs no model. Source hashes, the exact fixture index,
canonical run count and absent investigation activity are checked across restart.
The separate two-file CLI preflight completed with unchanged source.

J373 records 33 machine passes, zero failures and thirteen authenticated live
captures. Thirteen frozen programs and 6,688 source inputs remain unchanged
during execution. Native SHA-256:
`b9e533dcd10981d2a628a3dd1094a70137912eb69d359b6a1870d3dd4ad5bb4f`.
All captures use no-color with no color SGR codes. They cover the existing six
viewport sizes plus a 240-column view of the full header. Restart retains the
same snapshot bytes and one completed auxiliary run.

Both visual questions have State, Intent, Honesty and Craft answers, with an
agent verdict of `PASS_WITH_FINDINGS`. The raw harness exit 4 remains
`REVIEW_REQUIRED`. Eight inspected images replay ANSI cells using Menlo and a
chosen background; they are not OS screenshots. The index caption disappears
from compact chrome at 96 and 80 columns, and the header is omitted at 60 and
40 columns. Drafts remain readable. Long repeated paths and dense phase chrome
remain visible shortcomings; these captures establish no broad UX acceptance.

Evidence: `scripts/devex/artifacts/operator-status-copy-20261026/`.
The earlier 33 staged files remain exact and unapproved. This followup is also
uncommitted. It does not establish overall reference-level UX or close the
remaining product acceptance work.
