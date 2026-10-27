# Per-case historical spending scenarios, October 8, 2026

Scope-study and context-matrix approval now include the resource preview for the
exact frozen plan. Previously this step required the single-study receipt and
omitted both multi-case formats. Plans without calibrated evidence show their
fixed workload, maximum starts, available calls, protected Review allocation
and estimate uncertainty.

`campaign:study` declares `resourceBaselineCampaignId` as an optional shared
input. It selects one prior scope study or context matrix and cannot combine
with `baselineRunId`. Ordinary repetitions retain their existing named-run
path. The new option starts no work and grants no allowance.

The reader validates the prior finite plan, reads a bounded queue and considers
only its completed jobs. Each candidate requires the exact condition key,
authenticated child ownership, complete engine work and settled request
accounting. Changed source, context, scope, options, model or runtime withhold
calibration. Missing or malformed evidence records a limitation. Duplicate run
references cannot create additional samples. Named metadata inspection is capped
at 1 MiB per file and 32 MiB overall, with cancellation between jobs; existing
artifact authentication performs its own reads afterward. No repository walk,
model request, job delegation or repair loop is added.

Version 1 resource evidence is frozen inside the new plan and returned by both
receipt types. Every case records its conditions, planned passes, sample run
identities and observed per-pass request and price ranges. Scenario projection
includes every planned case and maximum attempts. An uncalibrated case makes the
full request total unavailable. Any missing complete price makes the full dollar
scenario unavailable. Historical ranges describe observations, not conservative
future bounds; neither dollar ceilings nor completion guarantees are inferred.
The durable allowance continues enforcing requests independently of the preview.

The TUI's Usage evidence row opens a selectable prior-study reader for multi-case
plans. It uses up to 100 already loaded campaign choices and preserves a named
selection outside that window. It supports detail paging, six viewport sizes,
cancel and exact selection. A changed choice invalidates work approval while
retaining scope, context, model, limits and spending. The chosen identifier and
frozen evidence survive prepared-plan recovery; file-group context generation
also retains it in the versioned return draft. Plain output remains exhaustive.
Loading campaign history directly from this picker remains a follow-up; the
current route uses the loaded Campaign deck and states that limitation.
The subsequent [bounded history increment](bounded-study-history-2026-10-08.md)
supersedes that limitation with direct background loading and explicit limits.

J133 is retained at
`/tmp/kuzushi-resource-study-20261008/tui/20261008-175432/J133`.
It records 23 machine passes, no failures and four human review questions.
Six actual native discovery jobs over two owned boundaries use fully intercepted
transport. Three complete samples per case yield a six-request scenario for a
new six-job plan. Dollar cost stays unavailable. Approval review separately
proposes 14 total calls, keeps the six existing commitments and two protected
Review calls, and discloses six remaining discovery calls. Cancellation and
no-color restart leave the original eight-call approval unchanged and the new
jobs unstarted. Source files remain unchanged. The native binary SHA-256 is
`16315f5234a01a751ea92c1cd69ec2bbde8a4c9fb2d1d53a44abfff4bae706d1`.

A separate native context-matrix draft under the same evidence root uses two
different inactive manual contexts. Both correctly remain uncalibrated against
the original context omission, without additional requests. An attempted matrix
combining omission with an imported context was rejected by the existing scope
control check; that restriction was preserved. A malformed empty DFD import was
also rejected. These retained failures establish no context or scanner quality.
The initial J133 setup refused uncovered integration files; the successful setup
explicitly covers integration and leaves its discovery unplanned.

Focused tests cover missing prices, unresolved accounting, workload limits,
immutable projection, bounded queue reads, source binding, draft invalidation,
picker paging and cancellation. Shared-dispatch scope planning also rejects
changed condition evidence. Raw exit 4 remains `REVIEW_REQUIRED`; scoped
implementation judgments do not grant operator acceptance or establish
reference parity. All transport is intercepted, all source is owned, and no
live inference or source execution occurs.

Live model usefulness, broader context-matrix TUI acceptance, direct bounded
history loading, complete per-tool validation and the full investigation journey
remain open. This increment does not close the broad delivery milestones.

## Current historical-usage qualification, October 24, 2026

J133 now reaches the current spending reader and allowance review again. Its
first attempt stopped in fixture setup: a direct Python SQLite read could not
open the checkpointed ledger. The shared read-only ledger helper returned the
six settled records from the same database. The fixture now uses that helper.
A second captured failure showed six planned jobs with zero attempts while the
journey waited for an obsolete job-count label. The journey now checks the
current label and navigates explicitly to the current Usage evidence row.

The renderer regression previously combined text from all viewport sizes.
It now requires the uncertainty text and final disclosure at each size,
independently, while preserving selection and the composer. The first stronger
assertion failed because frame borders separated wrapped words. The retained
final frame proves that the disclosure was visible. The corrected assertion
normalizes those borders and wrapping; no production paging change was needed.
All five focused picker tests and TUI all-target Clippy pass. The native journey separately pages the
40-column reader to its final disclosure and checks both final lines.

Final J133 records **25 machine passes, zero failures, seventeen capture pairs
and four pending formal operator judgments**. Thirteen ANSI cell replays were
inspected, including all six sizes, the detail tail, approval, cancellation and
no-color restart. These are terminal-cell reconstructions, not OS screenshots.

| Review prompt | Scoped judgment and evidence |
| --- | --- |
| Historical scenario and future limits | The reader shows six historical requests, unknown dollars, zero available discovery calls under the existing allowance, and a six-call shortfall. History is explicitly not a future upper bound. |
| Prior-study reading and cancellation | Selection and controls remain visible across all six sizes. The final disclosure is reachable at 40 columns. Cancel returns to the same prior study without starting new work. |
| Proposed allowance | Approval shows fourteen proposed total calls, two protected Review calls, six remaining discovery calls and six fixed jobs. Cancel preserves the original eight-call approval. |
| Restart | Public allowance reads retain revision one, the eight-call limit, two protected Review calls, six commitments, zero unresolved calls and the original approved work plan. The new plan's exact file digest and source files remain unchanged, with no new queue. |

The public allowance result also retains unavailable dollar completeness. The
fixture uses six intercepted responses for its completed baseline, three
matching passes per boundary. No live request, target execution, new allowance
or new discovery job follows from reading, cancellation or restart. Cumulative
live experiment usage remains sixteen; no live allowance remains.

Thirteen frozen programs and 6,527 repository inputs stayed unchanged during
the final journey. The executable SHA-256 is
`308a06045f19d2d5ae6455ad2f526927cf46a74a3c03522c7625ae519f5b6ea9`.
Evidence root: `scripts/devex/artifacts/historical-usage-current-20261024/`.
Earlier failed attempts, assertion diagnostics, public results and capture
provenance remain retained. The cold-history sibling uses the same unchanged
prepare/verify entry points; it was not run in this increment.

This correction changes tests and qualification evidence only. It leaves the
separately staged nineteen-file checkpoint intact. Formal operator acceptance,
live usefulness, broader history failures and full investigation qualification
remain open. No broader delivery milestone or module maturity changes here.
