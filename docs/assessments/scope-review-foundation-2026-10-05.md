# Source-bound scope review foundation

This increment implements finite scope data and a durable review boundary. The
monorepo operator journey remains incomplete. No TUI editing, model proposal,
scanner membership enforcement, or useful discovery quality claim follows.

`pack:scopes` declares create, read, edit, accept, and files operations in the
Rust descriptor. All dispatch uses the existing prepared boundary. It makes no
model requests and contributes no completed Map result. New version-1 artifacts
and optional strategy-queue references preserve existing manifests and tools.

Drafts contain at most eight primary scopes and an optional shared scope.
Paths are literal inventory members or directory prefixes, including bracketed
route names and spaces. Coverage exposes loose root files, overlap, exclusions,
shared context, and incomplete inventory. Exact totals accompany previews and
pages of at most 128 files. Shared context does not create discovery jobs.
Split edits must preserve the parent's inventoried membership. Invalid edits
leave the saved draft unchanged.

Source inventory is reused for an unchanged snapshot. Scope edits create
immutable revisions linked through the existing proposal queue and its lock.
An exact reference contains proposal identity, revision, and content digest.
Concurrent reviewers cannot overwrite a newer draft. Failed queue publication
leaves the old head intact; unreferenced content-addressed objects can be reused
on retry. Saved objects use bounded, contained, symlink-rejecting readers/writers.

Acceptance requires the current reference and source content/Git revision.
Uncovered inventoried files cannot be waived. Inventory limitations, overlapping
discovery, and exclusions each require explicit acknowledgement. Included files
absent from content identity are separately disclosed as `identityOmissions`
and must be excluded before acceptance. Source objects are checked against their
content-addressed digests, target fingerprint, and revision. Ordinary strategy
approval cannot accept boundaries or launch work. A study consumer must use
`load_accepted_scan_scope_proposal`; no study compiler consumes it yet. This gate
verifies that acceptance was committed in proposal history. New draft edits do
not invalidate an earlier committed acceptance, while orphaned acceptance after
a failed queue save cannot be consumed. History verification has a 4096-revision
read bound. These source checks do not determine whether a finding was fixed.

At this checkpoint, shared source identity had separate file/read limits from
inventory and a recursive traversal. The subsequent [source traversal
assessment](source-traversal-2026-10-05.md) replaces it with a bounded iterative
walk and verifies basic deep/wide and lock cancellation cases. Large-repository
performance and broader platform/crash evidence remain necessary. The preview/page budgets
do not cap that source work or constitute a strict dollar ceiling.

Focused evidence is under `.git/bounded-investigations/`. The recovery suite
covers draft edits, identity/coverage gaps, source drift, changed Git SHA with
identical files, cancellation, concurrent edits, failed publication, retained
history, digest corruption, and symlink refusal. Git commits occur only inside
isolated test fixtures. Native CLI evidence exercises create/read/page/rename,
exact acceptance, missing acknowledgement, stale reference, changed-source
refusal, historical read, and unknown-key rejection. No scan jobs or live
provider requests start. Workspace/quick receipts are recorded separately.

The initial `scopes` shell surface is implemented. It projects selectable
boundaries and coverage into responsive list/detail panels, with visible actions
for named split, merge, rename, scope/path exclusions, boundary questions, shared
discovery, whole repository and exact acceptance. Multiline forms use the shared
field editor, preserve the composer, and retain invalid or source-stale edits.
File membership is paged. Acceptance uses separate acknowledgements and starts
no jobs. The surface yields input and rendering to the exit confirmation.

J81 at `/tmp/kuzushi-bounded-investigations-tui/20261005-142100/J81/` records
23 machine passes and 14 separately judged passing text/ANSI captures. It covers
all six viewport sizes, actual 40x12 paging, multiline paste, split with a loose
root file, rename, concrete files, exact acceptance, changed-source refusal,
real exit and no-color restart. `manual-review.json` records capture hashes,
actual dimensions, native binary identity and the separate judgments. Raw
REVIEW_REQUIRED remains unchanged. Failed predecessors remain alongside it.
The fixture has an unborn Git repository; unavailable SHA remains explicit.
This is source-content drift evidence, not Git SHA transition evidence. Merge,
exclusion and parent dependency/question retention have focused shared-dispatch
coverage, but are not all driven in this native journey.

The final native CLI receipt has 12 passing cases, including path exclusion,
newer draft isolation and historical accepted reads. Focused checks record
35 core scope tests, 11 scope-named TUI tests (ten new tests and one existing
scope-selection test), two command-catalog contracts and ten paste regressions.
The workspace build and CRAP proxy passed for 212 changed code files. Quick
verification passed all ten gates at 2026-10-05T21:20:50.295Z in
`.git/bounded-investigations/scope-review-tui-quit-final-verification.json`.
That receipt records a dirty worktree and the verifier's conservative drift flag,
excludes full CI, and precedes this documentation closeout.

Accepted-context inheritance into scans, one budgeted model proposal, fixed
scoped study compilation, full boundary/dependency editing usability, large
inventory performance and real asynchronous cancellation/focus journeys remain.
J80 does not certify these additions. All nine implementation milestones remain
unchecked. No module is retired or promoted, and no full reference interaction
parity or complete investigation workflow is claimed.
