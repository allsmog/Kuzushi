# Pack inspection audit, October 9, 2026

The audit covers `pack:lint` and the retained `pack:suggest-shards` adapter.
It uses owned inert source files, pack metadata, real prepared dispatch,
retained run receipts and the native tmux shell. No model request, scanner,
target-source execution, reproducer, vulnerability patch or source commit runs.

The shard suggester already derives candidates from the shared bounded
repository inventory. Its ten focused tests cover small whole repositories,
loose parent files, non-source membership, the eight-candidate bound, oversized
leaves, quoted draft paths, partial inventory and refusal to materialize scopes
from incomplete inventory. This audit preserves that implementation. Its draft
is the legacy campaign shard format, separate from accepted modern scope
proposals. Exact dispatch remains available as Compatibility; default discovery
uses `pack:scopes` and optional budgeted `pack:suggest-scopes`. Neither the
suggester nor the linter owns a completed Map result.

The linter previously read whole documents and recursively traversed shard
and prompt directories. The file-count cap did not bound empty directories,
symlink cycles, model-directory enumeration or read bytes. Failed directory
reads disappeared from the result. One inspection now shares explicit limits:
100,000 walk entries, 8 MiB per document and 64 MiB document reading by default.
The entry and per-file ceilings equal those defaults; total document allowance
can be explicitly raised to 512 MiB. All limits are positive descriptor options.
Shared preparation and the executor perform input validation.

Directory traversal is iterative, excludes symlinks and non-regular entries,
checks containment and cancellation, and bounds retained file lists and visited
directories by the shared entry allowance. Each visited root and processed
entry consumes that allowance. Checking directory exhaustion can retrieve one
lookahead entry before the limit stops processing; it receives no file inspection.
Hidden shard entries remain intentionally
excluded and their count is disclosed. Sibling model documents retain the
existing direct-directory contract; prompt files are checked for destination
shape, not content. The 5,000-file per-shard cap remains, with lower-bound
count disclosure. Enumeration order and the subset retained at a limit are not
claimed identical across platforms.

Exact document reads reject oversized or invalid UTF-8 content. The adapter
reads at most its reservation and verifies the open file's size before and
after capture; it does not need an extra truncation-probe byte. Successful
reads consume captured bytes; failed reads conservatively retain their maximum
reservation. Invalid UTF-8 also consumes the actual captured bytes. These are
local IO allowances, not provider spending. Repeated document references can
consume the allowance again. Coverage reports entries, captured/reserved bytes,
hidden entries, omitted checks, cancellation and up to sixteen reason samples.
An omission count is not a count of all unseen files. Schema errors retain a
failed result; incomplete checks without schema errors return partial. A missing
active target explicitly leaves shard existence/count checks incomplete.

Read paths accept the operator's root alias as well as the canonical root,
while retaining the shared bounded file opener's containment policy. A regression
caught macOS `/var` versus `/private/var` rejection and verifies the correction.
Dangling or non-regular declared documents reach the bounded reader and are
reported as unavailable rather than silently classified as missing. Target
metadata failures retain explicit omitted checks. Diagnostics use pack-relative
document names where possible. Public
`lint_pack` and legacy draft/artifact contracts are preserved.

Native narrow reading also exposed excessive path repetition and two input
ownership gaps. The expanded transcript now yields control/modified keys to
the shell and leaves a foreground scope panel in control. Its origin, draft,
paste and page behavior remain covered. The scope footer now fits the complete
Enter menu and finite-plan actions at 40x12. The expanded transcript names
Ctrl+G palette and does not offer expansion while already expanded.

Evidence root: /tmp/kuzushi-pack-audit-20261009.
Thirteen linter checks, six shared-dispatch checks, ten shard checks, six reader
checks and one six-size scope/plain-output check provide scoped evidence.
The deep walk reaches 300 directories on a 64 KiB stack. Tests also cover
cancellation, shared entry limits, invalid options, failed reservations,
invalid UTF-8, cycles, external membership, malformed documents and missing
targets. Catalog receipts verify 109 tools, 99 default tools, exact Compatibility
dispatch and auxiliary phase ownership. The first failed assertions and native
runs remain retained. Native headless complete/partial/failed outcomes agree
with shell receipts on the same fixture. CLI exit codes retain the existing
batch contract: completed 0, partial 4 and failed 3. The initial headless
assertion incorrectly expected zero for partial; its receipts remain retained.

Final J143: /tmp/kuzushi-pack-audit-20261009/final-tui/20261009-090918/J143.
It records 25 machine passes, no failures, six operator questions and 24
live capture pairs across all six sizes. Every capture authenticates native
SHA-256 4a17555b91d1cff62555246b882210dcb46fe3a5ef28a2b68195d9a3255be6f9.
Text and ANSI projections agree. Actual 40x12 paging exposes the 16/16
reservation; Ctrl+G opens the palette and Escape restores the same page.
Scope controls remain complete at 40 columns. No-color restart retains the
unaccepted draft, missing Map, inspection receipts and unchanged source.
Raw REVIEW_REQUIRED remains distinct from agent-scoped screen judgment;
operator approval remains false. The tool matrix now has scoped evidence for
48 of 109 tools, with 61 unassigned. This is not complete module qualification.

The workspace build and focused risk check pass. The first architecture
wording failure and resource-file size failure remain retained. The directory
walker and its tests now have their own module. Final ten-gate summary verification passes in
/tmp/kuzushi-pack-audit-20261009/verify-final.json. Its dirty-worktree flag
remains explicit; passing commands cannot establish one clean Git tree.

Remaining: adversarial filesystem replacement during inspection, interruption
inside one bounded read, OS handle exhaustion, large multi-product pack
performance, all option combinations, cross-platform behavior and model/scanner
usefulness remain unqualified. No complete repository coverage, full TUI parity,
module promotion or retirement is inferred. All broad milestones stay open.
Work is uncommitted on main.
