# Bounded general context and recorded Map review, October 23, 2026

General threat-model synthesis used a separate breadth-first filename walk. It
materialized each directory listing without the canonical entry/byte limits or
cancellation and silently listed only a prefix. The prepared prompt now reuses
the canonical bounded repository inventory. Source-code capture and filename
projection share that inventory rather than walking again. Symlink and containment
policy, cancellation, progress and existing inspection ceilings remain shared.

The prompt carries one bounded structured receipt with the exact listed paths,
ordering and digest, enumerated/listed/unlisted counts, enumeration completeness,
entry/byte ceilings, omission examples, partial inspections and membership policy.
The filename receipt itself has a 512 KiB ceiling. Indexed enumeration excludes
untracked/ignored paths; the filesystem fallback explicitly says Git ignore rules
are not evaluated. Neither mode claims complete repository coverage.

System code stamps this input under `provenance.repositoryInventory`, schema 1,
with purpose `base-synthesis-filename-list`; tool data also exposes the receipt.
Refine does not build a filename synthesis prompt and records no new receipt in
tool data. It retains the earlier base-synthesis receipt in document provenance.
Legacy contexts remain readable. The context summary presents architecture first,
then the counts, limits and exclusions. Exact provenance remains in the saved
revision and its JSON reader.

Two additional regressions were reproduced before correction. Source collection
rejected a large unselected lockfile because content-prefix truncation was treated
as incomplete enumeration. Complete enumeration now permits bounded partial
content inspection; incomplete or unknown enumeration still refuses source-code
selection. A zero-call refine previously stamped a newly prepared filename list;
it now retains only its historical synthesis receipt.

The native route also exposed a real navigation defect. With Activity auto-open
disabled, `m` recorded Map but the visible `m Map` control could only dispatch
again. It now opens the authenticated current cached Map with no new run, using
the same presentation and input-ownership guard as foreground completion. Existing
context review shares this path. Background caching still never takes focus;
acceptance and context activation remain separate operator actions.

## Current evidence

Evidence is retained under `scripts/devex/artifacts/general-context-inventory-20261023/`.
Final J347 is `native-attempt-6/native/J347/20261023-222458/J347`: 42 machine
passes, zero failures, 40 capture pairs and three pending operator judgments.
Raw exit 4 remains `REVIEW_REQUIRED`. All 6,459 source inputs and 13 frozen
programs stayed unchanged during this sequential journey on dirty main at
`f744320dc3ed4cf0ded3122ebbc012e8d6e58479`. Native SHA-256:
`6ec35c60b70ea8f48a5589ebb71cddb17d91de2e1c6a65c5043bf80f97b6b096`.

The owned fixture has 62 tracked files, a literal Unicode filename, an ignored
file and a lockfile beyond the per-file inspection ceiling. One intercepted
GPT-5.5 medium request receives exactly 40 listed paths and the two real grounded
artifact rows. The saved receipt equals the submitted receipt. The supplied
response labels its source-only reading annotation and establishes no runtime
entry point, deployed architecture or vulnerability. This is transport and
workflow evidence, not live inference quality.

The operator inspects the inactive revision at all six viewport sizes, records
and accepts Map, selects one linked `app.py` path, approves three local installed
scanner passes under the same allowance and separately launches them. Three raw
policy observations consolidate to one identity. One human deferral, JSON export
and no-color restart preserve the finding and spending. The shared one-call cap
is not increased. Independent checks confirm four fixed work attempts, one settled
provider reservation, three producer observations, one decision, one Map handoff
run, unchanged 63 source files including the ignored file, and unchanged globally
active context. No target source executes.

Seventeen distinct ANSI cell replays were inspected across all six sizes,
including narrow paging, Map, approval, study completion, Review, export and
restart. They use Menlo 15 and a chosen dark background, not OS screenshots.
Architecture precedes receipt detail; filenames do not imply inspected source,
recurrence stays separate from proof and the allowance remains visible.

The final focused evidence comprises 681 Core threat-model checks, 446 TUI
context checks and seven inventory presentation checks. The enhanced zero-delta
history assertion also passes. Workspace build and Core/TUI all-target Clippy
with warnings denied pass. Repository summary verification is recorded separately
in the explicit dirty draft receipt. Clean signed publication receipts are
preserved; this draft does not authorize publication.

Earlier native attempts retain the fixture ignore-policy failure, mismatched
fixture home, incomplete response coverage, redraw capture race and missing
fixture context link. The one-call guard stopped an attempted gap-fill request.
The recorded Map navigation failure has a focused red regression before its fix.
Four requests are intercepted across the retained native attempts; zero live
requests are added. Cumulative live experiment use remains 16, with no allowance
remaining. Broad module usefulness, generation quality, formal operator acceptance
and reference-product parity remain open. The complete product goal stays active.
