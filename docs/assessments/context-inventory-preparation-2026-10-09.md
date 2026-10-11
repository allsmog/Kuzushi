# Inventory-backed context preparation

Context sampling now projects the same bounded repository inventory used to
assemble deterministic repository context. It no longer performs a separate
directory walk. This closes a duplicated traversal and cancellation gap;
source provenance and manifest inspection remain separate IO.

## Behavior and operator contract

`context:build` and hidden compatibility `context-lite:index` retain their
dispatch paths, names and sample aliases. Shared descriptor preparation accepts
`sampleLimit`, `limit` and `sample_limit` in the integer range 1 through 2000.
Invalid values fail before publication, rather than being substituted or clipped.
The default remains 200. Samples sort by path depth, then path, preserving loose
root files before deeper candidates. Counts and sample membership come from the
recorded inventory rather than an independently traversed tree.

The existing inventory supplies the 100,000-entry, 512 MiB inspection and
256 KiB per-file inspection caps, iterative filesystem traversal, symlink
exclusion, containment, progress, cancellation and partial receipts. Git
enumeration includes tracked and staged files but excludes untracked source.
Ignored and generated paths can remain outside filesystem enumeration.
Cancellation observed before or immediately after inventory preserves the prior
snapshot and does not proceed to inference or publication.

The Context reader separates source freshness from inspection extent. It shows
enumeration, sampled and enumerated counts, exact caps, recorded omissions,
partially inspected files and partial inventory status. Missing or malformed
inspection metadata is unknown, not zero. Additive file-index fields identify
enumeration and sample order. Older snapshots remain readable.

Long values and recovery commands now wrap. The first native audit exposed
Page Down skipping ten lines in a five-line body at 40x12. Context paging now
uses the actual rendered body height. It preserves the input draft and does not
skip unread rows when lower chrome changes the available space.

## Regeneration recovery

A broader regression exposed a mismatch between inactive text regeneration and
Map result ownership. The saved draft is valid recovery evidence but cannot
directly establish a Map checkpoint. Shared campaign dispatch now names the
required next action: compare the draft, save an exact checked revision through
`threat-model:verify`, then review the checked reference as Map. The shell keeps
the selected draft and explains this path without dispatching a forbidden handoff.

The integration test consumes the actual regeneration result, recovers its exact
parent/run/field provenance, refuses direct Map, records a runtime-free check,
and authenticates that checked revision in pending Map. It verifies one provider
request through an intercepted offline runtime, unchanged active context and
protected review capacity. This is lifecycle evidence, not live text quality.

The broader TUI suite also found an old test expecting raw failure-context JSON
in the transcript. The test now verifies the bounded readable receipt, its cause
and detail action, and the complete persisted failure context. Production
failure presentation was not changed for that test.

## Verification

Evidence root: `/tmp/kuzushi-context-inventory-20261009`.
Final native journey: `verified-tui/20261009-224501/J156`.
Native SHA-256:
`5c209fde33fa67356f2e52612c637e94d391eaf9643e3756df5e717cae206d28`.

J156 records 19 machine passes, zero failures and 29 authenticated live text/ANSI
captures. All captures identify the installed `kz` wrapper, the exact current
native binary, matching requested/actual dimensions and live alternate-screen
ownership. It covers 120x36, 160x48, 96x89, 80x24, 60x20 and 40x12, followed by
no-color restart. Restart ANSI retains emphasis without color codes.

The owned fixture has two staged source files, one untracked source file, and
one file exceeding the inspection cap. It checks sample membership, tracked
enumeration, exact limits, partial content, byte-identical retention after bad
input, a planned inert source edit, stale-slice refusal, explicit repository
rebuild and exact restart recovery. Twelve bounded narrow page captures expose
every receipt value and recovery command. It runs no model, scanner or target
source. Provider reservations, investigation work, findings and decisions remain
empty. Git initialization and staging create no commits or outbound work.

Four scoped assistant screen judgments remain separate from raw
`REVIEW_REQUIRED` and operator approval false. The first native run remains
available with weaker waits and the paging defect; only the final stronger run
supports the repaired paging claim. Compile failures and test failures are
retained in the evidence root.

There are 540 distinct passing focused tests: 278 Core and 262 TUI. They include
shared prepared dispatch, sample aliases and bounds, real downstream Map
consumption, deep trees, symlink cycles, entry/byte caps, cancellation, Git
membership, unknown receipt states, context ownership, wrapping, paging and
regeneration recovery. Workspace build and the risk proxy for 583 changed code
files pass. All ten repository summary gates pass. The copied receipt is
`repository-summary-receipt.json`; dirty/drift metadata includes the initial
dirty worktree and does not establish concurrent edits. Final documentation
contract checks follow this evidence update.

## Limits and remaining acceptance

Inspection metadata describes recorded work; it does not authenticate artifact
truth or establish complete repository coverage. Manifest and provenance reads
are outside the inventory byte allowance. Cancellation is cooperative and
cannot interrupt an arbitrary blocked filesystem call. This increment does not
prove total IO latency, large-repository performance, live enrichment quality,
architectural scope division or complete CLI/shell/scan option parity.

The fixture has an unborn Git repository and tests tracked membership rather
than real commit transitions. Existing SHA/source applicability guards remain;
no finding-fix verdict follows from this context work. The unused private
sampler and its unused filters were removed after caller inspection. No public
module was retired or promoted.

Qualification remains 55 of 109 tools, with 54 unassigned. All nine broad
delivery milestones remain open, including full live investigation, remaining
module functionality, integrated monorepo acceptance and complete reference
product interaction quality. Work stays uncommitted on main.
