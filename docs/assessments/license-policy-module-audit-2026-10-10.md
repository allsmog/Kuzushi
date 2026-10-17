# Bounded license policy and durable review

Actual prepared dispatch reproduced four supported-path defects. Oversized
license text became a completed clean-looking result, traversal accepted a
65-level tree without a guard, analysis artifacts generated header-policy
findings, and a symlinked license counted as present despite no inspected text.
The initial integration suite had two passes and four failures.

## Implementation and phase contract

The license engine now obtains one bounded regular-file inventory and derives
manifest, root-license and header candidates from it. It excludes symlinks,
build directories and `.kuzushi` state. Traversal fails above 100,000 entries,
50,000 files or 64 directory levels. A single root-file selection replaces the
extra root directory read, and the second recursive source walk is removed.
Manifest order is preserved by target-relative path sorting.

Reads are contained within the selected target. The existing 8 MiB manifest,
2 MiB license and 64 KiB header limits remain. License-file read errors retain
their causes and fail before findings persist. Header inspection considers
complete lines only: an incomplete prefix cannot establish header absence or
produce a cut-off identifier. A complete early identifier remains usable
before an uninspected remainder. Cancellation and pause checks occur during
traversal and between inspected files/stages.

`license-scan:scan` remains Scan work because it produces actual policy signals.
Its findings stay `signal_only`; tool/rule ids, fingerprints, options, aliases
and report fields are preserved. It needs a workspace and findings store,
without a model or context snapshot. Source hashes now come from the existing
shared source-snapshot guard. Results retain `snapshotHash` and `treeHash`, and
post-run source failure preserves output as partial. Those pre/post source
checks perform separate IO, and manifest parsers still reread files. The engine
inventory is not a total inspected-byte or latency ceiling.

Actual SAST dispatch selects the same engine and persists its scoped findings.
A child-directory test excludes an invalid parent manifest, and exact-file
scope requests fail instead of widening. SAST publishes a completed engine
coverage receipt. At this checkpoint, direct tools retained source and findings
but lacked composite coverage and per-run observation snapshots. The later
[license reassessment increment](license-reassessment-2026-10-16.md) adds those
artifacts, explicit enabled-rule policy and guarded direct covered absence.
Its evidence remains scoped to the named cases.

The shell's prerequisite planner explicitly asks before indexing or reusing
context for SAST. Its observed approval/reuse actions execute this ordering;
the core/headless executor does not infer ordering from DAG metadata. The
fixture uses identical default header policy in direct and umbrella paths.
Automatic triage, verification and patch continuation are disabled.

## TUI evidence and corrections

The real fixture produces three observations of one missing-license signal.
The scripted Review controls save one deferral. After a planned inert source
edit, a completed SAST pass records covered absence while retaining the finding
and decision. JSON export preserves that history. An oversized license then
fails without producing new findings, and explicit repair plus cached-context
reuse permits another completed scan. Restart retains those outcomes.

Screen review exposed an additional reading gap at 40x12. Scrolling could hide
the selected identity, while pending-result actions displaced the paging hint.
The Review pane title now keeps the selected alias, and result controls retain
the visible reader paging action. Neither change alters focus, decisions or
attempt disposition. Empty and comparison pane titles preserve their guidance.

Evidence root: `/tmp/kuzushi-license-audit-20261010`.
Final native journey: `verified-reading-tui/20261010-021211/J159`.
Native SHA-256:
`59ba31d879262e7fbf017ed547864898f4427ba9df0a0c44a93986eb8dc2e7c7`.
There are 35 machine passes, zero failures and 30 authenticated text/ANSI
captures across 120x36, 160x48, 96x89, 80x24, 60x20 and 40x12. Narrow page
captures keep F-0001 and the paging hint visible. No-color restart preserves
emphasis without color codes. Six scoped assistant screen judgments remain
separate from raw `REVIEW_REQUIRED` and operator approval false.

Five successful scanner outcomes and one failed outcome retain three real
observations, one scripted deferral and the exported JSON report. Only planned
inert package/license edits change source. Provider reservations, investigation
work attempts and source execution stay zero. Runtime-free context indexing is
approved explicitly once, and cached reuse is a separate visible decision.
This is ordinary tool execution, not finite-campaign-dispatcher evidence.

Focused verification has 153 distinct passing tests: 62 Core and 91 TUI. The
Core set includes eight actual shared-dispatch contracts, 44 license cases,
four shared source-guard tests and six bounded-walk cases. TUI tests protect
the pane title and existing phase-result controls. Workspace build and the
risk proxy for 597 changed code files pass. All ten repository summary gates
pass; `repository-summary-receipt.json` preserves the current receipt. Initial
dirty state and edits during verification contribute to its drift flag and do
not establish another writer. Final documentation checks follow this update.

Earlier failed native attempts remain under `tui`, `source-tui`, `coverage-tui`
and `prerequisite-tui`. They exposed the missing direct source binding, the
absence of composite coverage, and explicit prerequisite approval/reuse that
the first recipes omitted. The first recipe also expected an engine label that
was below the visible viewport. The earlier machine-passing run under
`verified-tui` exposed the narrow identity and paging-hint gaps during screen
review; machine success alone did not close reading acceptance.

## Limits and remaining acceptance

These are real local scanner observations on owned inert package metadata,
not model-generated findings or vulnerability-quality evidence. The source is
unversioned: exact content references are exercised, with no Git SHA transition
claim and no new commits. Scripted human-decision controls test persistence;
they do not establish operator verification or legal interpretation.

License recognition is heuristic. Header comparison still uses the first
declared manifest in path order; mixed-license monorepos require component
targets and owner review. Aggregate read limits, cancellation during a large
read, every supported ecosystem, broader policy/scope parity and full live
investigation acceptance remain open. No module is promoted or retired. All
nine broad delivery milestones remain unchecked, with work uncommitted on main.
