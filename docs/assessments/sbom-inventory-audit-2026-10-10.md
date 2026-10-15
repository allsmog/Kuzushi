# Dependency inventory and its Components consumer

October 14 follow-up: [shared input allowance and capture](sbom-source-budget-2026-10-14.md)
adds an aggregate byte ceiling, reuses captured inputs across parser stages and
tests cancellation between read chunks. The older limitations below describe
the October 10 checkpoint; authenticated source revisions and concurrent run
ordering remain open.

The real dependency inventory produced declared and resolved components, edges,
CycloneDX and SPDX, but its descriptor assigned Scan phase completion to an
inventory-only result. Its shell consumer had a separate defect: repairing a
manifest and running `sbom-scan:scan` left Components showing the target
inspector's previous error. Shared dispatch and TUI tests reproduced both gaps.

## Supported behavior

`sbom-scan:scan` is now auxiliary Map work with `phase_result: false`. It has
the same tool id, declared inputs, runtime-free executor and report fields.
Neither findings nor workflow completion follow from dependency inventory.
The DAG's `context:build` dependency is display metadata, and actual prepared
dispatch succeeds without a context snapshot. There is no SBOM discovery
task in SAST orchestration.

Completed reports update the matching active target's facts directly. A late
target-inspection response in that generation keeps the completed report;
an explicit new inspection clears the override. Structured failures and
malformed completed receipts clear current package claims and show the cause.
Canonical earlier run receipts remain available. Foreign-target results cannot
replace this display, and completion preserves focus, input and cursor.

Components stays reachable when collected target facts describe an inventory
failure or an empty repository. A tool-sourced report labels source freshness
as unverified. Restart recollects repository facts rather than treating a saved
report as evidence of current source bytes.

The audit also exposed two narrow-terminal defects. Gallery Page Down used a
fixed ten-row jump while 40x12 displayed two body rows. It now uses the visible
body after three pinned header rows and the position row. Component failure
text wraps before viewport selection. At compact gallery heights, the error
badge, dismissal hint and Logs link occupy one row so the document stays
readable. The view-model layer owns that layout decision. The footer exposes
`PgUp/PgDn page`, including at 40x12.

## Resource and scope evidence

The selected target bounds this filesystem inventory. A shared-dispatch test
selects a child target while an invalid parent manifest and symlink cycle remain
outside it. This adapter accepts a target root, not an exact-file discovery
scope. Its bounded walker fails at more than 100,000 entries, 50,000 regular
files or 64 directory levels. Manifest and lockfile reads are contained,
exclude symlinks and have a 64 MiB per-file cap. Actual oversized-file and
65-level tests return failures without fabricated components. Failure receipts
now retain underlying causes, including the size limit.

Those caps are finite operation limits, not one shared inventory snapshot or
an aggregate read-byte ceiling. Parsers reread files in separate stages. Ignored
directories and unsupported formats remain outside the package inventory.
The report does not authenticate a Git SHA or source-content identity and
cannot establish complete repository coverage or fix status.

## Verification

Evidence root: `/tmp/kuzushi-sbom-audit-20261010`.
Final journey: `verified-reading-tui/20261010-011405/J158`.
Native SHA-256:
`0e17db63ff319461bff291e8ae17a5a8a31e413aa6ba028f05939b8893fa7bbb`.

Focused suites have 135 distinct passing tests: 75 Core and 60 TUI. They cover
actual prepared dispatch, report/export consumption, malformed input, missing
context, cancellation before execution, depth, per-file size, containment,
symlink exclusion, late fact delivery, target switching, failed and malformed
receipt application, preserved input, narrow rendering, page geometry and
footer controls. The existing engine suite exercises 69 parser/format cases;
that does not certify every dependency ecosystem or malformed-input shape.

J158 has 40 machine passes, zero failures and 43 authenticated live text/ANSI
captures. Wrapper and native identity, requested/actual dimensions and live
alternate-screen ownership are checked across six viewports. Twelve 40x12
pages expose the full freshness and version text; six more expose the complete
failed-rerun cause and recovery command with the error badge still visible.
The visible page hint and a 48 ms draft echo are observed narrowly. No-color
restart retains emphasis without color codes.

Three successful runs and one malformed-manifest failure retain their actual
canonical results across explicit source revisions, repair and restart.
Fixture checks confirm unchanged source apart from planned inert edits, no
package-script execution, zero provider reservations, findings, discovery jobs
and phase attempts. A separate plain native `run` against an owned manifest
also produces a real report and preserves source under the same final binary.
Five scoped assistant screen judgments remain separate from raw
`REVIEW_REQUIRED`, operator approval false and overall TUI acceptance.

Workspace build and the CRAP-risk proxy for 593 changed code files pass. All
ten repository summary gates pass after the boundary repair. The copied
receipt is `repository-summary-receipt.json`; its dirty/drift metadata includes
the initial dirty worktree and changes made during verification, and does not
establish another writer. Six final documentation contract checks also pass.

Earlier attempts are retained under `tui`, `verified-tui`, `observed-tui`,
`final-tui` and `reading-tui`. The first two timed out because the navigation
helper closed the gallery and the completed receipt was hidden by the Map
origin. Later machine-passing attempts exposed the skipped narrow rows and
error banner that consumed the document. Those observations drove the fixes;
their machine results do not retroactively establish visual acceptance.
The repository gate also rejected direct shell-state reading from the renderer;
the rule now comes from the existing view-model layer.

## Remaining acceptance

This increment qualifies one inventory action narrowly. It changes no module
maturity and retires no module. Authenticated SBOM source revisions, aggregate
inspection limits, concurrent inventory-run ordering, cancellation during a
large read, every ecosystem and every interface remain unproven here.
Full live investigations, the remaining module audit, monorepo acceptance,
context learning and complete reference-product TUI parity remain open.
Work remains uncommitted on main, and all nine broad delivery milestones stay
unchecked.
