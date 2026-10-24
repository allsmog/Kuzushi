# Local architecture corrections

The context copy editor previously offered narration and question answers only.
An operator could inspect a mistaken component role or flow endpoint but could
not correct it through that editor. The same inactive-copy workflow now supports
component names, roles and trust zones, flow descriptions and existing-component
endpoints, and boundary names and descriptions.

Shared core metadata supplies the fields, constraints and choices to the TUI.
Roles use the three supported canonical values. Endpoints use unique existing
component IDs within the edit limits, preserving literal spaces, slashes and
tildes. Unsupported, ambiguous, empty and over-limit choices are excluded.
Names and zones require nonempty single-line text. Existing limits remain
64 edits, 16 KiB per value and 2 KiB for the copy name. Flow fields share their
endpoint choices instead of copying the component catalog for every flow.

`threat-model:revise` retains its exact-reference and pointer/text input shape.
The original context, active context, IDs, evidence and source/scope binding stay
unchanged. Saving records operator provenance and removes the old verification
stamp from the new copy. It neither accepts Map nor starts discovery. Model text
regeneration keeps its original narration-only allowlist; choosing an
architecture field cannot open that planner.

The TUI separates choosing, applying to the local draft, reviewing and saving.
Paste and Ctrl+S cannot apply a choice. Tab opens its complete value and retains
reading position when returning through the list. Paging uses the rendered
body dimensions and clamps at both ends. Single-line fields reject multiline
paste without changing their draft. Value errors lead with the actionable cause.
Choice cards and single-line forms fit their content, keeping controls close to
the question on tall terminals. Long details remain bounded and scrollable.

## Verification

Evidence is under `scripts/devex/artifacts/context-architecture-edits-20261023/`.

- 23 Core context-edit checks pass, including prepared dispatch, unchanged
  parent/active context, malformed/protected inputs and lock-wait cancellation.
- Three registry audit contracts pass. The broader TUI context suite has
  443 passes. After visual layout corrections, all 22 focused edit checks pass,
  including complete literal-value reading, caret/draft preservation, paging
  and nearby controls at all six sizes. These suites overlap.
- Workspace build, Core/TUI Clippy, CRAP-risk proxy and all ten repository gates
  pass. Final dirty receipts are separate from the clean signed receipt.
- Final J344 has 46 machine passes, zero failures, 35 captures and four pending
  operator judgments. It creates one inactive copy with exactly three reviewed
  edits, inspects the parent comparison, binds it to three unstarted jobs and
  restores that exact copy after no-color restart. Source hashes, original
  objects, active context, provider reservations and finding decisions remain
  unchanged. No provider request or target-source execution occurs.

The final native product SHA-256 is
`d0ffaf2a1e806cec02b62d0179ae6d4b1a1ccd21a481a9509fa7f98404f76ca6`.
J344 attempt 5 freezes 6,427 repository inputs and 13 executables, unchanged
through terminal exit, on main after `5a35a06271`. Its terminal receipt, program
and source manifests, owned fixture checks and capture provenance are retained.

Fifteen final ANSI cell replays were visually inspected: all six role-picker
sizes, compact details, blocked paste, canceled choice, single-line rejection,
flow details, review, saved-copy inspection and parent comparison/restart.
The small forms remove the large blank space observed in earlier captures;
the 40-column surface keeps its controls and full-value reading path. Review
shows all three actual before/after changes and the inactive-copy boundary.
These are Menlo 15 replays with a chosen dark background, not OS screenshots or
formal operator endorsement. The four operator judgments remain pending.

## Retained failures and scope

Attempt 1 sends navigation before private checkpoint recovery completes and
retains five passes and one timeout. An explicit editor-ready wait fixes the
journey. Attempt 2 retains 37 passes and one timeout after a Back/Select key
burst leaves comparison open. The journey now uses its visible `a use in study`
action directly. Attempt 3 has no machine failure but exposes an oversized
three-choice dialog during visual review. A red regression reproduces distant
controls at 60x20; the content-sized layout passes. Attempt 4 verifies the role
card but exposes the full-height single-line form, corrected in attempt 5.
No failed attempt is removed or counted as passing, and the original harness
is unchanged.

The catalog stays at 118 visible tools and 81 Core defaults. Only revision-edit
description/help metadata changes; its descriptor digest is
`sha256:a5b68aa43ed5eece5f11b2c1765d6c95eb1d86ff12d6895fbcd6881253b6a285`.
Existing artifacts require no migration. Reprepare unstarted revision-edit jobs
when their descriptor differs. No maturity promotion or module removal occurs.

This increment edits existing architecture fields. It does not add/remove graph
members, edit boundary membership or establish architectural truth. The fixture
is explicitly labeled; it proves local corrections and downstream plan binding,
not discovery precision or useful model semantics. Live experiment consumption
remains 16 cumulative with no allowance left and unknown dollars. The five
broader delivery items remain open.
