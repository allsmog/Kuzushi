# Investigation selection survives history refresh

The investigation browser kept row numbers when replacing disk snapshots. A new
campaign directory earlier in the list could silently select that campaign. An
edited unapproved plan could similarly move the selected job to another row.
Both failures were reproduced in focused tests before the repair.

Refresh now finds the previously selected campaign and job by their saved IDs.
The same item keeps its reader, scroll position, exclusions and composer draft.
If a selected item is unavailable, the browser leaves its old reader and names
the missing item with a selection action. Unreadable-directory diagnostics remain
visible alongside that notice. Switching targets clears the loaded campaign
history, selection, exclusions and trend presentation before loading the new
target. Matching IDs in different targets do not transfer that state.

The pure selection rules belong to `CampaignRouteState`; filesystem refresh
stays in the application path. There are no new tool options, persisted formats,
model choices, allowances or execution permissions. Frozen plan authentication,
dispatcher ownership and approval checks remain unchanged. Retaining a selected
ID does not authorize an edited plan.

## Verification

There are 118 distinct passing related TUI checks across serial runs. The broad
rerun passes 117 checks; its remaining linked-return fixture installed synthetic
history before selecting its target. The fixture now installs that history
after target selection, and its unchanged return assertions pass in the focused
rerun across all six sizes. This count does not imply one final 118-test run.

Five selection regressions cover earlier history insertion, job reordering,
missing campaign and job recovery, combined diagnostics and switching targets
with matching IDs. They also retain a nonzero scroll position, exclusions and a
Unicode-capable composer. Workspace build, TUI all-target Clippy with warnings
denied and the changed-code risk gate pass. Risk checks 43 production files in
the combined working tree. The summary receipt remains draft verification, not
a signed clean-commit claim.

Evidence is retained under
`scripts/devex/artifacts/campaign-selection-current-20261026/`:

- `control/red-tests.log` records both original identity failures.
- `control/revised/campaign-tests.log` records 117 passes and the fixture-order
  failure. An earlier run retains the target-isolation regression and a sandbox
  denial of an existing process-group test's `ps` command.
- `control/final/validation.json` records the corrected linked-return check,
  workspace build, Clippy and risk results.
- `control/final/draft-verification-receipt.json` records repository summary
  checks without replacing the signed publication receipt.
- `native-attempt-4/native/20261026-234345/J392` contains fourteen authenticated
  capture pairs, unchanged-source checks and the raw journey report.

Final J392 has fifteen machine passes, zero failures and four answered agent
screen questions with polish findings. Raw status remains `REVIEW_REQUIRED`,
exit 4, and formal operator acceptance remains pending. The native executable
SHA256 is `946f611eebd90f5b5054f2f6520ec5a4bc8d1020015ce362168f9851b13d60dc`;
all 6,807 authenticated inputs remain unchanged during the run.

The labeled unapproved history fixture inserts an earlier campaign and reorders
the original job rows. The selected job stays `held-2`. A separate PageDown
check retains first visible row 10 after refresh. The reader remains accessible
at 160x48, 120x36, 96x89, 80x24, 60x20 and 40x12. Removing the selected plan
returns to the campaign list with an explicit unavailable-history notice. All
queue entries retain zero attempts and dispatches, source bytes stay unchanged,
and no model request or target-source execution occurs.

The first two native attempts remain failures: the driver incorrectly expected
friendly labels on legacy plan rows, which display stable job IDs. Unused label
fields were removed from the fixture. Attempt 3 passes its fifteen machine
checks and three screen questions, but does not prove a positive reading
offset. Attempt 4 adds the explicit PageDown and capture-based offset check.
ANSI cell replays use Menlo 15 and a chosen dark background; they are not
operating-system screenshots.

## Remaining qualification

The legacy reader repeats some commands and spends many wide-screen rows on a
small record. The missing-history notice was inspected at 120x36, not at every
size. This repair does not bound campaign-directory enumeration or artifact
reads, qualify large histories, prove live engine usefulness, or establish full
reference-product parity. Those module and operator-experience requirements
remain open. The earlier 50-file lesson packet and eight-file DFD draft remain
separate and unchanged; this increment has no publication authorization.
