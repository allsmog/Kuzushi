# Exact settings guidance and bounded capability paging

`options .` now distinguishes a missing module focus from a focused module whose
actions require an exact tool choice. The latter names the module and points to
its tool browser and exact settings command. Existing compatibility settings
remain accessible without promoting an experimental action or starting work.

Page Up and Page Down now stop at the ends of the capability list. Previously a
page larger than the curated list wrapped into its middle. Paging uses saturating
cursor movement and handles empty lists, large steps and outdated selections.
Arrow navigation retains its existing behavior, and paging keeps the selected
row visible without entering text in the composer.

Twelve older test failures were reconciled against current behavior. Review
tests distinguish the displayed page from the next required Map checkpoint and
use the displayed Review projection for pinned finding details. A Review-ready
fixture now records its explicit Map skip and selected Scan attempt. Other
checks retain explicit compatibility action selection, Setup ownership before
Start Map, qualified cost text, the current Enter hint and the goals command.
The planner prepares an unapproved finite study rather than returning the old
immediate execution effect. Separate positive checks verify that workflow.

Verification records:

- 150 focused TUI checks and 17 proposal/draft guard checks pass. The initial
  focused run recorded 89 passes and twelve failures. No saved snapshots were
  accepted or rewritten.
- Workspace build and all ten draft quick checks pass, including the risk
  gate's 15 supporting checks and 14 changed code files.
- Expanded native J218 records 54 machine passes, zero failures, 40 live capture
  pairs and five pending human UX judgments. It covers capability paging,
  invalid-value correction, multiline Unicode drafts, session/global
  persistence, exact compatibility settings, six terminal sizes, complete
  recovery guidance in the transcript and no-color restart.

The first native run stopped because its new assertion expected the plain
renderer caption. Its diagnostic capture showed the modal correctly selecting
row 3/3. The journey now checks the actual modal selection counter. The second
run completed its machine checks; the final run adds the guidance reader across
six sizes. All earlier records are retained.

The copied executable has SHA-256
`4821a08652a40ddb29667c540b13ed0015ed241f60c413d230fbff4b7459f678`.
After the final journey, 4,234 source inputs, 686 runtime inputs and 13 copied
binaries retain their frozen hashes. The quick checks preceded the final
journey-only assertion and reader additions; the final journey exercised those
steps through the real harness. Evidence is retained under
`/tmp/kuzushi-tui-ux-qualification-20261015`.

The quick receipt is a dirty-tree draft, with both dirty and drift flags set;
it cannot authorize signing or publication. The native journey dispatched no
jobs. No provider request or target source execution was added. Fourteen cumulative live experiment
requests remain spent, with no further approved capacity. This qualification
does not establish a green full Rust suite or close the broader operator
experience requirements. Other module fixtures, TUI assertions and saved
snapshot differences remain to be reviewed.
