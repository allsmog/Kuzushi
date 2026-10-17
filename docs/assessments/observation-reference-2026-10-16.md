# Reopen the recorded observation from Review

Review now displays `open generation:<id>` in its action section for a persisted
observation. The reference uses the existing exact-generation resolver and is
relative to the current workspace. The adjacent explanation says that list
aliases can change as findings arrive. Unsaved findings receive no reopening
promise. No new public tool, schema or reference syntax is introduced.

This addresses an observed operator trap in J301: another finding took `F-0001`
after a second selected lockfile scan. The original finding became `F-0002`.
Its recorded observation reference remains the same. A later observation of the
same durable finding gets a different reference. Reopening an earlier generation
does not carry a decision to changed source or establish that a finding is fixed.
Existing decision-source and revision disclosures remain authoritative.

## Evidence and limits

Evidence root: `/tmp/kuzushi-observation-reference-20261016`.
Eleven focused TUI checks pass: two view-model checks, three Review renderer
checks and six continuity checks. Two ignored native fixture helpers are not
counted as passes. The historical source-replacement regression uses the
reference actually supplied by the Review view model and reopens the original
observation after refresh. Width checks retain the full command and explanation
at all six supported widths, including a maximum positive generation id.

The workspace build and all ten final summary checks pass. The risk proxy passes
for 178 changed production files and its 15 support checks. The initial risk
failure was a 42-line regression test. Removing an assertion duplicated by the
new exact-reference assertion brings it within the gate. The failed receipt and
focused diagnostics are preserved. The final summary remains dirty, unsigned
and `driftedDuringRun: true`; it is development evidence. Final documentation is
checked separately after this update.

Enhanced J301 is `native/J301/20261016-051440/J301`: 33 machine passes, zero
failures, 18 capture pairs and four pending human judgments. It runs three finite
installed offline audit jobs against owned hypothetical lockfiles, with an
explicit policy-omission control in a separate advisory database copy. Source
and scanner/database hashes remain unchanged. It reads the same displayed
reference before and after the alias changes, then after no-color restart.
The native binary has SHA-256
`465e87a705ed658fddd3f533017e83d9ee1c7f3eb8bfa3373c0407391f0a7156`.
All 13 programs, 4,291 source inputs and 734 runtime inputs retain their frozen
hashes. `native-evidence.json` verifies exact reference equality, alias change,
capture hashes and dimensions, six terminal sizes and no-color restarted readers.

The actual new reference captures are at 120x36. The six-size native matrix still
covers the source/policy comparison. Unit rendering checks cover reference text
at all six widths; these are distinct evidence scopes. Selected ANSI cell
replays were inspected visually. They are not OS screenshots. The command is
readable after paging the evidence reader and keeps the selected finding visible.
There is no new clipboard action or one-key reference control in this increment.
The earlier failed native case expected wrapped explanatory copy on one line;
its captures and frozen manifests remain preserved. The production executable
did not change for that recipe correction.

There are no new provider requests, target program executions, Git commits or
pushes. Fourteen earlier provider requests remain spent. Human interaction
acceptance, broader identity/history clarity, installed auxiliary-engine success
and the complete original investigation requirements remain open. This scoped
improvement does not claim reference-product UX parity or close a broad delivery
milestone.
