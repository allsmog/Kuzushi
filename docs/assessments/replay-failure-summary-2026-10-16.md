# Readable Replay failures and complete receipts

Incomplete runs with a recorded issue and a healthy typed receipt now open on a
summary. It shows the cause once, preserves distinct warnings and bounded-result
disclosures, and keeps work, artifact hashes and timeline in the full receipt.
Tab and Shift+Tab switch views without running or approving anything.

Each view retains its own scroll position. Reopening the same run keeps its
reading choice; another run starts on its summary. A prompt draft owns Tab,
while Navigate can switch views without changing that draft or its cursor.
The hint is suppressed while the prompt owns input. Plain output always reads
the full unscrolled receipt regardless of the interactive page.

Unknown integrity, durability, progress or delivery state retains the original
full reader. This change derives presentation only from verified typed records;
it does not infer a failure from arbitrary output or alter stored receipts.
Native checks compare the first refusal's original run, result and lifecycle
hashes after reading both views and after restart.

The heading keeps the Tab control visible at 40 columns when the condensed
footer omits it. The full receipt uses a shorter heading at that width so its
border cannot consume a separate row. Promoted errors fold only on exact
trimmed text from the same recorded event. Identical messages from a different
event remain visible, including repeated calls with the same tool label.

## Verification

Evidence root: `/tmp/kuzushi-replay-summary-20261016`; final native evidence is
in `exact-event`. Eighty-five distinct focused TUI checks pass, including typed
receipt reading, input ownership, both scroll positions, new-run reset, width
limits, plain output and keymap collisions. The workspace binary build passes.
The risk gate passes for 234 changed code files and all 15 support checks.
All ten repository summary checks pass. The unsigned development receipt is
dirty and records `driftedDuringRun: true`; it is not a clean publication receipt.

Final J307 is `exact-event/native/J307/20261016-105536/J307`: 27 machine passes,
zero failures, 25 capture pairs and three pending human judgments. It reads
both views at 120x36, 160x48, 96x89, 80x24, 60x20 and 40x12. It preserves the
summary reading position, an unsent Unicode draft and the canonical receipt's
exact hashes through restart. Four requests remain blocked, with zero jobs,
observations or provider reservations.

Final J304 is `exact-event/native/J304/20261016-105717/J304`: 55 machine passes,
zero failures, 54 capture pairs and seven pending human judgments. The exact
final build completes three baseline and three context-experiment jobs under
one six-call intercepted allowance. The actual adapter requests contain the
reviewed frozen lesson context. Six observations and one historical human
decision remain. Report requires source reassessment, retirement blocks new
lesson use, and no-color restart starts no extra work.

All 13 native programs, 4,305 source inputs and 744 runtime inputs retain their
frozen hashes during both final journeys. The executable SHA-256 is
`78a97667b763b25768b2899855ac432f2aa5278f4c50cbc27604f3baf74f0bbe`.
`exact-event/native-evidence.json` authenticates capture dimensions and hashes.

Earlier fixture failures and native captures remain preserved. The test fixture
was corrected to create the real typed producing call and canonical result
settlement. Visual inspection then exposed a hidden narrow-screen control and
a wrapped border row; both received focused assertions and fresh native runs.
A formatter-selection audit confirms that only the intended Rust paths changed.
The architecture gate also caught direct shell-view selection in the plain
adapter. Plain Replay now uses `PlainRenderMode::Replay` and the shared receipt
renderer; the failing check and full summary pass without weakening a guard.

Selected ANSI cell replays were visually inspected, including both final narrow
views and the summary at 120 columns. These are not OS screenshots or human UX
acceptance. Both journeys retain `REVIEW_REQUIRED`.

No live model request, exploit development, reproducer or vulnerability patching
is included. Earlier approved real experiments remain fourteen requests. The
full investigation requirements and human UX bar remain open. The earlier
366-file publication proposal and seven-file staged patch remain separate; no
commit or push is made.
