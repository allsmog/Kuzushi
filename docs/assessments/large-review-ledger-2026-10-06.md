# Large Review ledger, October 6, 2026

Review now distinguishes its loaded portion from all matching findings. A
500-row list over a 1,000-finding ledger says `500/1000 loaded`, including at
40x12. An empty loaded subset cannot claim that omitted findings are reviewed.
`Ctrl+F` in empty Navigate mode prepares the existing global `findings filter`
command. Enter applies it; typing retains the composer's cursor controls.
The shortcut remains visible in the compact footer. Local `/` search continues
to narrow loaded rows. No list limit, finding identity, decision or module
contract is changed.

Work remains on `main`, at `972e09ca5ae86de49d53f204dc28ac7f096f9baa`.
The checkout advanced externally from the preceding checkpoint. This work
preserves pending changes and performs no commit or push.

## Measurements and repairs

Evidence root: `/tmp/kuzushi-experiment-main-20261006/`. The owned fixture is
`/tmp/kuzushi-review-ledger-1000-before/`. It contains labeled synthetic findings
and commit metadata, real captures of benign generated source, and two runs
with 2,000 observations. Target source is never executed. No scanner or model
request is made.

The initial 100-finding measurement recorded approximately 10.5 ms for source
completion, 39.3 ms for full refresh and 2.1 ms for queue construction. The
1,000-finding measurement recorded 49.0 ms for store opening, 207.0 ms for
listing, 62.0 ms for source completion, 406.6 ms for full refresh and 7.5 ms for
queue construction. These are single measurements on the debug host, not a
performance distribution or reference parity claim.

Fixture preparation took 382 seconds and initially failed because the test
assumed every ledger row would be loaded. The fully prepared fixture is retained;
measurement then explicitly distinguished 500 loaded rows from 1,000 matching
findings. Native external decision writes measured roughly 0.7 to 0.8 seconds
each. Neither synchronous refresh nor durable-write cost was optimized here.
Both remain important responsiveness work.

Three product regressions failed before the repair: hidden loaded/matching
population, an empty loaded subset presented as completion, and the absent
global-filter shortcut. All 26 Review model checks pass after the change,
including composer cursor movement. Thirty-seven keybinding checks and 294
Review checks pass. Native inspection exposed a further 40-column footer gap;
its regression failed first, and all seven footer checks pass after prioritizing
the real filter control.

The composition suite passed 17 checks, including 120 phase/size/color buffers
and 30 plain projections, while its snapshot check failed on expected copy
changes. Only four reviewed Review snapshots were updated from `show full
queue` to `reset list`. The final snapshot check passes all 30 references.
Compatibility readers execute no verification or patching work. The final
workspace build is recorded in `large-review-footer-build.log`.

## Native evidence and limits

J101 at `tui/20261006-175449/J101/` records 29 machine passes and five separate
passing screen judgments. Raw `REVIEW_REQUIRED` remains unchanged.
`manual-review.json` includes actual text/ANSI hashes and capture provenance.
All six viewport sizes, the tiny Navigate control, settled omitted-row retrieval
and no-color restart were read. Six sampled key-to-echo measurements are
72, 90, 73, 77, 83 and 75 ms, within the existing 300 ms test budget. The
host receipt retains all observations and source bytes and records exactly six
bounded synthetic decision additions.

Predecessors remain intact. Run `171008` fails due to a wrong recipe command
and misleading population copy. `174625` passes machine checks but its filtered
capture mixes loading and prior-frame content, so that reading judgment fails.
`174949` retains the hard failure for a hidden tiny filter control and a 204 ms
echo sample. The settled recipe now waits for complete detail and explicitly
checks the tiny Navigate control. No raw report is rewritten.

The list is still capped; operators reach omitted findings through global
filtering. Cursor paging of the complete ledger, predictable large-ledger
refresh and decision-write responsiveness, wider scale, platform/accessibility
coverage, actual Git transitions, scanner precision and the full investigation
journey remain open. Screen and sampled timing checks do not establish complete
reference parity. No module is promoted or retired, and all nine milestones
remain unchecked.

`final-large-review-gates.json` records final repository gates. Independent
pending-change and native fingerprints accompany the receipt; preserve its raw
dirty/drift flags. The live-model source, accepted context and allowance require
an independent read before continuation. Its three-pass study and proposed
21-request ceiling remain unapproved and unstarted.
