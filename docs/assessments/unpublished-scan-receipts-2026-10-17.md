# Reading findings during Scan publication

An unfinished parent Scan previously made the findings reader fail with
`Scan result has no authenticated artifact`. The parent had started legitimate
work but had not published its correlated result. This interrupted reading of
findings from a completed sibling pass and left an error notice over the
Workbench.

The shared receipt reader now distinguishes an unpublished result from damaged
completed evidence. Healthy typed history, a nonterminal parent call, no run
terminal event and an unfinished readable summary permit a read with no new
authenticated child membership. The summary is read before the lifecycle
projection so concurrent publication cannot make an older unfinished projection
contradict a newer completed summary. This establishes no process liveness and
does not repair, finish or restart work.

Terminal calls, terminal or unknown summary states, completion markers,
unreadable summaries, ambiguous parents and damaged history remain errors when
the correlated result is absent. Typed history continues to exclude legacy
sidecars. Once the result is published, authenticated membership becomes
readable normally. Completed siblings remain available throughout.

## Qualification

Ninety focused Rust tests pass: eighteen receipt checks, thirty-three study
membership checks and thirty-nine guided-journey checks. The workspace build,
workspace Clippy and CRAP-risk proxy pass. Existing typed result authentication,
direct-engine scope validation and interrupted recovery remain covered.

Sequential J121 has 179 machine passes, zero failures, 113 capture pairs and
nineteen pending human judgments. Its strengthened held-request checks reject
the refresh error, read both completed-pass findings through shared prepared
dispatch and retain Scan as the next required phase. Palette return and a
40-column resize preserve the Unicode draft, original dispatcher, admitted
bridge, fixed queue and three committed calls. No new discovery job or provider
request is created by those interactions.

The same run continues through cancellation, partial acceptance, human triage,
a specific allowance revision, the original remaining job, Report, export,
no-color restart and missing-context recovery. It retains three fixed Scan jobs,
four attempts including one cancellation, four raw observations, two findings
and three human decision records. Accounting ends at five of seven calls, one
unsettled reservation and two protected Review calls; dollar cost is unavailable.

Copied binaries and source/runtime manifests are checked before and after the
run. Fourteen ANSI cell replays were inspected, including held work, palette,
all six partial Scan sizes, refreshing and settled Report, and restart. These
are terminal reconstructions, not OS screenshots, and close no formal human
judgments. Requested terminals are 40x12, 60x20, 80x24, 96x89, 120x36 and 160x48;
native panes have one fewer row for tmux's status line. The replay font does not
render every symbol faithfully.

Transport is intercepted. This adds no live inference or target-source
execution. Historical live requests remain fourteen with no approved capacity
left. This case does not qualify real-model usefulness, actual cross-commit
finding comparisons, general module readiness or reference-level UX parity.
At this checkpoint the in-flight Scan body still presented a completed engine
through its legacy projection while the guided journey waited for study
selection. The later [approved study progress checkpoint](approved-study-progress-2026-10-17.md)
separates the fixed study's queue from its selected result. All nine broad
milestones remain open. Public artifact formats and dispatch contracts are unchanged.

Evidence root: `/tmp/kuzushi-unpublished-scan-20261017`. Native manifests, capture
provenance, independent ledger/export verification and active-work evidence are
under `native-v1`. Temporary evidence paths are local and are not repository
artifacts.
