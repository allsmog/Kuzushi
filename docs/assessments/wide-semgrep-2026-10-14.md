# Wide exact-scope scanning and resource controls

October 14, 2026. Local changes on main at `f8649511f746`.

Exact-file Semgrep previously started a new process for every 64 files. The
adapter now packs ordered literal members into batches of at most 1024 files
and 12288 encoded argument bytes, including the executable and fixed arguments.
Directory expansion and globbing are absent. An oversized member or fixed
command stops work with an explicit error. Completed earlier batches survive
later errors. Existing output limits and the shared job deadline still apply;
there is no automatic retry, subdivision or new discovery job. The argument
budget does not guarantee launch on every environment or operating system.

The installed scanner defaults to nine workers on this host. Declared `jobs`
and SAST `semgrepJobs` now make this choice explicit, defaulting to one and
accepting integers 1 through 256. They flow through prepared dispatch into both
directory and exact-file commands. Study concurrency remains separate. Approval
shows the frozen worker count, and native receipts retain it alongside batch
limits. Supporting runtime threads are outside this setting. The public
`SemgrepScanner` fields remain unchanged; legacy methods use one worker.
Saved descriptor-bound plans need re-preparation and exact approval.

Home and End now reach the first and last 32-file page of a selected scope.
The file reader shows these controls. Menu and acceptance keys retain their
priority, drafts and source revision are preserved, and reading starts no work.
Report also keeps the selected format and its position in its fixed header,
with the destination on a separate fixed row. Large study details and long
format names cannot hide the destination during paging.

The controlled benchmark uses 1025 selected inert Python files and one
unselected sibling. It includes literal bracket, space and leading-hyphen
filenames. The only selected marker is in the final member; the sibling marker
must remain absent. Both builds run one scanner worker under the same observed
wrapper and local rule. The old adapter starts 17 processes in 21875.89325 ms;
the new adapter starts two batches of 635 and 390 in 5767.541125 ms. These are
single local samples including source authentication, not percentiles,
reference-product parity or general detection-quality evidence. All 1026 source
hashes remain unchanged. No source is executed and no model request is made.

Benchmark receipts are retained under
`/tmp/kuzushi-tui-integration-20261012/semgrep-scale-benchmark`.
The initial sandbox attempt could not access macOS trust anchors and returned
partial work. It is retained as an environmental failure, not a timing sample.
Normal host execution supplies system trust access. The installed implicit
nine-worker baseline is also retained separately from the controlled comparison.

The first J265 run at
`/tmp/kuzushi-tui-integration-20261012/wide-semgrep-tui/20261014-182954/J265`
completed all 24 actual jobs over 4105 source files: eight fixed boundaries,
three passes each, one outer worker and one scanner worker. Forty-eight analysis
processes produced 27 raw observations and nine consolidated policy signals.
Nine scripted operator deferrals reached Report. The run then failed its
format-position assertion because that label was below the large study body;
the fixed header now carries the same selection position. This failed run is
retained and does not establish export or restart success.

A second J265 run at
`/tmp/kuzushi-tui-integration-20261012/wide-semgrep-final-tui/20261014-183955/J265`
reached an observation timeout while its dispatcher continued. The test assumed
eight completions within 60 seconds, even though each accepted job has its own
60000 ms subprocess allowance and separate source authentication. No job failed.
The same dispatcher finished 24 jobs in 24 attempts, with no restart or queue
injection. Future observation waits derive a finite bound from accepted job
limits and fail immediately on a failed or stopped job. This changes the test
wait, not execution limits or approved work.

J267 at
`/tmp/kuzushi-tui-integration-20261012/wide-semgrep-recovery-tui/20261014-184701/J267`
reads that actual completed study, explicitly accepts Scan, records nine scripted
operator deferrals, exports JSON and verifies no-color restart. It passes 23
machine checks with 16 live text/ANSI capture pairs. Two human judgments remain
pending. The report preserves 27 observations, per-boundary three-pass recurrence,
nine decisions and unchanged source, context and allowance. No additional jobs or
provider requests occur. This is continuation of the retained failed observation,
not a green rerun of the full J265 script.

Producer hashes distinguish these receipts: the benchmark and initial J265 use
`6c6539d4934c6301bb927ec20081e57c39b758c0b5e6496ac71a69bb7f3253c1`;
the second J265 uses
`b5c21a938d60bf4213709489e3471d1b05a3c0f6a5b34fec3d5f05dd92488d09`;
and J267 uses the final Report reader
`2b64e1234f9d320df0531d31d8cacca24ade0d2e6914ab5269eb8c7e79dfd137`.
The latter change affects presentation, not batching or discovery.

The final focused checks pass: 59 Core Semgrep/prepared-dispatch checks, 185
TUI Report checks, 31 scope-review checks and 13 allowance-overview checks,
288 distinct tests. The locked workspace build and all ten summary gates pass,
including 391 Node tests and the CRAP-risk proxy for 719 changed code files.
The retained unsigned local receipt is
`/tmp/kuzushi-tui-integration-20261012/wide-semgrep-settled-green-receipt.json`.
It records `dirty: true` and `driftedDuringRun: true`. This is scoped local
verification, not a clean release, full Rust suite, full CI or platform matrix.

Earlier failures are retained. The first summary caught a 41-line test, now split
into prepared forwarding and invalid-input checks. A Report borrow error was
corrected before native freezing. The first all-format test compared a directory
destination with its basename without the trailing slash; the corrected check
normalizes only that test comparison. Production destinations are unchanged.

Two reader-script failures are also retained. The first expected the final
format to wrap, while the existing selector clamps at its ends. The second
expected the wide Campaign count in the first three body rows at 40x12. The
compact reader displays `work finished`; the exact job count is independently
authenticated from its unchanged queue. The script now uses that visible status.
All 42 format/size/paging captures had already passed before the latter timeout.
This also leaves a clear presentation limit: the compact Campaign count requires
reading farther down; this increment does not make that count sticky.

The final J266 reader at
`/tmp/kuzushi-tui-integration-20261012/wide-report-reader-verified-tui/20261014-185438/J266`
passes 94 machine checks with 48 live text/ANSI capture pairs. All six formats
retain their selected label and destination at 40x12, 60x20, 80x24, 96x89,
120x36 and 160x48, including narrow paging. A 40-column no-color restart
restores saved JSON choices and the same completed study. This checks format
selection and reading; actual export evidence is JSON, not every serializer.
Source hashes, plan and queue hashes, observations, decisions and zero provider
reservations remain unchanged.

J267 and final J266 together provide 117 machine checks and 64 live capture
pairs. Their hashes and qualified assistant reviews are retained separately.
Both raw results remain `REVIEW_REQUIRED`; four human judgments are pending.
The earlier active-work typing sample has a 21.47 ms median and 34.73 ms maximum;
the second has a 38.04 ms median and 54.09 ms maximum. Each has 24 samples across
six sizes with the same actual dispatcher verified before and after every echo.
These are tmux observations, not hardware latency, percentiles or parity claims.

The new operator-facing text passes the scoped register review. The earlier eight
approved live model requests remain exhausted. Architectural proposal quality,
security detection quality, full module qualification, physical terminal
latency and broad visual acceptance remain open. No module maturity changes or
retirements follow from this evidence.
