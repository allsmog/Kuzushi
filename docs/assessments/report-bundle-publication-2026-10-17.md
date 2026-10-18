# Complete Report bundle publication

Markdown exports now publish a completed bundle with its findings, investigation
receipt and authenticated manifest. Failed construction leaves the final path
retryable. The Report header retains the export outcome and destination while
reading; the compact footer keeps destination editing beside export.

This checkpoint also includes the preceding
[spending control acceptance](spending-control-acceptance-2026-10-17.md).
Four delivery items are locally verified and five remain open. This repair does
not close the broader Report or TUI acceptance requirements.

## Publication behavior

The original writer created the final directory before all finding files and
study metadata had succeeded. A later failure could leave a nonempty partial
bundle that the next export refused. The shared exporter now builds a complete
generation in a private sibling directory, then renames it into the final path.
It validates the destination both before construction and before installation.

Files, symbolic links and nonempty directories are refused without replacing
their contents. An existing empty destination remains empty on a build failure.
If installation fails after removing an empty destination, the adapter attempts
to restore that empty directory without overwriting another file. Normal errors
discard the private temporary directory. Concurrent publishers leave one intact
generation instead of combining their files.

This provides completed-directory visibility. It does not establish power-loss
durability; a hard process kill may leave an unpublished hidden temporary
directory. Single-file export and companion-receipt crash consistency are
unchanged. Export remains synchronous, so this small fixture does not qualify
large-ledger responsiveness.

No model work, option, artifact schema, public module name or dispatch path is
added. Study JSON/SARIF/JSONL already embed the investigation document; all study
formats retain its companion receipt. CSV and external-scanner row schemas stay
compatible. Findings-only history exports remain distinct from study reports.

## Visible recovery and focused checks

The destination header uses its existing row for `EXPORTED` or `EXPORT FAILED`
and the selected path. Full receipt details remain available. Selection or path
changes clear the previous outcome. The canonical `e edit path` binding appears
beside export; the compact footer shortens the same actions to `e path` and
`Enter export`. Draft, cursor, reading position and input ownership remain
unchanged.

All 126 distinct focused Rust checks pass. They cover real partial-bundle
construction, injected receipt-write failure, retry through the public exporter,
empty/file/nonempty/link destinations, concurrent publication, existing export
formats and aliases, actual Report key handling, six framed sizes and plain
output. The locked workspace build, Core/TUI Clippy and final risk proxy pass.
The risk proxy scores nine changed code files across this checkpoint, including
eight production files and one dedicated TUI test file classified by its naming
heuristic. The earlier spending increment separately records 125 focused Rust
passes and nine bridge checks; the two test counts are not added as distinct.

An initial test used a noncanonical macOS temporary path; its assertion now
matches the actual canonical receipt path. An incorrect test filter selected no
compatibility tests; the corrected filters executed fourteen actual export
cases. The first risk run exposed complexity in a dedicated test, which now
uses actual Home/End key events with simpler assertions. These failed or empty
attempts are retained and excluded from the passing totals.

The first native candidate exposed a hidden path-edit shortcut at 40 columns
during visual inspection, despite its passing machine checks. The footer repair
adds explicit framed and native visibility assertions. The second candidate
stopped because the journey sent save and export together before the UI consumed
the saved destination. The final journey waits for the saved Report path before
requesting export; it does not weaken the export or source-preservation checks.

## Final native evidence

Final sequential J121 has 210 machine passes, zero failures, 127 capture pairs
and twenty pending human judgments. Thirteen executables, 4,611 source inputs
and 809 runtime inputs are authenticated before and after execution. The main
executable SHA-256 is
`b8ef860437330121231a7dfb95c2b6af6b7ef47091972790d837609e7c4a0920`.

The journey exports a study JSON, refuses the owned source file as a bundle
destination, edits that destination at 40 columns, publishes the bundle, returns
to JSON and restarts without color. The actual completed bundle contains five
files. Its four non-self manifest entries authenticate exactly, and its
investigation receipt equals both manifest metadata and the existing JSON
receipt. File hashes are unchanged after restart. No private staging path leaks
into the bundle or remains after normal execution.

Independent verification reads actual SQLite rows and export bytes. Three fixed
Scan jobs retain four attempts, including one canceled attempt, four producer
observations and two distinct findings. Three human-decision records retain one
effective false-positive decision and one reassessed deferral. All five committed
calls, the one unresolved reservation and two unused protected Review calls
survive export and restart. Unknown dollar consumption remains unknown. Export
and destination recovery add no jobs or provider requests; owned source bytes
and the recorded Git identity remain unchanged.

Fifteen final terminal-cell reconstructions were visually inspected, covering
JSON and bundle selection, both destination editors, failure and recovery,
all six requested sizes, compact reading controls and no-color restart. Outcome,
path editing and export are visible together at 40 columns. These are ANSI
reconstructions with a chosen font and background, not OS screenshots or formal
operator judgments. Report metadata remains dense. All twenty human judgments
remain pending, and full reference-product parity remains open.

Evidence root: `/tmp/kuzushi-report-bundle-20261017`, with final native artifacts
under `native-v3`, focused logs, build/Clippy/risk results, independent proofs
and visual-inspection records. Five provider requests are fully intercepted;
zero new live requests or target-source execution are added. Historical real
requests remain fourteen, with no approved inference capacity left. Clean
repository verification and its signed receipt accompany publication outside
the committed tree.
