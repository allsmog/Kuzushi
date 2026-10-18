# Literal scope membership, October 18, 2026

Scope forms and native scanner dispatch now preserve leading and trailing
spaces in source names. This checkpoint repairs exact membership without
qualifying every finding reader or closing the broader scope milestone.

## Reproduced defects and correction

Split and exclude forms trimmed literal paths. Three focused TUI regressions
failed before the form correction. The first complete scanner experiment then
exposed separate shared defects: explicit list coercion and scan-path
normalization trimmed the same names. Three of its six fixed jobs failed;
the other three completed. Those attempts remain recorded as failures and were
not retried or reused as approval for new work.

Two path-normalization tests, one operator-list test and a shared prepared
dispatch regression also failed before the Core correction. Typed JSON arrays
and quoted operator list entries now retain exact strings. Comma-separated
shorthand still trims entries. Empty strings remain invalid. Scope-file lines
and native, agentic-input and full-mode path adapters retain literal names.
Boundary and member readers quote names with edge whitespace. Metadata list
parsers retain their own normalization. Public names and artifact shapes remain
unchanged; the option-description migration is documented in `RELEASING.md`.

## Verification

There are 219 distinct focused Rust passes across 222 test executions, including
prepared dispatch with and without an accepted scope reference. The locked
workspace build, Core and TUI Clippy checks, and the risk proxy pass. The proxy
covers 28 changed production files across this checkpoint and the preceding
unpublished lesson/report changes. No target source or model is executed by
these tests.

Final sequential native J335 uses installed Semgrep 1.165.0 with a local rule
over three owned inert files: `" app /lib.py"`, `"app/lib.py"` and `"loose.py"`.
It records 70 machine passes, zero failures, 63 text/ANSI capture pairs and six
pending human judgments. Exit 4 means review required, not machine failure.
The native binary SHA-256 is
`90eea8ca7d6316139978960859acdd0ed445e8650a9d4f625d4564ff0a29e0d3`.

The journey edits, excludes and restores only the spaced directory, refuses
literal `" . "` without changing the saved revision, and offers whole-repository
scanning before returning to two accepted boundaries. It explicitly approves
six jobs, three passes per boundary and one worker. Every job completes with
one attempt and dispatch, retaining nine observations and three separate
identities. Recurrence remains three per finding, severity remains informational,
proof remains signal-only, and three scripted human deferrals are recorded.
JSON retains all literal paths. The external scanner export reports completion
of this selected finite plan. Restart retains results and decisions.

The independent artifact check authenticates the plan and every approved input
digest, job counts, observations, decisions, native binary, captures, unchanged
source and the unset global context pointer. There are zero provider call
reservations. The allowance has one protected Review call and zero Scan calls
available; no model request is made. The live-model cumulative total remains 14.

Twenty ANSI cell replays were inspected, including fields and boundaries at all
six requested sizes, file readers, invalid input, approval, results, Report and
no-color recovery. These are terminal-cell replays, not OS screenshots. The
tmux status row leaves one fewer application row than each requested height.
Narrow boundary details require paging. Hashes for 4,645 source inputs, 815
runtime inputs and 14 frozen programs remain unchanged during execution.
The Semgrep entry point is hashed; this is not authentication of its entire
installed Python dependency tree.

## Remaining work and retained evidence

Review's spaced finding displays an unquoted location and reports live source
missing or changed despite unchanged fixture bytes. Frozen source remains
visible and exports retain the exact path. Fix and qualify that reader
separately. Scope review remains a flat boundary list with a paged file reader;
the requested selectable scope tree and visible context inheritance/local
overrides remain implementation work. Six human judgments remain pending.
This checkpoint makes no reference-product UX parity claim.

Evidence root: `/tmp/kuzushi-literal-scope-membership-20261018`.
Final journey: `native-v4/native/J335/20261018-061117/J335`.
Earlier native attempts and failing regression logs remain intact.
`verification-v2/focused-results.json`, frozen manifests and
`native-v4/independent-artifact-check.json` record the verification boundaries.
