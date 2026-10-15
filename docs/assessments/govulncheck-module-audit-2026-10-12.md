# Go advisory scanner audit

The Go scanner remains available through exact dispatch but is now Labs in
ordinary discovery. This audit establishes parser and support-disclosure
behavior. Installed scanner execution, source loading, network containment,
scope coverage and phase-to-phase usefulness remain unqualified.

The old parser treated each line as a complete message, although the upstream
[v1.1.4 decoder](https://go.googlesource.com/vuln/+/v1.1.4/internal/govulncheck/handler.go)
reads a stream of JSON values. It also accepted arbitrary nonempty JSON as a
zero-finding result. The parser now decodes streamed values, requires an initial
supported protocol config, rejects repeated configs, unrecognized or combined
messages, and fails incomplete JSON. Parsing is bounded to 16 MiB and 100000
events. These limits do not bound the subprocess capture before parsing.

The upstream [finding protocol](https://go.googlesource.com/vuln/+/v1.1.4/internal/govulncheck/govulncheck.go)
distinguishes required modules, imported packages and reported symbols. Previous
output labeled every trace reachable and every finding CodeCited, including
module-only records. Output now names the reported level and keeps SignalOnly.
Recorded scanner positions are retained, but module-relative paths are not
authenticated against the target and do not promote proof. A symbol reported by
static analysis does not establish deployment or executed vulnerability.

The executor still invokes PATH govulncheck with a ten-minute process deadline
and uses the target as its working directory. Target dependency loading,
network access, database identity, configurable limits, partial stream retention,
successful process with truncated-but-valid output, and exact scope containment
need further evidence or repair. Every signal still uses the legacy High
severity policy; this audit does not calibrate severity or deduplicate progressive
module/package/symbol messages. Public parser and scanner identifiers remain
unchanged. DAG context metadata does not execute preparation.

Ten focused checks pass, covering protocol failures, pretty printed streams,
module/package/symbol labels, conservative proof, parsing bounds, cancellation
before preflight, registry support and scan task resolution. Workspace build
passes. Native J221 inspects the catalog and experimental options with owned
inert Go metadata; no Go source is loaded, scanner invoked or model called.
Final native J221 is
`/tmp/kuzushi-govulncheck-audit-20261012/recovery-tui/20261012-000310/J221`.
It has 19 machine passes, zero failures and 11 authenticated captures at six
sizes, including no-color restart. Native SHA-256 is
`d706da6226510a5315f322c3d3bff208249e2abf8b48af34b23d09d301ab488e`.
Source hashes and all provider/work/observation/decision counters remain
unchanged. Default CLI discovery omits the scanner, and exact options retain
the experimental label. Three judgments remain raw REVIEW_REQUIRED;
assistant capture review is separate from operator acceptance.

Observed filtered browsing originally treated experimental tools as unknown.
The tool view now distinguishes matching Experimental and Compatibility tools,
with an exact settings command. In the compact native capture, the reason and
settings action precede empty-result details and remain immediately visible.
Seven tool-model tests and one renderer check pass. The action remains a typed
command, so complete visible-control/palette parity remains open.

Predecessor receipts remain intact: the initial catalog verifier expected a
ledger before TUI launch; the next asserted different display labels; a 16-pass
run proved curation but retained the generic empty state; the following compact
run exposed support text below the viewport. No failed receipt is rewritten.
The locked workspace build and all ten repository summary gates pass. The risk
proxy passes for 429 changed production files. Receipt
`/tmp/kuzushi-govulncheck-audit-20261012/recovery-verification.json` is dirty,
remains unsigned and predates final evidence documentation. Final documentation
checks are recorded separately.

Default catalog omission, exact inspection and restart do not establish scanner
execution reliability. No retirement, deletion, complete module qualification
or broad delivery milestone follows this audit.
