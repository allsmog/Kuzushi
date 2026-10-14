# Agentic preparation audit, October 8, 2026

The monorepo audit found a preparation defect before expanded orchestration:
the agentic scanner capped selected snippets but recursively traversed directories
without an entry limit or cancellation. Sparse or deeply nested repositories
could consume unbounded preparation work before any model request.

Preparation now uses an iterative walk with a 100,000-entry limit and a
conservative 512 MiB content-read allowance. The sampler preserves its existing
language, filter and vendor-source behavior. This matters because the structural
inventory classifies vendor roots without descending them, while this engine's
existing explicit vendor filters include their source. Shared file containment
and read helpers remain authoritative; symlinked files and directories are
excluded. No source executes.

The sampler checks cancellation during enumeration and processing. Directory and
metadata errors are explicit. Unreadable candidate files contribute to the
skipped-entry count; per-path failure reasons are not retained yet. Failed and binary-looking candidate reads
retain their conservative reservations. Snippet bytes are measured before
decoding; binary inspection can read `max(4096, snippet limit) + 1` bytes. A
64-byte snippet therefore has a 4,097-byte maximum read, rather than a false
64-byte read claim. Resource bounds concern preparation, not later agent reads.

The descriptor exposes `maxInventoryFiles` and `maxBytesPerFile` on both SAST
surfaces, with the existing defaults of 80 and 2048. Accepted jobs freeze these
options through shared prepared dispatch. `inventoryCoverage` records extent,
limits, skipped/ignored counts and truncation. Prompts and canonical results
retain its qualification; snippets do not establish complete repository coverage.
Legacy snippet consumers fail at walk/read limits when they cannot preserve a
partial receipt. Missing historical receipts remain unknown.

The study's source panel presents the frozen preparation limits before launch.
Scan keeps a concise preparation warning beside each recorded engine outcome.
Expanded Report details put those warnings ahead of long provenance identifiers.
An engine's completed operation does not hide partial preparation.

Evidence is retained under `/tmp/kuzushi-agentic-preparation-20261008`.
Thirty core checks cover limits, cancellation during enumeration, deep trees,
root files, symlink cycles, vendor source, filters, binary inspection, failed
read reservations and existing engine behavior. One real shared-dispatch test
and focused presentation tests exercise canonical results and honest previews.
The workspace build is recorded separately.

J125 uses an owned greeting target, two explicit fixed passes, one worker and a
four-call allowance with two calls protected for Review. Its transport intercepts
every request without network fallback. Actual executors and correlated artifacts
preserve the one-snippet/64-byte preparation limit, two fresh bridge processes,
two committed call reservations, no findings and unchanged source. These are
plumbing and UI observations, not live model usefulness or scanner precision.
The fixture explicitly omits context; it does not establish an accepted Map.

Earlier failures remain retained: an undeclared fixture turn option, outdated
result text, typing a command while Navigate owned input, closing Report through
the generic navigation helper, and preparation warnings below long provenance.
The last of these exposed the report hierarchy defect repaired in production.
Raw tmux review status remains distinct from scoped implementation judgments and
operator approval.

Final J125 evidence is at
`/tmp/kuzushi-agentic-preparation-20261008/tui/20261008-112240/J125`: thirteen
machine passes, no failures, twenty-five authenticated text/ANSI pairs and two
separate scoped screen judgments. Raw exit 4 remains `REVIEW_REQUIRED`.
Native digest:
`f939ce09b6e4f859f7262c07fe2802b2bc695476ff77cc6fd0a0abe9bcfaa2f8`.
`verify-final.json` records all ten quick summary gates passing, including
CRAP-risk. The dirty checkout sets `driftedDuringRun`; this flag alone does not
prove that source changed during verification.

At this preparation checkpoint, exact accepted-file discovery was unsupported.
The subsequent [scoped discovery increment](./agentic-scoped-discovery-2026-10-08.md)
adds acknowledged membership and inherited source context. Finite multi-scope
execution, live OAuth validation, the complete per-tool outcome audit and full
original TUI acceptance remain open. No broad delivery milestone is closed by
this preparation increment.
