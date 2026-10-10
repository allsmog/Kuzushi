# Concurrent Review snapshot, October 9, 2026

The owned J121 investigation recorded refresh failures when the ledger moved
between multiple read queries. The shell retried one final consistency race,
but a race inside the shared page reader could fail earlier. Faster retries did
not establish coherent rows, decisions and counts during sustained writes.

The shared findings store now offers a synchronous SQLite snapshot boundary.
`findings:list` uses it around complete page construction. The full shell reader
wraps page, corpus, decisions, source-completion and compatibility lifecycle
queries in the same transaction. Nested page reads join that transaction.
The initial projection query fixes the database read point; the returned
watermark identifies it. External commits become visible to a later read.
The obsolete retry loop is removed. Callback errors and panics release owned
transactions; existing caller transactions remain open.

Public inputs, page JSON, cursor bindings, source checks, manual-decision
validation and model policy remain unchanged. A snapshot does not authorize
writes or freeze files, run metadata or policy configuration. WAL allows an
external writer to commit while the reader retains its view, but long readers
can retain WAL history. No latency or filesystem-atomicity guarantee is added.

Evidence root: `/tmp/kuzushi-review-snapshot-20261009`.
Native J155: `tui/20261009-213447/J155`.
Native SHA-256:
`a6ab7b48e8c4eaeaff2651a42846a16d71ad79be97cba84351842cf6ad8f9fa9`.

J155 has 24 machine passes, zero failures and 23 authenticated text/ANSI
captures. All native hashes, dimensions, row counts and ANSI-stripped text
agree. Six sizes, actual 40x12 detail paging, list return and no-color restart
are covered. No capture contains a ledger-refresh failure. During a pending
read, the wide layout explicitly labels previous results. The later page,
selected finding and composer draft remain intact during actual external writes.

The isolated dataset contains 800 labeled synthetic findings and synthetic
import bookkeeping. It is not discovery evidence or a completed real scan.
One finite native writer commits through the real store and writer actor,
updating a different finding. The fixture verifies its live process identity
and another committed update before the relevant checks. It is bounded to 240
writes with a 250 ms pause and an explicit stop file. This run stops after 33
writes, retaining 833 observations and exactly one explicit human deferred
decision on the unchanged original selected id. Source bytes stay identical.
No model, scanner, target execution or provider/work reservation occurs.

Four scoped assistant screen judgments remain separate from raw
REVIEW_REQUIRED and operator approval false. The fixture checks the exact
decision target, verdict, author and reason after updates and restart. It does
not derive a fixed verdict from the absence of later observations.

There are 271 distinct focused passing tests across Core snapshots, finding
pages, writer guards and TUI findings/parity/plain/stress checks. Deterministic
tests commit findings and decisions from a second connection between related
reads and verify one retained watermark. Nested reads, error/panic cleanup,
missing ledgers and fresh subsequent reads are covered. Page cursors still
reject changed query contents after the read closes; existing writer and TUI
tests retain changed-subject/source rejection. Workspace build and the risk
proxy for 570 changed code files passes. All ten repository summary gates
pass. The receipt records dirty source and `driftedDuringRun: true`; this flag
includes initially dirty state and does not prove concurrent edits. Final
documentation contract checks follow this evidence update.

Broader checks exposed an old `G`-means-last-row test even though Review already
binds `G` to groups. The test now checks navigation and that actual shortcut
owner. Two old plain snapshots were refreshed only for reviewed differences:
catalog tool count, current review hints and missing decision-source disclosure.
These changes do not alter the production key or renderer behavior. Retained
compilation failures record an incorrect line type and fixture field name.

Remaining: filesystem/run-metadata races, long-reader/WAL resource bounds,
cross-platform performance, full live investigation, remaining module
qualification and complete reference-product parity. Visible qualification
stays 55 of 109 with 54 unassigned. All nine broad delivery milestones remain
open. Work stays uncommitted on main; no product commit, push or OAuth renewal
occurs.
