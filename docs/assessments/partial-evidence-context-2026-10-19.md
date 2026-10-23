# Partial inventory and exact context, 2026-10-19

The [October 23 follow-up](source-index-context-acceptance-2026-10-23.md)
records the persistence repair and successful actual-cap journey. The original
failure and limits below remain the historical record.

This implementation is a draft on main after `a2a38eedf13a8c760acfb13eaffc759a32260ba7`.
Its wide-repository qualification is incomplete. The actual-cap native test
exposed a source-index persistence bottleneck before the TUI could launch.
The broader investigation remains four locally verified delivery items and
five open items. No new live provider request was made.

Exact-file context selection now uses the authenticated inventory cache owned
by scope planning. It accepts selected files already enumerated in a partial
inventory. A file absent from that inventory is refused rather than assumed to
be a member. Unknown legacy extent and canceled reads remain errors. The same
source and enumeration checks protect cache reuse; content inspection is
reused, while source and membership authentication still require work.

Plans gain optional `sourceInventory`, included in their plan digest and
`ContextStudyReceipt`. Generation retains actual inventory extent, source
identity, inventory hash, limits, omissions and truncated-file counts in
`provenance.fileContext.receipt.inventory`. Path detail is limited to 16 entries
per list, with remaining counts disclosed. Selected-text regeneration records
its current inventory separately. Selected excerpt completeness never implies
complete repository enumeration or complete repository coverage.

The TUI distinguishes those states before approval and in the saved context
reader. It puts the shared consumption summary before potentially long source
lists and inventory detail. A native regression caught the spent-call counter
moving below the first result screen; a six-viewport render test now protects
consumption, protected Review capacity and the blocked accounting state.

Evidence is retained locally under the ignored
`scripts/devex/artifacts/partial-evidence-context-20261019/` directory:

| Check | Observed result |
| --- | --- |
| Focused Rust checks | 202 distinct passes across scoped context, campaign context studies, regeneration, diagram studies, evidence readers and consumption visibility |
| Workspace build | Passed on the final native source |
| Core/TUI Clippy | Passed with warnings denied before the final presentation-only adjustment |
| Model policy | Passed after moving the inline fixture into its dedicated test module |
| Repository summary | All ten final checks passed, including model safety, workspace check and CRAP-risk; the dirty receipt is separate from the published clean receipt |
| Final J339 | 46 machine passes, zero failures, three pending human judgments, 43 text/ANSI/provenance capture sets |
| J341 | Failed during setup: zero machine passes, one failure, no TUI captures and no provider calls |
| Frozen native build | SHA-256 `59535ca27d700491bea1eefb1c89303cbf5b0578bfafcde7d88983e8676a44ac` |
| Frozen inputs | 6,379 repository inputs and 13 programs remained unchanged during both journeys |

Fifteen J339 terminal-cell renders were inspected across all six sizes,
narrow paging, prepared and completed plans, exact Back restoration and
no-color restart. They use Menlo 15 and a chosen dark default background;
they are ANSI cell replays, not operating-system screenshots. The three formal
human judgments remain pending. The forms still contain too much explanatory
text, raw byte counts and long identity values for reference-level UX parity.

J339 preserves the two literal selected file paths, the different globally
active context, the original five-pass parent draft and one settled synthetic
request. The partial-inventory Core tests use the real inventory builder with
a small entry cap. These tests do not substitute for the failed wide native
journey. The first J339 attempt on this feature had 44 passes and two spending
visibility failures; the final result above follows the presentation repair.
The inline test initially failed the model-policy gate, which was rerun
directly before the dedicated test-module correction.

J341 creates 100,001 empty filler files, four owned source comments and a
separate out-of-prefix source file. Its initial `threat-model:import` exceeded
the fixture's explicit 240-second limit. Python killed and reaped that child;
the native controller exited 1 and the process was independently confirmed
absent. No study, imported context or model request was produced. Inspection
of a stable copied ledger found one target snapshot, 42,108 indexed-file rows,
42,109 journal-projection events, zero observations and zero review decisions.

A two-second process sample places the import in `index_workspace_snapshot`,
`commit_index_projection` and `StorageWriterSession::commit_many`. The latter
executes each command separately. Each indexed-file event uses its own synced
journal append and SQLite projection transaction. This is a concrete scaling
problem in the source-index path; the sample is not a complete import profile
or a throughput benchmark for the finished operation.

The next implementation must reduce this persistence overhead while preserving
all source blobs, tree identity, individual event envelopes, receipt sequences,
journal limits and restart recovery. Replacing the full snapshot with an
identity-only registration would change what historical consumers can read and
is not an equivalent fix. The source-index path also needs cancellation and
progress during persistence, followed by a fresh actual-cap J341 run. The failed
fixture and process sample are retained. No automatic rerun was started.

The separate one-request live context test remains unapproved and unexecuted.
Live experiment usage remains fourteen requests. Module usefulness, structural
DFD comparisons, remaining literal diagram-row formatting and full operator
acceptance are still open.
