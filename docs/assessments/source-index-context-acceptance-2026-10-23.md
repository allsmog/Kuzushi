# Source indexing and bounded context, 2026-10-23

This draft on main follows `b891f86c842e575850f915a11ed3eaf89d07611b`.
The requested pull found main current and preserved the local changes and
original staged patch. No new commit or push is included.

The [earlier partial-inventory test](partial-evidence-context-2026-10-19.md)
stopped during import after 240 seconds. Source indexing now persists groups of
at most 128 individual journal envelopes with one journal sync and one SQLite
transaction per group. It retains full source blobs, tree identity, envelope
sequences and journal limits. Ordinary finding and human-decision writes retain
their existing behavior. Cancellation is checked during source walking, writer
lock acquisition and between persisted groups. Import reports progress.

A second regression reproduced loss after an interrupted first index: a later
file update retained only 128 of 260 files. An identity-only registered snapshot
similarly retained only one file. Incremental updates now require projected
membership to hash to the recorded tree. An incomplete projection uses the
existing bounded full capture instead. Both regressions pass. The focused
writer tests also cover replay after a subprocess stops following journal sync.

Context planning and approval now resolve the authenticated file-group source
once per preparation, instead of repeating full repository validation. They use
the resulting inventory source identity without a separate redundant tree walk.
Freshness checks before and after source collection and synthesis remain.
Approval compares recorded optional `sourceInventory` with the current receipt.
A regression first demonstrated approval of edited inventory counts with a
recomputed plan digest; that altered draft is now refused before an allowance
is created. Legacy plans without this optional receipt remain readable.

## Verification

Local evidence is under the ignored directory
`scripts/devex/artifacts/context-approval-20261023/`.

| Check | Result |
| --- | --- |
| Focused Rust checks | 276 distinct passing test names across recorded runs; affected context, inventory, index and DFD suites rerun after the final changes |
| Build and lint | Workspace build and Core Clippy with warnings denied passed |
| Repository summary | All ten checks passed, including workspace check, model policy and CRAP-risk; the receipt is a separate dirty draft |
| Identical model-free approval | 52.28 seconds before source reuse, 23.26 seconds after; unchanged call/job limits, no requests or job launch |
| Final J339 | 48 machine passes, zero failures, three formal operator judgments pending; 43 capture sets |
| Final J341 | 29 machine passes, zero failures, three formal operator judgments pending; 29 capture sets |
| Frozen native | SHA-256 `d739344d5edf40c7518af417481d3cdd3f33e32199ad673f1af90d2d5b447457`; 6,390 repository inputs and 13 programs unchanged during the journeys |

J341 retains the actual 100,000-entry inventory ceiling, 512 MiB inspection
ceiling and 256 KiB per-file inspection ceiling. It creates 100,001 empty filler
files, four owned source comments and one separate source file. The final import
completed in 35 whole seconds according to its run receipt. A stable WAL-aware
ledger copy contains all 100,006 indexed source paths. Every retained blob was
compared byte for byte with its source, including the shared empty blob. There
are six distinct blobs, two snapshot records and one distinct content tree;
snapshot registration is separate from full indexed membership. The complete
journal was not independently rehashed by this inspection.

The bounded inventory records 99,995 files and explicitly discloses truncation.
Both selected files are known members. A genuinely absent member is refused;
the fixture no longer assumes filesystem enumeration has lexical ordering.
The supported `campaign:context-map` path supplies a real Map review attempt,
which the TUI accepts explicitly. Selecting the component topology and pressing
`g` prepares both files; entering a focused context row intentionally narrows
the selection to that row.

The final journey keeps one job, one worker, one attempt and one intercepted
request. Three total calls reserve two for Review. The request settles with no
unresolved reservation. The original active context and all selected source
bytes remain unchanged. The inactive result and its partial inventory receipt
survive no-color restart. All original observation limits remain in place,
including the 30-second approval observer. No live inference is used by either
journey.

Nineteen terminal-cell images from these journeys were inspected across all
six sizes, approval, result, Back restoration and restart. These are ANSI cell
replays using Menlo 15 and a chosen dark background, not operating-system
screenshots. Six formal operator judgments remain pending. The forms still
need a stronger first-screen hierarchy: narrow terminals require substantial
paging, long identifiers obscure context names, raw byte limits are hard to
compare, and linked DFD evidence can make leading-space paths ambiguous.

## Approved real-model context result

The separately approved seven-file, 2,221-byte architecture test completed with
one actual OpenAI OAuth request using GPT-6 Luna and low reasoning. This reaches
15 cumulative experiment requests, with none left approved. Dollar cost is
unknown. The original explicitly approved frozen runtime predates the latest
pull; its SHA-256 is
`f6e665d355faf34a01a9fc0ed16a9592b0492fda60f7937457bc2d0c65ebb8a0`.
It does not validate live inference on the newly rebuilt runtime.

The result has seven components, seven flows, one boundary and four open
questions. All 55 source citations resolve to existing selected paths and line
bounds. Its summary distinguishes the two adapters and discloses missing
deployment and authentication-transport evidence. Semantic defects remain:
Principal and Invoice appear as disconnected process nodes, and the response
flow skips the gateway. Valid citations do not establish useful flow semantics.
The result remains an unverified, inactive draft.

The current rebuilt TUI read this exact result across all six sizes and opened
its DFD at three sizes. Nine terminal-cell images were inspected. Before/after
checks retain identical source hashes, active-context manifest, plan, queue,
request/attempt counts and finding/decision counts. No request, acceptance or
new work was triggered. Its older missing inventory receipt is honestly shown
as not recorded. Evidence is in `live-result-readonly/`; the original live
dispatch evidence is under
`scripts/devex/artifacts/live-diagram-context-20261019/control/`.

This closes the concrete wide-context regression locally. Broader module
usefulness, scope proposal quality, experiments, lessons, full investigation
acceptance and reference-level TUI quality remain open. No broad delivery
checkbox changes from this checkpoint. Documentation updates follow the frozen
journeys and are outside their input manifests.
