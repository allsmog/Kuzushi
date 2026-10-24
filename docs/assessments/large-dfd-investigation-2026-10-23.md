# Large diagram investigation, October 23, 2026

The shared DFD parser silently retained only the first 64 valid nodes and flows.
Imported or saved contexts could contain more. The displayed totals, selection,
linked source and scoped actions therefore omitted later components. Two red
checks reproduced 1,024 nodes becoming 64 and the missing tail of a 96-node graph.

Parsing now preserves every valid element of the bounded context document.
Saved context JSON retains its existing 16 MiB storage limit. One node index
replaces repeated name and zone searches while parsing flows; duplicate legacy
IDs keep their first recorded name and zone. Trust-zone order remains stable.
This does not qualify rendering performance at the storage ceiling.

Visual inspection exposed two related presentation defects. Wide and stacked
layouts selected the right neighbor zone but left its relevant source on another
page. They now share the causal layout's choice of a connected flow and page its
endpoints into view. Selected boundaries use their recorded crossing. A node
prefers its first outgoing flow, then its first incoming flow; this is browsing
context, not a claim that all adjacent flows fit on screen.

Stacked connectors also always pointed down, even when selection placed the
destination above its source. The arrow now follows the recorded flow direction.
Two neighborhood regressions and one direction regression failed before their
respective fixes. Existing selection, context, paths, schema and tool contracts
remain unchanged. No stored artifact migration is needed.

## Native investigation evidence

Evidence is retained under
`scripts/devex/artifacts/large-dfd-navigation-20261023/`.
Final J346 is `native-attempt-3/native/J346/20261023-192242/J346`:
48 machine passes, zero failures, 31 authenticated text/ANSI captures and three
pending operator judgments. Raw exit 4 remains `REVIEW_REQUIRED`.
The frozen native digest is
`24faa497f1ef0872e151626e8df55151d86d9934af677f2d2123c237c6b52182`.
All 6,441 repository inputs and 13 frozen programs remained unchanged during
the run on dirty `main` at `f744320dc3ed4cf0ded3122ebbc012e8d6e58479`.

The owned non-Git fixture contains 95 inert Python modules plus a README. Each
module contains the same harmless owner-policy marker. Its manually imported
context declares 96 components, 95 transfers and two boundaries, with explicit
source links. The declaration does not prove deployed isolation, runtime flows
or a vulnerability. No target module is imported or executed.

The operator accepts the context, selects its last component, inspects the
diagram and opens a study for exactly `modules/worker_095.py`. Canceling the
first draft returns to that selection and creates no plan, queue, observation,
work attempt or provider reservation. A new draft freezes three jobs with one
worker, one attempt each and the exact accepted context. Approval starts no work;
launch is separate. The installed Semgrep engine completes all three attempts.
Each result contains one observation at the selected tail file; the batch has
one identity with recurrence three of three. The other modules' identical
markers make accidental whole-repository discovery visible to this fixture.
Subprocess arguments were not separately recorded by this observer.

Review preserves the source excerpt and an explicit deferred decision. JSON
export retains three raw observations, one reviewed finding, zero confirmed
findings, the immutable context, source fingerprint and allowance. Restart with
no color preserves that result and decision without new work. Source hashes
and the active context remain unchanged throughout. The source is unversioned;
this fixture makes no cross-SHA applicability claim.

The shared allowance has one call, entirely protected for Review. Discovery
therefore has no provider capacity. All three jobs are runtime-free. There are
zero provider reservations or requests, and one unused protected Review call
remains after export and restart. No model-backed follow-up is approved or run.
The cumulative live experiment count stays at 16, with no live allowance left.

Reading covers 160x48, 120x36, 96x89, 80x24, 60x20 and 40x12. At 40x12 the
inspector discloses that topology needs more space and retains the selected name
and visible actions. Fifteen final ANSI cell replays were inspected, including
all six sizes, cancellation, approval, completion, Review, export and restart.
They use Menlo 15 and a chosen dark background, not OS screenshots. Earlier
native attempts and all red test output remain retained. The journey harness
and agent instructions are unchanged.

## Checks and open qualification

Six parser checks, three neighborhood checks and the final 114-check DFD suite
pass; those selections overlap. Workspace build, TUI Clippy with warnings denied,
the risk proxy and all ten repository summary gates pass. The draft receipt is
`final-draft-receipt.json` under the evidence root. It is not a signed clean
publication receipt. No complete workspace Rust test result is claimed.

All three native runs also expose a ledger refresh error during child startup.
In the final completion capture, prior errors for trials two and three remain
in the visible log tail even though authenticated recurrence and later Review,
Report and restart succeed. Their timing is consistent with a read preceding
child receipt publication; that cause needs a focused reproducer. This is an
open workflow defect, not a failed scan or permission to relax receipt checks.
The next correction must distinguish an in-progress read from a terminal
missing or malformed receipt, preserve the last honest projection, and retain
strict rejection of unauthenticated completed work.

The subsequent [study receipt correction](pending-study-receipts-2026-10-23.md)
reproduces both publication windows and resolves this error on the owned route.
Its J346 has 49 machine passes, zero failures and observed pending feedback with
no ledger refresh error across 31 captures. The three operator judgments remain
pending; the earlier error captures above remain historical evidence.

This increment qualifies the owned large-diagram route through local discovery,
human triage, export and restart. Generated architecture usefulness, maximum-size
render throughput, broader failure combinations, formal human acceptance and
reference TUI parity remain open. No module tier or broad delivery checkbox is
changed, and the complete product goal remains active.
