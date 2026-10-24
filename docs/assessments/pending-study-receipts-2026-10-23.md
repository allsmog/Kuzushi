# Study reads during startup, October 23, 2026

The [large-diagram journey](large-dfd-investigation-2026-10-23.md) exposed a
ledger refresh error while a child was starting. Queue state already named the
current attempt, but its run metadata or child-consumption receipt had not yet
been published. The findings reader treated that temporary absence as a failure.
Two red checks reproduced both publication windows through the real batch reader.

Required artifact reads now carry a typed `RunArtifactMissing` error. Its display
text, checked paths, containment, byte limits and no-follow behavior are
unchanged. The batch reader returns the additive `BatchReceiptPending` type only
for the current attempt of a queue entry recorded as running, and only for the
exact missing run metadata or child receipt. A child receipt may be pending only
while the run summary is also running. Recorded queue state does not establish
process liveness or authenticate a finding.

Malformed, non-file, unsafe, unrelated and historical receipt failures retain
their errors. Terminal or parked queue states cannot use the pending result.
Neither can a terminal summary. Runtime/configuration and provider checks run
before a missing child receipt can be classified as pending. No completed work
is credited without its authenticated receipts. The typed pending result also
survives the shared finding-page consumer.

The TUI retains loaded findings, durable decisions, draft and navigation origin.
It clears completion qualification while a read is unavailable and presents
`Work receipts pending` with an explicit refresh action. It does not repeatedly
schedule the same read. A later store update or explicit refresh can resume it;
the carried navigation continuation still respects later operator interaction.
Synchronous reads use the same distinction. A later genuine error remains visible
as a failure, and pending feedback does not follow another target.

## Native evidence

Evidence is retained under
`scripts/devex/artifacts/pending-study-receipts-20261023/`.
J346 is `native-attempt-1/native/J346/20261023-195049/J346`:
49 machine passes, zero failures, 31 authenticated text/ANSI captures and three
pending operator judgments. The raw exit remains 4, `REVIEW_REQUIRED`.
The frozen native digest is
`40fded8648848548cce8fba475578cfd4949dc859daec585ec1c63d4c78794a4`.
All 6,447 repository inputs and 13 frozen programs stayed unchanged during the
run on dirty `main` at `f744320dc3ed4cf0ded3122ebbc012e8d6e58479`.

This reruns the owned 95-module source chain with its manual 96-component diagram.
After accepting context, the operator selects the tail beyond the former cutoff,
cancels one draft, then separately approves and launches three fixed installed
Semgrep jobs over the exact tail-file scope. The real pending branch appears in
the captured log. All 31 captures are checked for the former ledger refresh error;
none contain it. The historical pending note remains timestamped in the log tail.

The jobs retain three raw observations under one identity with recurrence three
of three. Review records one deferred decision. JSON export and no-color restart
retain that decision, source fingerprint, immutable context and spending receipt.
All source hashes and the active context stay unchanged. There are three work
attempts, zero provider reservations and zero new model requests. One protected
Review call remains unused. No follow-up, target source execution or extra job
occurs. The cumulative live experiment count stays at 16; no live allowance remains.

Ten ANSI cell replays were inspected: the six diagram sizes, completed jobs,
Review, export and restart. These use Menlo 15 and a chosen dark background,
not OS screenshots. The narrow diagram still discloses its topology fallback.
The dedicated Review pending presentation and stale-process recovery combinations
are not independently qualified by this native run.

## Verification and limits

The Core batch selection passes 41 checks, including eight pending-receipt checks;
five typed artifact-reader checks pass. TUI refresh passes 19 checks, hydration
passes 82 and finding projection passes eight. Four explicitly selected fixture
writers remain ignored across the batch and projection selections. Workspace
build, Core/TUI Clippy with warnings denied, the risk proxy and all ten repository
summary gates pass. The dirty draft receipt is `final-draft-receipt.json` under
the evidence root, separate from the clean signed publication receipt.

Earlier evidence remains retained. One recovery fixture initially put its
database outside `.kuzushi`, correctly triggering frozen-source drift; it now
uses the real workspace database location. Two TUI test results initially used
an uncanonical temporary path and were correctly discarded by target ownership;
the tests now deliver results for the app's owned target. No production guard
was relaxed to make those tests pass.

This resolves the reproduced startup refresh defect on the owned route. It does
not establish general scanner usefulness, process liveness, generated architecture
quality, maximum-size rendering throughput, formal human acceptance or reference
TUI parity. No module tier, public artifact format or broad delivery checkbox
changes. The complete product goal remains active.
