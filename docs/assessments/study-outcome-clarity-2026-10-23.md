# Study outcomes describe work and severity, October 23, 2026

A completed study with findings previously said `security disabled` when no
optional severity cutoff was configured. That wording described the gate setting
as a security verdict. The same row reported `blocking 0` and an unwritten SARIF
export even when neither policy was requested. A long equivalence key preceded
the finding claim. Four focused regressions reproduce those presentation defects.

The shared findings presentation now says `Severity cutoff: not configured`,
reports reached or not reached with the qualifying count when a cutoff exists,
and says `Severity assessment: unavailable` when the receipt is absent. The
count explicitly concerns completed passes. Work completion, failures and pending
trials remain separate, as does the warning that recurrence does not establish
proof. The TUI and headless human output share these meanings. Stored gate schema,
status fields, thresholds, folding, suppression policy and exit behavior do not
change. Existing artifacts need no migration.

Finding titles and locations precede the equivalence key. Full finding identities,
run references and equivalence text remain available at narrow widths. Empty
results retain their receipt. Only a requested SARIF export receives a saved or
not-saved line in the TUI. No findings, decisions, jobs or model work are added by
this presentation change.

The first native run exposed receipt loss during background refresh: the
standalone study read had an authenticated gate, but finding membership used
the controller projection, which intentionally omits gate metadata. Applying
that projection replaced the displayed receipt with an absent one. The run
retains 41 machine passes and this failure; it did not reach triage/export.

A focused Core regression reproduces the loss. Finding-page snapshots now
authenticate optional gate metadata after binding membership and its cursor.
The in-process `FindingPageSnapshot` adds `study_gate_error`. A stale or malformed
severity receipt remains unavailable and surfaces a transient warning without
widening finding membership or blocking triage. The strict standalone batch
reader still rejects invalid receipts. Missing trial evidence remains a hard
error or the existing typed startup-pending result. Metadata-only gate changes
do not invalidate a membership cursor. No old assessment is carried forward.

## Current evidence

Final evidence is retained under `scripts/devex/artifacts/study-outcome-hierarchy-20261023/`.
The final J346 case is `native-attempt-2/native/J346/20261023-205917/J346`.
It records 60 machine passes, zero failures, 50 captures and three pending
operator judgments. Raw exit 4 remains `REVIEW_REQUIRED`. All 6,453 source inputs
and 13 frozen programs stayed unchanged through the native run on dirty `main`
at `f744320dc3ed4cf0ded3122ebbc012e8d6e58479`. The native SHA-256 is
`60453e114cd61cc1fa0dfe5d6b25f5ca266a6570ca59a2d82f905e59ada1d414`.

The owned fixture has 96 declared components and 95 flows. The operator accepts
context, selects the tail file, approves three fixed installed-engine jobs with
one worker and one attempt each, then separately launches them. Three raw
observations consolidate to one identity. A human deferral, JSON export and
no-color restart retain exact source/context provenance and spending. No target
source executes. The one protected Review call stays unused. No model or provider
request is made; cumulative live experiment use remains 16 with no allowance left.

Independent checks compare the immutable plan, queue, gate JSON, exported report,
ledger counts and source hashes. They confirm three work attempts, three producer
observations, one human decision and zero provider reservations. The standalone
human output agrees with the recorded disabled optional cutoff, while describing
it as unconfigured. Stored status values remain unchanged. All six outcome
viewport groups retain the cutoff caption, finding, source location and receipt
heading across their captured pages. Background refresh no longer loses the gate.

Twenty-one distinct final ANSI cell replays were inspected, including all six
sizes, narrow pagination, the exact finding, export and recovered Report. These
use Menlo 15 and a chosen dark background, not OS screenshots. Full wrapped
identities, paths, run references and equivalence text are also checked directly
at widths 40, 60, 80, 96, 120 and 160. The primary finding precedes receipt metadata;
controls, completed-work counts and the recurrence limitation remain available.

The final focused matrix has 170 passing Rust checks: six severity presentation,
45 batch receipt/occurrence, 27 finding-page, nine TUI projection, 19 background
refresh and 64 campaign rendering checks. Four explicit native fixture writers
remain ignored. Workspace build, Core/TUI Clippy with warnings denied, the risk
proxy over 85 changed code files and all ten repository summary gates pass. The
dirty draft receipt is `final-draft-receipt.json` under the evidence root. Clean
signed publication receipts are preserved. No full workspace Rust test or release
qualification is claimed.

The earlier native failure and focused red regressions remain retained. A first
compile also corrected use of the existing severity label method. No guard is
relaxed to obtain the passing result. This increment does not close the broad
module-value, model-quality, formal operator or reference-product parity items.
The complete product goal remains active.

