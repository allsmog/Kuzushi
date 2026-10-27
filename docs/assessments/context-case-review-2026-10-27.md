# Review exact observations from a context experiment

Status: scoped local qualification with remaining interface findings. Operator acceptance and full reference-interface parity remain open.

## Behavior

Context results now expose `f findings`. The picker retains the selected case, lists its recorded findings and opens an explicitly selected observation in the existing Review surface. Review shows source, evidence confidence and decisions. Returning restores the picker, case, reading position, prior filter, selected study and composer draft. A target switch clears the return origin. Finding selection follows the recorded fold key through a refreshed row order.

This closes the direct-navigation gap identified in [the earlier context and lesson assessment](context-learning-2026-10-27.md). Recurrence remains a completed-pass count. Opening Review adds no model request, discovery job, automatic verdict or source execution. Existing pending-read and operator-interaction guards own asynchronous findings refresh; this action uses the same refresh/open effects as the shared finding reader.

Occurrence rows add optional `representativeObservationRef`. Its opaque `generation:<id>` string identifies the representative observation in the original workspace rather than a later fingerprint match. JSON keeps the identifier as a string. Plain receipts and CLI summaries expose the reference too. Missing, malformed or unavailable references remain in the case reader with an explicit error. Old artifacts remain unchanged; [the migration note](../../RELEASING.md#exact-observation-links-in-study-results) covers additive output and Rust struct literals.

The picker reserves visible rows for its controls. Its selection marker and severity remain outside title clipping, including at 40 columns. Independent detail scrolling keeps the original case scroll unchanged.

## Qualification

Retained local evidence root: `scripts/devex/artifacts/case-review-current-20261027/`. These artifact directories are local records, not published source files.

| Check | Result |
| --- | --- |
| Core occurrence and reference behavior | 42 distinct passes across serial runs; see `control/observation-reference-green.log` and `control/observation-reference-final.log` |
| Case-result TUI behavior | 26 passes, zero failures; `control/tui-final.log` |
| Diagram-findings navigation | 12 passes, zero failures; `control/dfd-findings.log` |
| Scope-findings navigation | Five passes, zero failures; `control/scope-findings.log` |
| Locked workspace build | Pass; `control/workspace-build-final-2.log` |
| All-target Core/TUI Clippy | Pass; `control/clippy-final.log` |
| Changed-code risk proxy | Pass; `control/risk-final-2.log` |
| Final native J363 | 87 machine passes, zero failures, nine answered agent screen questions |

The final run is `J363-attempt-2/native/20261027-085337/J363`, using native SHA256 `a2a29cbd6526f7e810bb8b548bf7d72c02f1394747105b998afb588a3d37f6d3`. It freezes all 13 native programs and authenticates 6,837 repository/runtime inputs before and after execution. Both source and staged-index guards pass. The separate 18-file publication request stays byte-identical in the index throughout this work. The signed receipt for the published checkpoint remains unchanged.

Eighty-three authenticated text/ANSI/source-receipt capture triples are retained. Nineteen current ANSI replays were directly inspected, including the picker at 160x48, 120x36, 96x89, 80x24, 60x20 and 40x12; complete narrow reference paging; exact historical Review; both return steps; allowance revision; export; and no-color restart. All nine questions have State, Intent, Honesty and Craft answers in `agent-review.json`. Raw exit 4 remains `REVIEW_REQUIRED`, agent judgment is `PASS_WITH_FINDINGS`, and operator acceptance is false.

## Independent state checks

At the new Review step, the rendered `Reopen this observation` reference matches the original Alpha ledger generation. It differs from the later Beta generation sharing the same fingerprint. The fixture still has five intercepted requests, three raw observations and zero decisions at that point. This check reads the actual displayed reference and does not assume that optional review-session logging is enabled.

The terminal ledger and JSON export are reconciled using a stable immutable copy after verifying that the live WAL is absent or empty. Both case references resolve to an observation in that case's recorded run set. Source bytes, the globally active Gamma context and accepted job membership remain unchanged.

The final matrix retains six fixed jobs, seven attempts including the original failure, four observations and two scripted operator decision records. Alpha recurrence is 3/3 and Beta is 1/3. Seven intercepted provider requests are settled, two protected Review calls remain unused, and unknown dollar charges remain unknown. Restart creates no new work. `independent-end-state.json`, `exact-observation-check.json` and `capture-hashes.json` retain these checks.

## Retained failures

The first reference regression failed because occurrence output had no exact observation link. The first wider Core run passed 41 checks and found a setup error in the new regression: the later test run had not been registered before insertion. After correction, the remaining reference test passes, including reopening the earlier generation after a later matching fingerprint appears.

The first TUI run found three new fixtures using a temporary-path alias rather than the app's canonical target when seeding its cache. It also caught an existing control-position assertion that still assumed three footer rows. The fixtures now use the active target and the test selects the reading-position row by meaning. All 26 checks pass. Early risk checks also caught an oversized renderer and branchy handlers; small named helpers keep the changed code within the gate.

Native attempt 1 completed 87 machine checks but screen review found that long titles could clip the selection marker and severity at 40 columns. That candidate is retained with a blocking screen finding. The corrected formatter fits only the title and preserves the fixed prefix. A focused assertion checks that visible prefix at every viewport. Attempt 2 completes the unchanged machine assertions with the corrected marker visible. No assertion or driver was weakened.

## Remaining limits

The fixture contains inert owned greeting text and explicitly labeled policy observations. Every provider request is intercepted, with no network fallback or real credentials. Target source is never executed. This increment adds zero live provider requests; the earlier twenty-request live allowance remains exhausted.

The manually declared Alpha and Beta context drafts report failed grounding. This tests exact selection and source isolation, not successful Map grounding, model accuracy or vulnerability proof. It does not qualify broad monorepo throughput or the complete installed adapter dependency closure.

The one-finding wide picker remains sparse and repeats the finding title in its list and detail. Complete case receipts remain dense with ids and hashes. Session dollars still compete with the unavailable investigation-cost disclosure. Legacy scanner confidence wording also needs clearer emphasis relative to the evidence-confidence axis. ANSI replays use Menlo 15 and a disclosed dark background and are not OS screenshots; physical-terminal font fallback remains unproven. Broader [bounded-investigation acceptance](../quality/bounded-investigation-acceptance.md) remains open.
