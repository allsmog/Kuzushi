# Trust calibration + recipient/export hardening proposal

Stage 1 only (strongest-model direction). Re-verified against the dirty tree on
2026-08-18. No production or test source was edited.

## Verdict summary

| Item | Verdict | Why |
| --- | --- | --- |
| Proof meter treats verification infrastructure failure as disproof | **PROPOSE** | Confirmed; the TUI assigns `Rejected` locally while the canonical classifier preserves static evidence. |
| Three colliding “confidence” concepts / unannounced default order | **PROPOSE** | Confirmed; copy can distinguish proof band from author-reported decision score and name the order. |
| Glyphs and author markers are undecoded / `@?` is ambiguous | **PROPOSE** | Partly improved since the audit (`● proof · s sources · @ author` now exists), but still not decoded and no-decision still maps to `@?`. |
| Conflict signal flattens scanner recurrence and proof contradiction | **PROPOSE (bounded)** | Confirmed; current TUI and export duplicate a single `reappeared_after_rejection` rule. Add evidence-sensitive conflict kinds. |
| Personal calibration loop | **DEFER** | The review record has `TriageAuthor::Human`, but no stable actor for ordinary decisions; calling a workspace-wide human aggregate “your hit rate” would be dishonest. |
| Markdown bundle drops remediation prose and uses internal framing | **PROPOSE** | Confirmed; all prose is already on `WorkspaceFindingExportRecord`, but the renderer never consumes it. |
| Zero-evidence findings export as `source_linked` | **PROPOSE** | Confirmed; constructor-derived source signatures and automatic source occurrence rows are not evidence, yet currently satisfy the state predicate. |
| SARIF flattens critical/high and offers no rule help | **PROPOSE** | Confirmed; both map to `error`, and rule properties lack GitHub `security-severity`; `help.text` is absent. |
| Fix-page/autonomy “fix” collision | **PROPOSE** | Confirmed, minor copy defect; the footer says only `⛭ fix`. |
| Receipts hide tool keys | **PROPOSE** | Confirmed; the comment explicitly says the result heading intentionally removes the registry key. |
| Narrow Setup explanatory copy | **DEFER to hostile-terminal workstream** | Confirmed at the renderer, but changing line allocation risks hiding the Start Map row/summary and overlaps Setup layout work. |

## A. Proof and Review surface

### A1. Derive every meter tier from the canonical classifier

Evidence:

- `crates/kuzushi-tui/src/ui_view_models/findings.rs:1520-1533` derives the meter from a separate local `ProofTier` path.
- `crates/kuzushi-tui/src/ui_view_models/findings.rs:1546-1565` maps `HarnessFailedToBuild` and `InfrastructureError` to `ProofTier::Rejected`.
- `crates/kuzushi-core/src/findings/presentation/detail/proof_ladder.rs:50-70` uses the canonical ladder; infrastructure outcomes are not rejection evidence, so linked static evidence remains `Likely`.
- The local code also labels any persisted `Exploited` verdict as verified without calling `PersistedVerification::is_empirically_verified`, while the canonical path requires authenticated provenance (`persisted_results.rs:358-370`).

Precise change:

1. In `crates/kuzushi-tui/src/ui_view_models/findings.rs`, add the single pure mapping `ProofConfidence -> ProofTier` (`Confirmed -> RuntimeVerified`, `Likely -> StaticLinked`, `Unverified -> Suspected`, `Dismissed -> Rejected`).
2. Make `finding_proof_badge` compute its tier only from `ProofConfidence::classify(finding)`. Keep the granular label (`verify-build`, `verify-infra`, `not reproduced`) as context, but do not let a failed attempt overwrite the surviving proof band.
3. Make `finding_proof_meter` consume the same canonical band/mapping, not call a second classifier.
4. For runtime labels, use `runtime_validation_summary(Some(verification))` (already provenance-aware in `proof_state_label.rs:236-255`) rather than treating raw `Exploited` as verified. Preserve the static label fallback for model/not-attempted verification.

Required regression tests in
`crates/kuzushi-tui/src/ui_view_models/findings/tests.rs` beside
`finding_proof_label_prioritizes_runtime_and_static_evidence`:

- infrastructure error + `SourceSinkLinked` => label `verify-infra`, meter `[●●○]`, tier `StaticLinked`, canonical band `Likely`;
- harness build failure without static evidence => `[●○○]`, `Suspected`, `Unverified` (never `[×××]`);
- `NotReproduced` + code-cited/static-linked evidence retains the matching static meter while naming the failed reproduction;
- raw legacy `Exploited` without authenticated reproducer provenance never renders `[●●●]` or “verified”; a real `test_empirical_verification` still does.

### A2. Rename the quantities, announce the order, and decode row signals

Evidence:

- `detail_pane.rs:77-96` calls the canonical band simply `confidence`.
- `detail_pane.rs:318-335` calls the decision author's score `confidence` again.
- `review_queue.rs:387-398` emits the unexplained `conf:NN%`.
- `ui_view_models/review_queue.rs:131-158,175-185` exposes an ordering indicator only when Learn mode overrides order; the default proof-first order is silent.
- `panes/review_queue.rs:71-86` now has a partial legend, but `:333-340` still maps both no decision and an unknown author to `@?`.
- `phase_pages/confirm.rs:447-453` still emits undecoded `RTV/LIK/UNV/DIS`.

Precise change:

1. In `renderer/views/workbench/detail_pane.rs`, render `proof band: …` and `decision score: …`; the latter must append `author-reported; not proof` for automated/model decisions.
2. In `renderer/views/workbench/panes/review_queue.rs`, replace `conf:NN%` with `decision-score:NN%`. Add `BASELINE_ORDERING_INDICATOR = "order: proof band first · severity second"` in `ui_view_models/review_queue.rs`; return it for the normal queue, keep the existing Learn indicator when Learn truly reorders, and rely on the backlog header's existing `severity-first` disclosure in backlog mode.
3. Map decision author `"-"` to `@–`; reserve `@?` for an unrecognized nonempty author. Replace the partial legend with responsive legend atoms that decode all visible values: meter bands (runtime/static/signal/dismissed), `s#`, `@H`, `@A`, `@I`, `@–`, and `@?`. At narrow widths do not add four permanent chrome rows: the row already spells runtime/static/signal/dismissed, so show only the compact source/author legend.
4. In `phase_pages/confirm.rs`, replace `RTV/LIK/UNV/DIS` with the already-used compact plain labels `runtime/static/signal/dismissed`; no new legend is then needed.

Regression tests:

- Update `renderer/views/workbench/panes/review_queue.rs` tests to assert the baseline order line by default, Learn replacement, backlog `severity-first`, `decision-score` framing, `@–` for no decision, `@?` only for unknown, and full legend coverage at 120 columns without losing selected rows at 33/60 columns.
- Update `renderer/views/workbench/detail_pane.rs` tests around lines 973-1027 to assert `proof band`, `decision score`, and the automated-score disclaimer; assert the old bare `confidence:`/`conf:` copy is absent.
- Add a compact Prove renderer test in `phase_pages/confirm.rs` covering all four plain band words and absence of `RTV/LIK/UNV/DIS`.

### A3. Split review conflicts by evidence strength; centralize the rule

Evidence:

- `ui_view_models/review_conflicts.rs:5-29` returns only `reappeared_after_rejection`.
- `workspace/application/export_review_context.rs:79-87` duplicates the same policy, creating a TUI/export drift risk.

Precise change:

1. Add a small pure core domain helper (for example
`crates/kuzushi-core/src/findings/domain/review_decision_conflict.rs`) returning a closed enum and stable export tokens:
   - carried false-positive rejection + authenticated empirical proof: `runtime_verified_after_rejection`;
   - carried false-positive rejection + active scanner/static signal: preserve compatibility token `reappeared_after_rejection`;
   - carried `Confirmed|ToFix` + `NotReproduced`: `not_reproduced_after_confirmation` (worded as re-review, never “refuted”).
2. Have both TUI and `WorkspaceFindingReviewContext` call this helper. The renderer maps them to `conflict:runtime-verified`, `conflict:scanner-reappeared`, and `conflict:not-reproduced` rather than flattening all to `reappeared`.
3. Do not infer a personal score. A later schema migration must attach a stable actor to every ordinary `ReviewDecisionRecord` (not only dismissal `actor`) before an operator-specific calibration fold is possible.

Regression tests:

- Extend `ui_view_models/tests/review_state.rs` and `ui_view_models/tests/review_queue.rs` with all three kinds and assert every conflict keeps the row open.
- Extend `workspace/tests.rs::exports_reappeared_rejected_identity_as_open_conflict` to cover strong runtime contradiction and confirmed/not-reproduced export tokens, proving TUI/export parity.

## B. Human handoff and machine exports

### B1. Render the enrichment prose in every Markdown finding

Evidence:

- `export_projection_model.rs:60-73` carries `recommendation`, `impact`, `category`, `exploit_scenario`, and `preconditions`.
- `export_projection.rs:160-171` fills them from the finding.
- `export_markdown_bundle.rs:257-270` renders only header, message, and evidence; none of the enrichment prose is consumed. `push_bundle_remediation` at `:326-365` is patch-lifecycle metadata, not producer fix guidance.

Precise change in
`crates/kuzushi-core/src/workspace/application/export_markdown_bundle.rs`:

1. Add `push_bundle_security_context(out, record)` between the summary header and scanner message.
2. When present, render plain-language sections/fields: `Recommended change`, `Impact`, `Exploit scenario`, `Preconditions` (one escaped bullet per item), and `Category`. Do not synthesize missing prose and do not fall back from impact to review rationale.
3. Reuse the existing hostile-Markdown escaping helpers for every producer-owned string. Keep patch application state under its distinct `Remediation` label.

Regression test in `crates/kuzushi-core/src/workspace/tests.rs`:

- persist a finding with sentinel values in all five fields, export a Markdown bundle, and assert every value appears in `findings/F-0001.md` under the correct heading;
- assert a sparse finding does not get empty/fabricated sections;
- include newline, brackets, `@`, and backticks in a recommendation/precondition to prove the existing injection boundary still holds.

### B2. Make the bundle README recipient-facing and make omissions exhaustive

Evidence:

- `export_markdown_bundle.rs:85-103` exposes the Rust type name and a bare `Completeness: all`.
- `:151-170` labels `proof_confidence` simply `Confidence`.
- `export_metadata.rs:85-101` omits only a subset of fields actually absent from Markdown.

Precise change:

1. Replace the human README's projection line with two short framing paragraphs: Kuzushi combines scanner output with automated/AI-assisted analysis; findings require review. Define the four proof bands in evidence terms (`confirmed` = authenticated runtime reproduction, `likely` = linked static/code evidence, `unverified` = claim not yet promoted, `dismissed` = rejected/suppressed), without implying that model scores are proof.
2. Rename `Completeness` to `Finding selection` and combine it with `Included N of M`; state that this is row completeness, not field completeness. Rename the table column and per-finding line to `Proof band`.
3. Remove `WorkspaceFindingExportRecord` from the README only; retain `metadata.projection` in `manifest.json` for machine consumers.
4. Change the README omission line to `Field coverage: human-readable subset; see manifest.json metadata.omittedFields`.
5. Audit `MARKDOWN_BUNDLE_OMITTED` against the actual renderer. At minimum add currently unrendered `kind`, `triageState`, `dismissal`, `suppressed`, `location.endLine`, `evidence.evidenceConfidenceMax`, `analysis.humanReviewPresent`, granular verification fields not rendered as fields, `vulnSource`, `provenance.kuzushiVersion`, and `remediation.findingScanId`; keep the existing omitted entries. Do **not** list the five enrichment fields after B1 renders them.

Regression tests:

- Update `exports_workspace_findings_to_markdown_bundle` to assert recipient framing, proof-band definitions, no Rust type in README, and row-vs-field completeness wording.
- Add a table-driven metadata test that asserts every intentionally omitted Markdown path is present and every newly rendered enrichment path is absent from `omittedFields`.

### B3. Make `message_only` reachable using evidence, not identity metadata

Evidence:

- `export_projection.rs:323-329` passes `source_signature.is_some()` as `has_source_link`.
- every constructor computes that signature (`findings/domain/extract_cwe.rs:185-194`), and persistence also creates occurrence-oriented `FindingSource` rows (`finding_sources.rs:49-63`). Neither is inspectable finding evidence.

Precise change:

1. In `export_projection.rs`, replace the current `derived_source_present`/`has_source_link` predicate with a pure `has_source_grounding` predicate based on explicit static proof that cites or analyzes source (`CodeCited`, `SourceSinkLinked`, `SanitizerChecked`, `StaticallyConfirmed`, or `StaticallyRejected`). `SignalOnly`, `NeedsRuntimeEvidence`, automatic source occurrence rows, and an identity signature alone are false.
2. Feed that same boolean to `WorkspaceEvidenceExportSummary.derived_source_present` and `evidence_state_label`; do not maintain two meanings.
3. This changes exported boolean semantics, so document it in `RELEASING.md` and the export contract docs as a correction: source signatures remain available in provenance, but no longer masquerade as evidence.

Regression tests in `workspace/application/tests/export_projection.rs`:

- a fresh `Finding::new_tool` with zero evidence/static proof => `message_only`, `derived_source_present=false`;
- `CodeCited`/`SourceSinkLinked` with no evidence rows => `source_linked`;
- two independent sources still => `corroborated`;
- observed and model-generated evidence retain precedence over source-linked state.

### B4. Preserve security severity and useful guidance in SARIF

Evidence:

- `export_sarif.rs:161-172` emits descriptions but no `help`.
- `:389-395` maps critical and high to the same SARIF `error` level.
- GitHub's current primary documentation recommends rule
`properties.security-severity` (string score 0.1-10.0) for security rules and
uses it to distinguish critical/high/medium/low; it also displays `help.text`
or `help.markdown`: <https://docs.github.com/en/enterprise-cloud@latest/code-security/reference/code-scanning/sarif-files/sarif-support>.

Precise change in `export_sarif.rs`:

1. Keep standard `result.level` (SARIF only has note/warning/error), but add rule property `security-severity`: critical `9.1`, high `8.0`, medium `5.0`, low `2.0`, info `0.1`; omit it for unknown. Ensure every emitted vulnerability rule has the `security` tag, appending CWE when present.
2. Add `help.text`: use `Recommended change: <record.recommendation>` when supplied; otherwise use a fixed honest instruction to inspect the result message, proof band, and evidence properties. Do not add `helpUri`: Kuzushi has no stable per-rule documentation URL, and a generic repository link would pretend to offer rule help.
3. Add a small `sarif_hunt_properties` merge carrying recommendation, impact, category, exploit scenario, preconditions, and `kuzushiTriageState`, so SARIF no longer silently drops data that its metadata claims to include. Keep `references` as the declared omission.
4. When duplicate records share a rule id, choose the highest severity for rule-level `security-severity`/default configuration (result-level `level` remains per finding); never depend on incidental first-row order.

Regression tests in `workspace/application/tests/export_sarif.rs` plus the existing integration export test:

- critical and high rules both have `level:error` but distinct `security-severity` (`9.1` vs `8.0`);
- security tag exists with and without a CWE, and CWE is appended once;
- supplied recommendation appears in `help.text` and `kuzushiRecommendation`; sparse records receive no fabricated recommendation property;
- duplicate rule records pick the maximum rule severity while preserving each result's own `level`;
- unknown severity omits `security-severity` rather than inventing a score.

## C. Small vocabulary/graduation fixes

### C1. Disambiguate the autonomy ceiling from the Fix phase

Change `ui_view_models/journey.rs:783-790` from `⛭ fix` to
`⛭ autonomy:fix` (and corresponding rungs). Keep the warning suffix. Update
`journey.rs` unit coverage, `status_footer`/rail expectations, and the footer
snapshot at `renderer/chrome/footer/justify_prefer_right.rs:294`. Add an app
test that a locked-page notice can coexist with `autonomy:fix` without the
footer presenting the same bare noun twice.

### C2. Put the registry key back beside the friendly receipt name

Change `run_lifecycle/application/presentation/display/payload.rs:144-153`
from `Result · <friendly name> · …` to
`Result · <friendly name> (<module:tool>) · …`. This retains scanability and
teaches the exact dispatch key without claiming that re-running without the
original options is equivalent. Update the contradictory comment at `:145-147`.

Regression test in
`run_lifecycle/application/presentation/tests.rs::result_display_skips_the_preview_line_that_restates_the_summary`:
assert the first line contains both the friendly label and exact tool key, and
that preview de-duplication remains unchanged.

## Explicit deferrals/rejections

- **Personal “your hit rate”: defer.** First migrate ordinary human review decisions to carry a stable actor identity and define privacy/aggregation scope; then build a fold over later authenticated proof outcomes. Workspace-wide `Human` is not personal identity.
- **`helpUri`: reject for now.** Add `help.text`; do not link every rule to a generic repository homepage. Revisit when stable per-rule documentation URLs exist.
- **Narrow Setup copy: defer to the Setup/hostile-terminal workstream.** `setup.rs:26-50,109-126` puts full detail on the compact row and truncates it. A safe fix needs a height-budgeted selected-row detail line plus tests proving Start Map and the summary remain reachable at 40x12; it should not be slipped into trust/export changes.

## Suggested implementation order

1. A1 proof-meter canonicalization (highest trust risk).
2. B1+B2 Markdown remediation and recipient framing (handoff-critical).
3. B3+B4 export evidence/SARIF correctness.
4. A2 vocabulary/order/legend, then A3 conflict taxonomy.
5. C1+C2 small copy/graduation changes.

Each implementation commit should run the narrow crate tests named above and
`pnpm quality:crap-risk`; broad verification, if needed, should use
`pnpm verify:quick:summary` per repository instructions.
