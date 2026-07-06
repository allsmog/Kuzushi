# Redesign Current State And Plan

This note records the implementation baseline for mapping the Fable UX/data
recommendations onto Kuzushi's real defensive scanner domain.

## 1. Architecture Summary

Kuzushi has one live Rust module boundary. Scan, shell, and run modes should
prepare descriptor-backed input through `ModuleRegistry::prepare_tool_input`
and execute through `dispatch_prepared_tool_with_runtime`. Rust built-ins own
product behavior; the retained TypeScript module SDK is compatibility surface
for external modules and tests.

The important bounded contexts for this redesign are findings, run artifacts,
workspace/export, and the Ratatui shell. Scanner output must stay distinct
from operator review state: detectors emit findings, proof, evidence, and run
artifacts; humans and model triage add decisions and rationale.

## 2. TUI Structure

The shell is Rust-native under `crates/kuzushi-tui`. `ShellView::Workbench` is
already the main review cockpit, with source, center, findings, and details
panes. The redesign should refine the existing Workbench rather than replace
it with a generic dashboard.

Workbench rendering currently consumes view models from
`crates/kuzushi-tui/src/ui_view_models`. Finding rows expose severity, verdict,
confidence, proof label, CWE, source, evidence, and selection state. Details
render proof, runtime verification, next action, triage, evidence, scanner
message, and stable identifiers.

## 3. Data Model

The core persisted `Finding` lives in
`crates/kuzushi-core/src/findings/domain/finding_record.rs`. It includes:

- machine scanner fields: fingerprint, rule, severity, path, line range,
  message, tool, source, evidence, static proof, verification;
- review fields: triage verdict, triage author, confidence, rationale,
  suppression/snooze, remediation, references;
- dedupe/provenance fields: actor fingerprint, dedup key, source signature,
  corroboration count.

Current risk: fingerprint and dedupe helpers still use line-derived inputs in
places. The legacy fingerprint collision migration now runs transactionally
and preserves child evidence, triage/review history, verification rows,
patch-result linkage, and review compatibility fields before removing the
duplicate row.

## 4. Persistence Model

`FindingStore` is SQLite-backed under
`crates/kuzushi-core/src/findings/persistence/open`. The schema has
`scan_runs`, `findings`, `triage`, `finding_evidence`, `verifications`,
`patch_results`, and `finding_sources`.

Current risk: `triage` is a single latest row per finding with sticky human
triage semantics. The redesign needs append-only review decisions or an
equivalent audit trail before richer review workflows depend on it.

## 5. Report Generation Path

Workspace exports start in
`crates/kuzushi-core/src/workspace/application/export_workspace_findings.rs`
and fan out to JSON, JSONL, SARIF, CSV, and markdown bundle renderers. PR
comments use `crates/kuzushi-core/src/findings/presentation/pr_comment`.

Current exports read raw findings directly. The redesign should introduce a
canonical report projection that carries severity, confidence, review decision,
proof state, verification, evidence, run/model provenance, suppressions, and
audit history without implying remediation from absence.

## 6. Files To Change First

- `crates/kuzushi-cli/src/application/runs_diff.rs`: rename absent-in-compare
  category from `fixed` to `not_seen`.
- `crates/kuzushi-cli/src/application/suppressions.rs`: require explicit
  target instead of silently using the current directory.
- `crates/kuzushi-tui/src/renderer/views/workbench/detail_pane.rs`: separate
  proof wording from confirmation/triage wording.
- `crates/kuzushi-tui/src/ui_view_models/findings.rs`: keep detector severity,
  confidence, proof, verification, and review decision as separate fields.
- `crates/kuzushi-core/src/findings/domain/*`: add explicit review decision
  and lifecycle types before changing persistence.
- `crates/kuzushi-core/src/findings/persistence/open/*`: add migrations only
  after the domain model and tests are stable.
- `crates/kuzushi-core/src/workspace/application/export_*`: route exports
  through a canonical report projection.

## 7. Risks And Unknowns

- Run diffs currently say `fixed` when a finding is merely absent from the
  comparison run. That can mislead users into believing remediation happened.
- Suppression commands still had a path to default to `.`. Bug-bounty scope
  discipline requires explicit target consent.
- Human review state is sticky but not append-only. Richer review screens need
  an auditable decision history.
- Legacy fingerprint collisions now copy child data to the surviving finding
  in a transaction before removing the duplicate row. Future migrations must
  keep this copy-forward posture and never drop evidence/review data without an
  explicit operator-controlled migration.
- Live run tests now drain the unified `LiveRunEvent` channel, applying trace
  and scan events before terminal tool events. Activity assertions should match
  the runtime routing path instead of relying on the retired direct tool
  channel.
- `taint-iris:hunt` currently delegates to the `taint-iris-next` report shape
  and may persist findings without structured `data.flows[]`. AttackPath
  auto-open must stay gated on an actual taint-flow snapshot, not on the tool
  name alone; the legacy descriptor declares `mcps` so callers can explicitly
  opt out where appropriate.
- Export formats are inconsistent in the review/proof fields they surface.

## 8. Implementation Plan

Phase 1: semantic safety fixes and data foundations. Rename misleading
run-diff labels, require explicit targets for suppressions, add review-decision
domain types, and test the behavior.

Phase 2: selectors and view models. Build canonical selectors that separate
scanner status, proof state, verification state, priority, confidence, and
operator decision.

Phase 3: Workbench state. Wire filters, focus, and detail state through the
view models without duplicating scanner semantics in renderers.

Phase 4: screens. Update Workbench, finding detail, run diff, and report
surfaces to use real scanner terminology.

Phase 5: CLI/report output. Route JSON, JSONL, SARIF, CSV, markdown bundle,
and PR comments through a canonical report projection.

Phase 6: tests and migration checks. Add focused unit tests near each helper,
integration tests for CLI output and persistence, and regression tests proving
evidence/review data survives migration and export.
