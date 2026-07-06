# REAL_IMPLEMENTATION_SPEC.md

Implementation-ready specification for applying the accepted Fable
recommendations to Kuzushi without losing scanner semantics.

## 1. UX Changes

### Workbench Review Queue

- Keep `ShellView::Workbench` as the primary TUI cockpit.
- In the findings pane, every row must show:
  - alias / durable identity
  - title and location
  - severity
  - confidence
  - derived priority order
  - lifecycle status
  - human decision
  - proof/static-verification summary
- Do not collapse severity, confidence, status, decision, and proof into one
  "confirmation" badge.
- Add a reconciliation header:
  - `showing X of Y`
  - active filters
  - open/complete mode
  - sorted by priority unless another sort is named
- Empty states must say exactly why the list is empty:
  - not run yet
  - run in progress
  - completed with zero findings
  - failed
  - cancelled/partial
  - filtered out

### Finding Detail

- Restructure detail content into these sections:
  - Claim: alias, kind/rule, title, location, producing tool.
  - Signals: severity, confidence, derived priority, lifecycle status,
    current human decision.
  - Evidence: observed code/capture evidence, source references, stale markers.
  - Analysis: static proof state, dataflow/structural evidence, model reasoning
    explicitly labeled as model-generated when applicable.
  - Verification: latest static/runtime verification record, with limits.
  - Decision: current decision and decision history summary.
  - Provenance: run id, tool version, model/runtime where available.
- Replace ambiguous labels such as `confirmation:` with precise labels:
  `proof`, `static analysis`, `verification`, `human decision`.
- Do not imply live exploitation or successful attack.

### Activity

- Keep Activity trace-backed; no synthetic progress.
- Add/verify:
  - terminal outcome banner with run id, terminal status, finding count, and
    partial/failure reason when applicable.
  - stalled/no-output indicator based on real trace timestamps.
  - cancelled/partial labeling for all partial artifacts.
- A completed zero-result run must not open an empty findings/viz page as if it
  found content.

### Scope and Target Chrome

- Keep `target`, `scope`, `InScope`, `OutOfScope`, and `Unknown`.
- Persistent chrome must expose active target and scope state when loaded.
- Scope-gated operations must refuse `OutOfScope` targets.

### Decision Feedback

- When a user records a decision, show feedback only after durable write:
  `decision saved; will carry forward`.
- If a filter hides the row after the decision, say that the row moved because
  the active filter excludes it.

## 2. TUI Screen Map

### Existing Surfaces to Keep

- Target Picker: pre-shell target selection. No silent cwd fallback.
- Workbench: default cockpit and review surface.
- Activity: live run/tool progress.
- Replay/Trace: read-only run artifact inspection.
- Config/Tools/Options/Help: existing support surfaces.

### Workbench Layout

Wide terminal:

```text
[SOURCE | CODE/DFD/FLOW/RISK/CHAIN | FINDINGS | DETAILS]
```

Narrow terminal:

```text
[FINDINGS]
[DETAILS]
```

Collapse order:

1. Source tree.
2. Center context tabs.
3. Findings/details stack vertically.

### Workbench Findings Pane

Row fields:

```text
F-0007  high  conf:72%  p:1  status:new  decision:none  rule/title  file:line
```

Display priority as row order and an optional compact label. Do not let
priority replace severity.

Pinned sections:

- Decision conflicts, including reappeared rejected findings.
- Stale evidence.
- Partial-run findings when reviewing a partial run.

### Workbench Details Pane

Must render from `FindingDetailModel` and remain available in plain output.
Evidence and model-derived reasoning must be visually and textually separated.

### Activity View

Left pane: real module/task DAG state from trace events.
Right pane: output deck/artifacts.
Footer: focused pane, pause/tail state, verbose toggle, cancel state.

### Compare View

Use existing `runs diff`/run-diff model but change classes to:

- new
- unchanged
- changed
- resolved_absent / not_seen
- uncertain_match when applicable

Never label absence as fixed without remediation evidence.

### Report Preview

Add either:

- a dedicated report preview shell view, or
- a Workbench Ship page panel backed by a `ReportPreviewViewModel`.

Preview must use the same projection/serializer as export.

## 3. CLI Command Changes

Do not adopt Fable's `tool ui/run/step` command tree. Keep Kuzushi's public
commands.

### Preserve

- `kuzushi scan [target]`
- `kuzushi` / `kuzushi shell --target <path>`
- `kuzushi run <module:tool> --input <json>`
- `kuzushi findings --target <path>`
- `kuzushi finding <reference> --target <path>`
- `kuzushi runs list|show|trace|diff|prune`
- `kuzushi export --out <path> --format <format>`
- `kuzushi suppress ... --target <path>`

### Add / Modify

- Add `--scope open|complete` or `--completeness open|complete` to findings
  listing and export surfaces.
- Add `--decision` as an alias for verdict filtering, while preserving
  existing `--verdict`.
- Add lifecycle `--status` filtering once status is modeled separately from
  decision.
- Add `--preview` to `kuzushi export`, or add `kuzushi export-preview` if
  command compatibility is easier.
- Fix `suppress` and `suppressions` to require explicit target, matching
  `findings` and `finding`.
- Update `runs diff` output:
  - `fixed` -> `resolved_absent` or `not_seen`
  - add warnings for partial/failed comparison runs
  - include decision carry-forward/conflict counts when the decision store
    exists.

### Do Not Add

- Do not add `--ci` to `kuzushi run`.
- Do not make a global `--json` semantics change without a migration plan.
- Do not rename `--target` to `--project`.
- Do not repurpose existing exit codes globally.

## 4. Data Model Changes

### Add Durable Finding Identity

Add a durable identity table. Proposed names:

```text
finding_identities
  identity_id text primary key
  target_id text not null
  alias text not null
  fingerprint_current text not null
  first_seen_run_id text not null
  created_at text not null
  retired_at text null
```

Add fingerprint history:

```text
finding_identity_fingerprints
  identity_id text not null
  fingerprint text not null
  match_basis text not null
  created_at text not null
  primary key(identity_id, fingerprint)
```

Current `findings` rows should be treated as per-run finding occurrences.
Add:

```text
findings.identity_id text null references finding_identities(identity_id)
findings.identity_match_tier text null
```

### Replace Line-Only Identity

Current `fingerprint_parts(rule_id, file_path, start_line)` is too brittle.
Introduce v3 identity inputs:

- weakness kind / rule id / normalized CWE when available
- normalized repo-relative path
- structural anchor when available
- stable evidence signature

Line numbers remain location/evidence, not the durable identity basis.

### Add Append-Only Decisions

Add:

```text
finding_decisions
  decision_id text primary key
  identity_id text not null references finding_identities(identity_id)
  verdict text not null
  reason text null
  scope text not null default 'this_finding'
  author text null
  decided_at text not null
  superseded_by text null references finding_decisions(decision_id)
  run_id_context text null
```

Verdicts:

- `confirmed`
- `rejected_false_positive`
- `suppressed`
- `deferred`
- `accepted_risk`

Compatibility mapping:

- existing `true_positive` -> `confirmed`
- existing `false_positive` -> `rejected_false_positive`
- existing `needs_review` -> no decision / review needed
- existing `by_design` -> `accepted_risk` unless product owner chooses
  suppression-by-policy

Keep the existing `triage` table as a compatibility/latest-assessment surface
until all readers move to decision history.

### Add Per-Run Assessment Projection

Current severity, triage confidence, static proof state, and verification live
across several tables. Introduce a read model or table for:

```text
finding_assessments
  finding_id integer not null
  run_id text not null
  severity text not null
  confidence real null
  lifecycle_status text not null
  priority_score real null
  priority_inputs_json text not null
  computed_at text not null
```

If a physical table is too much for the first phase, implement this as a pure
Rust selector first.

### Evidence Additions

Add fields or side table data for:

- source reference
- observed vs model-generated/derived flag
- stale/changed evidence marker
- optional content-addressed blob reference
- purge tombstone

Do not delete evidence without leaving an explicit tombstone.

## 5. State Model Changes

### Domain State

Domain truth lives in:

- findings SQLite store
- run artifacts under `.kuzushi/runs`
- whitebox suppression store during migration
- future decision history table

### Application Projection

Build a current finding projection from:

- latest occurrence per identity
- latest assessment per identity
- current decision from append-only decision log
- latest evidence/proof/verification
- scope and run provenance

Projection fields:

```text
identity_id
alias
latest_finding_row_id
latest_run_id
severity
confidence
priority
lifecycle_status
decision
decision_conflict
evidence_state
scope_state
```

### Transitions

- Runs are forward-only: running -> completed/failed/cancelled/partial.
- Completed run artifacts are immutable.
- Decisions are append-only.
- Automated runs may update lifecycle status and assessments, never decisions.
- Comparison writes no finding truth.
- Exports mutate no finding truth.

### Invalid Transitions

- Auto overwriting a human decision.
- Treating suppression/defer/reject as resolved.
- Treating absence in failed/partial runs as fixed.
- Mutating sealed run evidence.
- Creating findings without target/run provenance.

## 6. View Models and Selectors

### Update `FindingsModel`

Files to modify first:

- `crates/kuzushi-tui/src/ui_view_models/findings.rs`
- `crates/kuzushi-tui/src/renderer/views/workbench/detail_pane.rs`
- `crates/kuzushi-tui/src/renderer/views/workbench/panes.rs`
- `crates/kuzushi-tui/src/renderer/views/workbench/render_workbench_view.rs`

Add fields:

```text
filter_label
visible_count
total_count
completeness_mode
rows[].severity
rows[].confidence
rows[].priority_label
rows[].lifecycle_status
rows[].decision
rows[].decision_conflict
rows[].evidence_state
```

### Update `FindingDetailModel`

Add:

- current decision
- decision history summary
- lifecycle status
- explicit evidence rows with observed/derived flag
- stale evidence flag
- run/model/runtime provenance where available
- omitted/missing evidence markers

### Add `ReportPreviewViewModel`

Fields:

- format
- completeness
- target
- run id / baseline run id
- generated-at preview metadata
- projected counts
- omitted fields for the selected format
- preview page rows from canonical export projection

### Update Run Diff View Model

Files:

- `crates/kuzushi-cli/src/application/runs_diff.rs`
- `crates/kuzushi-tui/src/ui_view_models/run_diff.rs`
- `crates/kuzushi-tui/src/renderer/views/runs/run_diff_lines.rs`

Changes:

- rename `fixed` to `resolved_absent` or `not_seen`
- carry decision states when identity data exists
- flag partial comparison runs
- expose uncertain matches separately

## 7. Persistence Changes

### SQLite Migrations

All migrations must be additive and transactional:

1. Add identity tables.
2. Add decision history table.
3. Add identity linkage columns to `findings`.
4. Add assessment/projection table only if selectors are insufficient.
5. Add evidence metadata/blob/tombstone tables if needed.

Before migration:

- create backup of findings DB
- run integrity check
- record schema version

After migration:

- every finding has an identity
- every decision maps to an identity
- aliases are stable
- counts reconcile
- no dangling evidence, verification, patch, suppression, or source refs

### Suppression Store

- Preserve `whitebox-suppressions.json` compatibility.
- Link suppressions to durable identities when possible.
- Do not silently convert suppressions into rejected findings.
- Fix CLI target handling so suppression commands require explicit `--target`.

### Run Artifacts

- Do not rewrite sealed run artifacts.
- Add read-time adapters for old artifact formats.
- New run artifacts should include model/runtime/config provenance already
  available in run metadata.

## 8. Report Generation Changes

### Canonical Projection

Create a canonical export record:

```text
WorkspaceFindingExportRecord
  identity_id
  alias
  fingerprint
  kind/rule_id/title
  location
  severity
  confidence
  priority
  lifecycle_status
  decision
  decision_reason
  suppression/defer metadata
  evidence summary/full refs
  observed_vs_model_generated flags
  static proof state
  verification summary
  tool/rule/source provenance
  run_id
  tool_version
  model/runtime provenance where available
```

All formats must use this projection.

### Format Requirements

- JSON: full structured projection plus metadata.
- JSONL: one deterministic record per finding plus header/metadata strategy.
- CSV: deterministic columns for identity, location, severity, confidence,
  priority, status, decision, tool, rule, evidence summary, run provenance.
- SARIF: keep valid SARIF 2.1.0; put Kuzushi-only fields under `properties`
  rather than faking SARIF-native fields.
- Markdown bundle: README summary, one file per finding, manifest with
  completeness, run provenance, omitted fields, and file hashes.

### Preview

- Preview must call the same serializer/projection path as export.
- Preview must show the selected completeness mode and omitted fields.
- Empty export requires explicit confirmation and still writes valid metadata.

## 9. Migration Plan

### Phase 0: Semantic Guard Tests

- Add tests that lock current terms and no-silent-target behavior.
- Add tests that `runs diff` no longer says "fixed" for plain absence.
- Add tests for suppression target requirement.

### Phase 1: Presentation-Only Separation

- Update `FindingListRow`, `FindingDetailModel`, and renderers to show the five
  signals separately using existing fields.
- Add honest empty-state reason selection.
- Add Activity terminal outcome banner if missing.

### Phase 2: Decision History

- Add `finding_decisions`.
- Backfill from `triage` and suppression store.
- Keep existing `triage` readers working.
- Add TUI/CLI decision writes through one application service.

### Phase 3: Durable Identity

- Add `finding_identities`.
- Backfill identities from existing fingerprints.
- Introduce v3 fingerprint function and match tiers.
- Link new findings to identities during persistence.
- Preserve all existing aliases and decisions.

### Phase 4: Report Projection

- Add canonical export projection.
- Add completeness mode.
- Route all export formats and preview through it.
- Add omitted-field metadata.

### Phase 5: Compare and Conflict Workflow

- Make run diff identity-aware.
- Add reappeared/rejected conflict flags.
- Suppress resolved classification for partial/failed comparison runs.

## 10. Test Plan

### Unit Tests

- identity function is stable under line shifts and formatting changes.
- identity function does not accept run order, timestamp, array index, or
  absolute line number as required inputs.
- decision vocabulary maps from old triage verdicts.
- priority is deterministic and never overwrites severity or confidence.
- lifecycle status and decision are distinct enum/domain types.

### Persistence Tests

- migration preserves findings, evidence, triage, verifications, patch results,
  sources, suppressions, aliases, and decisions.
- decision writes are append-only.
- automated triage cannot overwrite human decisions.
- sealed run artifacts remain byte-identical.
- suppression commands require explicit target.

### View Model Tests

- Workbench row contains five labeled signals.
- filtered-empty differs from completed-clean.
- row counts match rendered rows.
- detail separates observed evidence from model-derived reasoning.
- reappeared rejected finding is flagged as conflict.

### CLI Tests

- `findings` and `finding` still require explicit target.
- `suppress` and `suppressions` require explicit target.
- `runs diff` uses `resolved_absent`/`not_seen`, not `fixed`.
- `kuzushi run` remains machine-readable without adding `--ci`.
- stdout/stderr contracts stay unchanged for machine-readable commands.

### Export Golden Tests

- repeated export of the same sealed run is deterministic.
- JSON, JSONL, CSV, SARIF, and markdown bundle agree on shared fields.
- omitted fields are recorded.
- open vs complete modes differ only by inclusion policy.
- preview and export share projection output.

### Safety Tests

- report/UI text does not imply exploit success for unverified findings.
- static/model reasoning is labeled separately from observed evidence.
- scope-gated operations refuse out-of-scope targets.
- no silent model/runtime fallback paths are introduced.
