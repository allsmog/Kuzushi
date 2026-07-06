# GPT_IMPLEMENTATION_BRIEF.md

You are implementing the domain-safe Fable reconciliation for Kuzushi. Preserve
real scanner semantics. Do not introduce exploit code, payloads, offensive
procedures, live target attack validation, persistence/stealth behavior, or
instructions for unauthorized access.

## Priorities

### P0: Semantic Safety and Wording

1. Keep public terms: target, scope, finding, evidence, severity,
   confidence, priority, status, decision.
2. Do not rename `--target` to `--project`.
3. Do not rename confidence to certainty.
4. Do not label absent findings as fixed.
5. Do not imply live exploitation or confirmed impact unless the data actually
   says so.
6. Do not add `--ci`/`--json` to `kuzushi run`; run mode already emits JSON.

### P1: Presentation Separation First

Use existing data first. Make Workbench/details/reports display the five
signals separately before changing persistence.

### P2: Decision History and Identity

Add durable identity and append-only human decisions after presentation tests
lock the intended semantics.

### P3: Report Projection

Build one canonical export projection and route preview/export formats through
it.

## Constraints

- scan/shell/run semantics must stay shared through the Rust registry boundary.
- Do not create CLI-only or TUI-only scanner behavior.
- Human decisions must never be overwritten by automated triage, verification,
  comparison, report generation, or a later scan.
- Completed run records and run artifacts are historical snapshots.
- Scope-gated operations must refuse `OutOfScope`.
- Missing/incompatible model/runtime is a hard error; no silent fallback.
- Keep changes small and CRAP-risk aware. Functions touched or added should
  stay under the repo's complexity/length gates.

## Inspect These Files First

### Domain and Persistence

- `crates/kuzushi-core/src/findings/domain/finding_record.rs`
- `crates/kuzushi-core/src/findings/domain/mod.rs`
- `crates/kuzushi-core/src/findings/domain/triage_outcome.rs`
- `crates/kuzushi-core/src/findings/domain/static_proof_state.rs`
- `crates/kuzushi-core/src/findings/persistence/open/connection_and_schema.rs`
- `crates/kuzushi-core/src/findings/persistence/open/finding_writes.rs`
- `crates/kuzushi-core/src/findings/persistence/open/triage_and_verification.rs`
- `crates/kuzushi-core/src/findings/persistence/open/finding_evidence.rs`
- `crates/kuzushi-core/src/findings/persistence/open/finding_sources.rs`
- `crates/kuzushi-core/src/proof/suppressions/`

### TUI

- `crates/kuzushi-tui/src/ui_view_models/findings.rs`
- `crates/kuzushi-tui/src/ui_view_models/workbench.rs`
- `crates/kuzushi-tui/src/ui_view_models/activity_view.rs`
- `crates/kuzushi-tui/src/ui_view_models/run_diff.rs`
- `crates/kuzushi-tui/src/renderer/views/workbench/detail_pane.rs`
- `crates/kuzushi-tui/src/renderer/views/workbench/panes.rs`
- `crates/kuzushi-tui/src/renderer/views/workbench/render_workbench_view.rs`
- `crates/kuzushi-tui/src/renderer/views/activity/`
- `crates/kuzushi-tui/src/commands/shell_command_specs/`

### CLI and Reports

- `crates/kuzushi-cli/src/command.rs`
- `crates/kuzushi-cli/src/command/subcommands.rs`
- `crates/kuzushi-cli/src/application/findings.rs`
- `crates/kuzushi-cli/src/application/suppressions.rs`
- `crates/kuzushi-cli/src/application/runs_diff.rs`
- `crates/kuzushi-cli/src/application/export.rs`
- `crates/kuzushi-core/src/workspace/application/export_workspace_findings.rs`
- `crates/kuzushi-core/src/workspace/application/export_sarif.rs`
- `crates/kuzushi-core/src/workspace/application/export_markdown_bundle.rs`
- `crates/kuzushi-core/src/findings/presentation/`

## Required First Changes

1. Replace `runs diff` wording:
   - `fixed` -> `resolved_absent` or `not_seen`.
   - Add tests proving absence in a partial/failed run is not reported as
     fixed.

2. Fix suppression target parity:
   - `suppress` and `suppressions` must require explicit `--target`, matching
     `findings` and `finding`.
   - Do not default to cwd.

3. Separate Workbench row/detail fields:
   - severity
   - confidence
   - priority/order
   - lifecycle status/proof state
   - human decision

4. Change misleading labels:
   - avoid `confirmation:` as a catch-all.
   - label static proof, verification, model reasoning, and human decision
     separately.

5. Add export completeness groundwork:
   - open vs complete mode in export projection.
   - report metadata says what was included.

## Persistence Migration Guidance

- Add tables/columns additively.
- Back up SQLite before schema migration.
- Do not rewrite sealed run artifacts.
- Backfill identity and decision records from current findings/triage only
  after tests prove alias and decision preservation.
- Keep compatibility readers for old `triage` and fingerprint fields.

## Tests That Must Pass

Run the narrow tests for touched crates first, then broader checks.

Required test coverage:

- `runs_diff` output and JSON shape.
- suppression target requirement.
- findings view model signal separation.
- finding detail labeling.
- export projection field equality across formats.
- migration preservation of aliases, triage, verification, evidence, and
  suppressions when migration work begins.
- no-silent-fallback policy tests if runtime/model code is touched.

Suggested commands:

```sh
cargo test -p kuzushi-core findings
cargo test -p kuzushi-core workspace::application
cargo test -p kuzushi-cli runs_diff
cargo test -p kuzushi-cli suppress
cargo test -p kuzushi-tui findings
cargo test -p kuzushi-tui workbench
pnpm quality:crap-risk
```

If a command is too broad or currently failing because of unrelated dirty
worktree state, record the exact failure and keep the implementation scoped.

## Do Not Do

- Do not implement Fable's generic `tool ui/run/step` command tree.
- Do not rename scanner concepts to neutral review-model terms.
- Do not make reports compute or mutate finding truth.
- Do not hide suppressed/rejected/deferred findings permanently.
- Do not attach a prior decision to an uncertain identity match.
- Do not generate offensive examples, payloads, exploit procedures, or live
  attack validation.
