# Kuzushi Uncle Bob Simplification Progress

Stage: Clean Code simplification follow-up
Active story: UB-002 Decompose Core Module Registry Families
Status: continuing focused slices because `crates/kuzushi-core/src/modules.rs` remains the dominant hotspot

## Checklist

- UB-001 Record Current Simplification Hotspots: passed.
- UB-002 Decompose Core Module Registry Families: passed; continuing safe follow-up slices.
- UB-003 Extract Rust TUI App State Transitions: passed.
- UB-004 Extract Rust TUI Rendering Surfaces: passed.
- UB-005 Separate Verification Pipeline Phases: passed.
- UB-006 Separate Finding Persistence And Reporting Helpers: passed.
- UB-007 Simplify Secondary Rust Hotspots: passed.
- UB-008 Run Full Simplification Milestone Gate: passed.

## Iteration Log

- UB-001: Recorded current simplification research in
  `docs/assessments/codebase-simplification-hotspots.md`, added the Ralph PRD,
  and defined the loop script contract. Current priority is Rust-first because
  the largest files are `crates/kuzushi-core/src/modules.rs`,
  `crates/kuzushi-tui/src/app.rs`, and
  `crates/kuzushi-tui/src/renderer.rs`.

### UB-002 automation gate

- Task attempted: ran the Uncle Bob simplification loop for Decompose Core Module Registry Families.
- Files changed: see git diff for this story commit.
- Tests/checks run: cargo check -p kuzushi-core && cargo test -p kuzushi-core modules; PRD fast global checks.
- Result: gates passed and PRD story marked passes=true.
- Remaining work: next incomplete PRD story by priority.
- Blockers or repo facts that contradicted this prompt: none recorded by automation.

### UB-002 manual follow-up, iteration 1

- Task attempted: extracted module option input validation from
  `crates/kuzushi-core/src/modules.rs` into
  `crates/kuzushi-core/src/modules/options.rs`.
- Files changed:
  `crates/kuzushi-core/src/modules.rs`,
  `crates/kuzushi-core/src/modules/options.rs`, and this progress note.
- Tests/checks run: `cargo test -p kuzushi-core modules::tests`;
  `cargo check -p kuzushi-core`.
- Result: gates passed; module registry option coercion, defaults, required
  options, and catalog serialization behavior remain covered.
- Remaining work: continue decomposing `modules.rs` by cohesive concern while
  preserving tool names, DAG nodes, persisted output shapes, and model/runtime
  enforcement.
- Blockers or repo facts that contradicted this prompt: none.

### UB-002 manual follow-up, iteration 2

- Task attempted: extracted SAST run artifact helpers from
  `crates/kuzushi-core/src/modules.rs` into
  `crates/kuzushi-core/src/modules/sast_run.rs`.
- Files changed:
  `crates/kuzushi-core/src/modules.rs`,
  `crates/kuzushi-core/src/modules/sast_run.rs`, and this progress note.
- Tests/checks run: `cargo fmt --all`; `cargo fmt --all --check`;
  `cargo check -p kuzushi-core`;
  `cargo test -p kuzushi-core modules::tests::sast`;
  `cargo test -p kuzushi-core modules::tests::whitebox`;
  `cargo test -p kuzushi-core modules`.
- Result: gates passed; `sast:scan` remains the orchestrator while persisted
  run IDs, scan-input capture, summary JSON, triage JSONL, verify JSONL,
  patch JSONL, and whitebox-static artifacts live behind a smaller module
  boundary.
- Remaining work: continue decomposing `modules.rs` by cohesive concern; it
  remains the dominant production hotspot even after this SAST artifact slice.
- Blockers or repo facts that contradicted this prompt: none.

### UB-003 automation gate

- Task attempted: ran the Uncle Bob simplification loop for Extract Rust TUI App State Transitions.
- Files changed: see git diff for this story commit.
- Tests/checks run: cargo test -p kuzushi-tui app::tests; PRD fast global checks.
- Result: gates passed and PRD story marked passes=true.
- Remaining work: next incomplete PRD story by priority.
- Blockers or repo facts that contradicted this prompt: none recorded by automation.

### UB-004 automation gate

- Task attempted: ran the Uncle Bob simplification loop for Extract Rust TUI Rendering Surfaces.
- Files changed: see git diff for this story commit.
- Tests/checks run: cargo test -p kuzushi-tui renderer::tests; PRD fast global checks.
- Result: gates passed and PRD story marked passes=true.
- Remaining work: next incomplete PRD story by priority.
- Blockers or repo facts that contradicted this prompt: none recorded by automation.

### UB-005 automation gate

- Task attempted: ran the Uncle Bob simplification loop for Separate Verification Pipeline Phases.
- Files changed: see git diff for this story commit.
- Tests/checks run: cargo check -p kuzushi-core && cargo test -p kuzushi-core verify; PRD fast global checks.
- Result: gates passed and PRD story marked passes=true.
- Remaining work: next incomplete PRD story by priority.
- Blockers or repo facts that contradicted this prompt: none recorded by automation.

### UB-006 automation gate

- Task attempted: ran the Uncle Bob simplification loop for Separate Finding Persistence And Reporting Helpers.
- Files changed: see git diff for this story commit.
- Tests/checks run: cargo check -p kuzushi-core && cargo test -p kuzushi-core findings; PRD fast global checks.
- Result: gates passed and PRD story marked passes=true.
- Remaining work: next incomplete PRD story by priority.
- Blockers or repo facts that contradicted this prompt: none recorded by automation.

### UB-007 automation gate

- Task attempted: ran the Uncle Bob simplification loop for Simplify Secondary Rust Hotspots.
- Files changed: see git diff for this story commit.
- Tests/checks run: cargo check -p kuzushi-core && cargo test -p kuzushi-core; PRD fast global checks.
- Result: gates passed and PRD story marked passes=true.
- Remaining work: next incomplete PRD story by priority.
- Blockers or repo facts that contradicted this prompt: none recorded by automation.

### UB-008 automation gate

- Task attempted: ran the Uncle Bob simplification loop for Run Full Simplification Milestone Gate.
- Files changed: see git diff for this story commit.
- Tests/checks run: cargo test --workspace && pnpm build; PRD fast global checks.
- Result: gates passed and PRD story marked passes=true.
- Remaining work: next incomplete PRD story by priority.
- Blockers or repo facts that contradicted this prompt: none recorded by automation.
