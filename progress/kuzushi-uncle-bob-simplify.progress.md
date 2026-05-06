# Kuzushi Uncle Bob Simplification Progress

Stage: Clean Code simplification loop setup
Active story: UB-002 Decompose Core Module Registry Families
Status: ready

## Checklist

- UB-001 Record Current Simplification Hotspots: passed.
- UB-002 Decompose Core Module Registry Families: pending.
- UB-003 Extract Rust TUI App State Transitions: pending.
- UB-004 Extract Rust TUI Rendering Surfaces: pending.
- UB-005 Separate Verification Pipeline Phases: pending.
- UB-006 Separate Finding Persistence And Reporting Helpers: pending.
- UB-007 Simplify Secondary Rust Hotspots: pending.
- UB-008 Run Full Simplification Milestone Gate: pending.

## Iteration Log

- UB-001: Recorded current simplification research in
  `docs/assessments/codebase-simplification-hotspots.md`, added the Ralph PRD,
  and defined the loop script contract. Current priority is Rust-first because
  the largest files are `crates/kuzushi-core/src/modules.rs`,
  `crates/kuzushi-tui/src/app.rs`, and
  `crates/kuzushi-tui/src/renderer.rs`.
