# Post-Uncle-Bob Phases Progress

## Phase 2 - Complexity / CRAP-risk

- Files inspected:
  `crates/kuzushi-core/src/modules.rs`, `crates/kuzushi-tui/src/app.rs`,
  `crates/kuzushi-tui/src/renderer.rs`, `crates/kuzushi-core/src/scan.rs`,
  `crates/kuzushi-core/src/verify.rs`, `crates/kuzushi-core/src/findings.rs`,
  `src/bus/orchestrator.ts`, `src/store.ts`, and
  `crates/kuzushi-core/src/modules/*`.
- Decision made:
  true CRAP scores are unavailable, so the assessment uses the requested
  CRAP-risk proxy. The verified `modules/input.rs` extraction is the safe
  complexity cut for this iteration.
- Files changed:
  `docs/assessments/complexity-crap-hotspots.md`.
- Checks run:
  `wc -l` hotspot measurements; Phase 0 focused Rust gates.
- Result:
  top 15 hotspots and next 5 safe cuts are recorded.
- Remaining risk:
  the largest Rust files remain large; future cuts should be test-led.
- Output type:
  docs plus a verified behavior-preserving code extraction from Phase 0.

### Phase 2 follow-up - Finding detail/reporting slice

- Files inspected:
  `crates/kuzushi-core/src/findings.rs`,
  `crates/kuzushi-core/src/findings/reporting.rs`,
  `crates/kuzushi-cli/src/main.rs`, and
  `crates/kuzushi-cli/tests/cutover_cli.rs`.
- Decision made:
  implement the high-value finding detail command as a read-only reporting
  slice and keep proof-state rendering out of the CLI entrypoint.
- Files changed:
  `crates/kuzushi-core/src/findings/detail.rs`,
  `crates/kuzushi-core/src/findings.rs`, `crates/kuzushi-core/src/lib.rs`,
  `crates/kuzushi-cli/src/main.rs`, `crates/kuzushi-cli/tests/cutover_cli.rs`,
  `README.md`, and `docs/assessments/complexity-crap-hotspots.md`.
- Checks run:
  `cargo fmt --all --check`, `cargo test -p kuzushi-core findings`, and
  `cargo test -p kuzushi-cli --test cutover_cli finding_detail_resolves_alias_and_outputs_json_report`.
- Result:
  `kuzushi finding <alias-or-fingerprint-prefix>` now shows one finding's
  evidence, proof state, runtime validation, latest patch result, and next
  action in plain text or JSON. Fingerprint-prefix resolution now attaches the
  latest persisted verification through the same helper as exact lookup.
- Remaining risk:
  the larger findings store still contains schema, filtering, and persistence
  responsibilities; avoid schema-affecting cleanup without migration tests.
- Output type:
  code plus focused tests.

## Phase 3 - Human onboarding

- Files inspected:
  `README.md`, `AGENTS.md`, `docs/rust-migration-status.md`,
  `docs/modules.md`, `docs/assessments/mode-parity.md`, and
  `src/ui/README.md`.
- Decision made:
  create a concrete owner/test map rather than another broad audit.
- Files changed:
  `docs/devex/new-contributor-map.md`.
- Checks run:
  `pnpm check:docs`.
- Result:
  contributor areas, invariants, focused checks, first 30 minutes, gotchas,
  safe first issues, and verification recipes are documented.
- Remaining risk:
  map should be updated whenever CLI/TUI owner files move.
- Output type:
  docs.

## Phase 4 - Light DDD alignment

- Files inspected:
  Rust core modules/findings/scan/TUI owner files and retained TypeScript SDK
  module contracts.
- Decision made:
  document current bounded contexts and avoid code churn beyond the already
  verified input-helper extraction.
- Files changed:
  `docs/architecture/domain-boundaries.md`.
- Checks run:
  `pnpm check:docs`.
- Result:
  findings, module/tool, scan/run, runtime/model, and shell/TUI contexts are
  documented with vocabulary, invariants, dependencies, extension points, and
  anti-ceremony guidance.
- Remaining risk:
  future code moves should keep the contributor map and domain doc in sync.
- Output type:
  docs.
