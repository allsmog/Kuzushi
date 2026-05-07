# Complexity / CRAP-Risk Hotspots

Audit date: 2026-05-06.

True CRAP scores are not available in this checkout because no Rust coverage
complexity tool is configured. This report uses the requested proxy:

```text
CRAP-risk = complexity_weight + size_weight + side_effect_weight + coverage_gap + centrality_weight
```

Evidence gathered:

- `wc -l crates/kuzushi-core/src/modules.rs crates/kuzushi-tui/src/app.rs crates/kuzushi-tui/src/renderer.rs crates/kuzushi-core/src/scan.rs crates/kuzushi-core/src/verify.rs crates/kuzushi-core/src/findings.rs src/bus/orchestrator.ts src/store.ts`
- `wc -l crates/kuzushi-core/src/modules/*.rs`
- Phase 0 focused gates:
  `cargo fmt --all --check`, `cargo check -p kuzushi-core`,
  `cargo test -p kuzushi-core modules`

## Top Hotspots

| Rank | File / region | Why it ranks | Available tests | Decision |
| ---: | --- | --- | --- | --- |
| 1 | `crates/kuzushi-core/src/modules.rs` | 11,311 lines after extraction; owns registry, SAST orchestration, runtime-backed module dispatch, hidden DAG nodes, and many tests. Central to scan/shell/run parity. | `cargo test -p kuzushi-core modules` | Fixed one safe slice now: shared input parsing/prompt/path helpers moved to `crates/kuzushi-core/src/modules/input.rs`. Continue family extraction later. |
| 2 | `crates/kuzushi-tui/src/app.rs` | 10,391 lines; command handling, state, worker events, reducers, and tests sit on the interactive boundary. | `cargo test -p kuzushi-tui app::tests` | Defer overnight; prior UB-003 extraction passed and P0 public-surface work is higher leverage. |
| 3 | `crates/kuzushi-tui/src/renderer.rs` | 6,296 lines; view rendering, layout tests, and formatting helpers remain dense. | `cargo test -p kuzushi-tui renderer::tests` | Defer; prior UB-004 extraction passed. Keep future cuts view-scoped. |
| 4 | `src/bus/orchestrator.ts` | 4,195 retained TS reference/orchestration lines; central only to retained TS paths, not the current Rust operator CLI. | `pnpm typecheck`, TS tests | Do not touch in this pass; avoid resurrecting TypeScript runtime work. |
| 5 | `crates/kuzushi-core/src/scan.rs` | 2,812 lines; subprocess execution, scanner normalization, cancellation, and static evidence indexing mix side effects and parsing. | `cargo test -p kuzushi-core scan` | Defer; next safe cut is scanner process helpers vs JSON normalization. |
| 6 | `crates/kuzushi-core/src/verify.rs` | 2,749 lines; runtime validation, sandbox, classification, and persistence decisions. High model/runtime invariant risk. | `cargo test -p kuzushi-core verify` | Defer without a focused failing test or clear extraction boundary. |
| 7 | `src/store.ts` | 2,118 retained TS persistence facade; compatibility-sensitive. | `pnpm typecheck`, TS store tests | Defer; Rust findings store is the current operator path. |
| 8 | `crates/kuzushi-core/src/findings.rs` | 1,946 lines before the detail-command follow-up; schema bootstrap, dedupe, aliases, filtering, reporting state. Persisted format risk. | `cargo test -p kuzushi-core findings` | Fixed one non-schema slice: finding detail/proof-state rendering moved into `crates/kuzushi-core/src/findings/detail.rs`, and prefix lookup now shares verification attachment. |
| 9 | `crates/kuzushi-core/src/modules/vendor_assessment.rs` | 498 lines; extracted but still mixes attachment parsing, prompt bundles, and reports. | `cargo test -p kuzushi-core modules` | Defer; not in first-wow path. |
| 10 | `crates/kuzushi-core/src/modules/context.rs` | 494 lines; repo walk, inference, artifact writing. | `cargo test -p kuzushi-core modules::tests::dispatches_context_build_snapshot` | Defer; cohesive enough after extraction. |
| 11 | `crates/kuzushi-core/src/modules/plugin_adapters.rs` | 477 lines; model/runtime-backed plugin wrappers plus persistence. | `cargo test -p kuzushi-core modules::tests::dispatches_plugin_backed_adapters_through_runtime_and_persists` | Defer due runtime no-fallback sensitivity. |
| 12 | `crates/kuzushi-core/src/modules/sast_run.rs` | 422 lines; run artifact writes and candidate rules. | `cargo test -p kuzushi-core modules` | Defer; keep artifact format stable. |
| 13 | `crates/kuzushi-core/src/modules/prompt_armor.rs` | 308 lines; plugin dispatch plus authorization gates. | `cargo test -p kuzushi-core modules::tests::prompt_armor_network_tools_require_authorization` | Do not touch without auth-gate tests in hand. |
| 14 | `crates/kuzushi-core/src/modules/native_scanners.rs` | 296 lines; direct scanner tools and persistence. | `cargo test -p kuzushi-core modules::tests::dispatches_semgrep_scan_and_persists_findings` | Defer; first-wow relies on this staying stable. |
| 15 | `crates/kuzushi-core/src/modules/input.rs` | 273 lines; newly extracted parsing helpers. | `cargo test -p kuzushi-core modules` | Fixed now; watch for future split if validation messages drift. |

## Safe Cuts Completed

The completed Phase 0 slice moved shared tool input parsing, SAST task
filtering, prompt override loading, boolean/string coercion, and path
resolution from `modules.rs` into `modules/input.rs`.

Why this was safe:

- The functions were cohesive and mostly pure, except prompt file reads.
- Call sites remained in the same parent module namespace with `pub(super)`.
- Tool names, DAG descriptors, persisted findings, and model/runtime behavior
  were unchanged.
- Focused Rust module tests passed.

The follow-up finding-detail slice moved proof-state, runtime-validation,
patch-result, and next-action rendering into
`crates/kuzushi-core/src/findings/detail.rs`.

Why this was safe:

- It added a read-only CLI surface over existing finding, verification, and
  patch-result tables.
- It did not change SQLite schema, alias ordering, scanner behavior, or
  persisted `.kuzushi` formats.
- Prefix lookup now uses the same latest-verification attachment helper as
  exact fingerprint lookup.
- Focused findings and CLI cutover tests passed.

## Next 5 Complexity Cuts

1. Split `scan.rs` subprocess process management from scanner JSON
   normalization; keep cancellation tests focused.
2. Split `modules.rs` taint-family prompt/input normalization into a cohesive
   `modules/taint.rs` helper only if tests remain under `modules`.
3. Move TUI renderer view-line builders one view at a time, starting with the
   findings view because it maps to the public first-wow workflow.
4. Extract verify evidence classification helpers from sandbox side effects in
   `verify.rs`; do not touch runtime/model fallback paths.
5. Continue moving findings report rendering helpers behind focused modules
   without changing SQLite schema or alias ordering.

## Remaining Risk

The largest files are still large. The overnight-safe choice was to complete
one verified extraction and spend the rest of the pass on public trust
surfaces. Any deeper CRAP reduction should start from a failing or narrowly
scoped focused test, not from line count alone.
