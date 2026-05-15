# New Contributor Map

Use this map to find the right owner area and focused checks before editing.
For vocabulary and dependency rules, see
[`docs/architecture/domain-boundaries.md`](../architecture/domain-boundaries.md).

## Where To Change What

| Change | Primary files | Focused checks |
| --- | --- | --- |
| Rust CLI command, flags, exit behavior | `crates/kuzushi-cli/src/main.rs`, `crates/kuzushi-cli/tests/` | `cargo test -p kuzushi-cli cutover_cli` |
| Rust TUI command/reducer behavior | `crates/kuzushi-tui/src/app.rs`, `crates/kuzushi-tui/src/app/state_transitions.rs`, `crates/kuzushi-tui/src/commands.rs` | `cargo test -p kuzushi-tui app::tests` |
| Rust TUI rendering/plain output | `crates/kuzushi-tui/src/renderer.rs`, `crates/kuzushi-tui/src/renderer/plain.rs`, `crates/kuzushi-tui/src/theme/mod.rs` | `cargo test -p kuzushi-tui renderer::tests` |
| Module/tool registry | `crates/kuzushi-core/src/modules.rs`, `crates/kuzushi-core/src/modules/*`, `src/modules/*` for retained SDK contracts | `cargo test -p kuzushi-core modules` |
| Findings persistence/reporting | `crates/kuzushi-core/src/findings.rs`, `crates/kuzushi-core/src/findings/reporting.rs`, CLI findings paths | `cargo test -p kuzushi-core findings`; `cargo test -p kuzushi-cli cutover_cli` |
| Scan orchestration | `crates/kuzushi-core/src/scan.rs`, `crates/kuzushi-core/src/modules/sast_run.rs`, `crates/kuzushi-cli/src/main.rs` | `cargo test -p kuzushi-core scan`; `bash tests/e2e/run-smoke.sh` |
| Verify/sandbox | `crates/kuzushi-core/src/verify.rs`, `crates/kuzushi-sandbox`, verification tests | `cargo test -p kuzushi-core verify` |
| Agent runtime/model enforcement | `src/agent-runtime/enforcement.ts`, `src/config.ts`, Rust runtime bridge call sites | `pnpm typecheck`; runtime no-fallback tests named in `AGENTS.md` |
| Retained TypeScript helpers | `src/modules`, `src/ui` non-visual helpers, `src/testing`, `src/store.ts` | `pnpm typecheck`; `pnpm test -- --run` when behavior changes |
| Docs/evals/public examples | `README.md`, `docs/`, `examples/`, `.github/workflows/kuzushi-reference.yml`, `scripts/check-doc-command-drift.mjs` | `pnpm check:docs`; run any example script touched |

## Architectural Invariants

- No silent model fallback. Runtime-backed work uses `ctx.toolModel ??
  ctx.config.model` or the Rust equivalent and fails on incompatible pairs.
- Scan, shell, and run mode parity is the default. Intentional asymmetries
  belong in `AGENTS.md` and `docs/assessments/mode-parity.md`.
- Tool names keep the `<moduleId>:<action>` convention.
- The interactive operator TUI is Rust Ratatui only. Do not add React, Ink,
  TSX, `src/ui/components`, `src/ui/primitives`, or `src/copilot/shell.ts`.
- Persisted `.kuzushi` formats are compatibility surfaces. Schema changes need
  tests and a release note.
- Public docs must follow the current Rust workflow:
  `install -> doctor -> scan -> findings -> evidence/report -> PR comment`.

## First 30 Minutes

1. Build confidence in the surface:
   `cargo run -q -p kuzushi-cli -- --help`,
   `cargo run -q -p kuzushi-cli -- doctor --help`, and
   `pnpm check:docs`.
2. Run the deterministic workflow:
   `examples/first-wow/run.sh`.
3. Inspect one module:
   `crates/kuzushi-core/src/modules/native_scanners.rs` and its tests under
   `crates/kuzushi-core/src/modules.rs`.
4. Run one tool through the registry:
   `cargo run -q -p kuzushi-cli -- --target . run secret-scan:scan --input '{}'`.
5. Open shell help without changing code:
   `cargo run -q -p kuzushi-cli -- shell --help`.
6. Read one persisted findings DB path from the first-wow output and list it:
   `cargo run -q -p kuzushi-cli -- findings --target <first-wow-temp> --json`.

## Common Gotchas

- Model/runtime compatibility is enforced at startup and dispatch; do not
  paper over it with a hardcoded fallback model.
- External binaries such as Semgrep, CodeQL, `nmap`, and `curl` are optional
  by tool. Missing binaries should fail actionably.
- `pnpm build` compiles retained TypeScript exports; Rust builds use Cargo.
- `.kuzushi`, `.ralph`, `.kuzushi-active`, native binaries, temp prompts, and
  SQLite files are local state, not product assets.
- The pre-commit hook expects `lint-staged`. If local dependencies are missing,
  run focused checks and record the hook blocker before bypassing hooks.

## Safe First Issues

- Improve README wording while preserving verified commands.
- Add a focused CLI help assertion in `crates/kuzushi-cli/tests/cutover_cli.rs`.
- Add a deterministic fixture to `examples/first-wow` without committing
  generated `.kuzushi` state.
- Move a cohesive pure helper out of a hotspot file with unchanged tests.
- Add doc drift patterns to `scripts/check-doc-command-drift.mjs`.

## Verification Recipes

Rust core module/tool change:
`cargo fmt --all --check`; `cargo check -p kuzushi-core`;
`cargo test -p kuzushi-core modules`.

Rust TUI command/reducer change:
`cargo fmt --all --check`; `cargo test -p kuzushi-tui app::tests`.

Rust TUI rendering change:
`cargo fmt --all --check`; `cargo test -p kuzushi-tui renderer::tests`.

Persisted finding/run-artifact change:
`cargo test -p kuzushi-core findings`; `cargo test -p kuzushi-cli cutover_cli`;
`bash tests/e2e/run-smoke.sh`.

Runtime/model change:
`pnpm typecheck`; run the no-silent-fallback tests named near the changed
adapter; update `AGENTS.md` and `RELEASING.md` if semantics change.

Retained TypeScript helper change:
`pnpm typecheck`; `pnpm test -- --run` if behavior changes.

Docs/public example change:
`pnpm check:docs`; run the touched example or help command.

## Do Not Break Invariants Checklist

- Does the change preserve current CLI help truth?
- Does it keep the Rust TUI as the only interactive shell?
- Does it avoid silent provider/model substitution?
- Does it preserve `.kuzushi` schema compatibility?
- Does it keep hidden DAG tools hidden from `/use`, `modules`, and `tools`?
- Does it update mode-parity docs for any intentional asymmetry?
- Does it include a focused test command in the commit/progress note?

## When To Update Docs / RELEASING

Update `README.md` for user-visible workflow changes, `docs/modules.md` for
module contract changes, `docs/assessments/mode-parity.md` for mode behavior,
and `RELEASING.md` for breaking changes, persisted format changes, runtime
model semantics, or removed public commands.
