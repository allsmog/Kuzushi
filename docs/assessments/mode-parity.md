# Mode Parity Assessment

This document describes the current Rust execution surfaces for `kuzushi scan`,
the interactive shell, and `kuzushi run`. Historical TypeScript runtime notes
belong in migration ledgers, not in this current operator contract.

## Shared Boundary

All modes should prepare and dispatch tools through the Rust module registry:

- `ModuleRegistry::prepare_tool_input(...)`
- `ModuleRegistry::dispatch_prepared_tool_with_runtime(...)`

The implementation lives under
`crates/kuzushi-core/src/modules/builtins/with_v2_builtins/`. Mode-specific
code may create workspace, runtime, trace, option-store, and cancellation
context, but descriptor-backed option validation and output normalization belong
to the shared registry boundary.

## Current Matrix

Legend: ✓ = present, ◐ = partial or tool-dependent, N/A = not applicable.

| Capability | scan | shell | run | Notes |
| --- | :--: | :---: | :-: | --- |
| Registry input preparation | ✓ | ✓ | ✓ | CLI scan compiles flags into `sast:scan`; shell and run prepare focused tool input through the same registry method. |
| Descriptor option validation | ✓ | ✓ | ✓ | `OptionSpec` aliases, defaults, coercion, and unknown-key checks are centralized where descriptors are present. |
| Stored tool options | ✓ | ✓ | ✓ | Global/workspace option stores are loaded before registry preparation. |
| Explicit input precedence | ✓ | ✓ | ✓ | Explicit JSON or command input overlays stored options. |
| Runtime no-silent-fallback policy | ✓ | ✓ | ✓ | Runtime-backed tools resolve a configured model and fail on incompatible provider/runtime pairs. |
| Findings store support | ◐ | ◐ | ◐ | Tools that require a store must receive one from mode preparation; policy must remain shared. |
| Trace/run artifacts | ✓ | ✓ | ✓ | Tool dispatch writes canonical run artifacts where the mode starts a traced run. |
| Cancellation | ✓ | ✓ | ✓ | Scan and shell wire cancellation handles; headless run must keep SIGINT cancellation parity. |
| Plain/scripted output | ✓ | ✓ | ✓ | Plain output should reuse the same view-model or line-builder data as TTY output. |
| Interactive views | N/A | ✓ | N/A | Workbench, Activity, replay/trace, prompt editor, and guided pickers are shell-only. |
| Machine output | ✓ | N/A | ✓ | Scan has CI/scripted output; run uses `--json` for single-tool automation. |

## Intentional Asymmetries

- **Interactive shell views** are shell-only: Workbench, Activity dashboard,
  replay/trace, prompt tuning, actor detail, guided phase picker, model/auth
  pickers, and two-stage idle Ctrl+C.
- **`--ci` is scan-only.** `kuzushi run` should use `--json` and run artifacts
  for machine consumers.
- **Pipeline JSONL artifacts are scan-owned.** All three write the canonical run bundle:
  `run.json`, `events.jsonl`, `trace.jsonl`, `failures.json`,
  `report.md`, `artifacts.json`, and legacy `summary.json`. Single-tool
  run/shell dispatch also writes tool input/result artifacts, but scan
  orchestration owns pipeline files such as `triage.jsonl` and `verify.jsonl`
  unless a tool explicitly emits them.
- **Workspace handles are shell lifecycle objects.** Headless run can pass a
  workspace id to tools that look one up, but it does not own the shell's live
  workspace-manager lifecycle.
- **DAG descriptors are not automatically execution ordering.** In the current
  Rust path, a `depends_on` edge is execution input only when the owning scan
  executor consumes it. Otherwise it is progress/catalog metadata.

## Current Parity Risks

- Per-tool policy still has mode-specific call sites. Runtime requirements are
  centralized; findings-store, cancellation, workspace-default, and related
  policy should follow the same descriptor-backed pattern.
- Hidden or descriptor-less tools can bypass strict option validation unless
  they declare their accepted input or the shared input boundary rejects unknown
  keys for them.
- Command discoverability depends on parser, handler, and help/spec metadata
  staying aligned. Tests should assert that every parsed shell verb is visible
  or intentionally hidden.
- View-models should stay pure or read through cached app services. Per-frame
  filesystem reads in TUI review surfaces are parity/performance bugs because
  plain and TTY output should observe the same data without repeated IO.

## Adding Shared Behavior

1. Add the user-facing knob to `ToolDescriptor.options` first.
2. Consume canonical prepared input in the Rust executor.
3. Put mode-independent policy in `crates/kuzushi-core/src/modules/` or a core
   application service, not in CLI/TUI allowlists.
4. Add a parity test that exercises scan, shell preparation, and headless run
   where the feature is expected to work in all modes.
5. If the feature is intentionally shell-only or scan-only, add it to the
   intentional-asymmetry list in this file and in `AGENTS.md`.
