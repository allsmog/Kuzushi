# Descriptor/executor decoupling

## Context

An earlier agent left the tree broken while attempting two legitimate refactors:

1. Give the report module real per-tool executors instead of routing through the catch-all string-match dispatch shared by 14 modules.
2. Break the descriptor-to-registry dependency cycle caused by `descriptor_model.rs` importing `registry::ToolExecutor`, so descriptor models can live in their own crate.

The broken state includes a two-parameter function where a five-parameter `ToolExecutor` is required, a call to a nonexistent `crate::report::build_markdown_report`, and two orphaned non-workspace proof-of-concept crates based on `Box<dyn Any>` type erasure.

The required outcome includes the full physical extraction of descriptor models into the workspace member `crates/kuzushi-descriptor`.

## Design

`ModuleRegistry.executors: BTreeMap<String, ToolExecutor>` is already keyed by tool name, and `invoke_prepared_executor` in `execution.rs` reads only that map. It never reads `tool.executor`.

The descriptor executor field is only a registration-time conveyance. It is `#[serde(skip)]` and excluded from the manual `PartialEq`. The correct fix is to remove the field, keep descriptors as pure data, and carry executor bindings on `BuiltinModule`, the registration layer. This preserves dispatch behavior, the serialized descriptor fingerprint, and public contracts without type erasure.

## Phase 0 — Restore a compiling baseline

- Restore these two broken tracked files from `HEAD`:
  - `crates/kuzushi-core/src/modules/builtins/with_v2_builtins/builtin_registration.rs`
  - `crates/kuzushi-core/src/modules/report_module.rs`
- Remove the two untracked, non-member, non-compiling proof-of-concept crates:
  - `crates/kuzushi-contract`
  - `crates/kuzushi-descriptor`
- Recreate `crates/kuzushi-descriptor` properly in Phase 3.
- Do not touch the four unrelated dirty files:
  - `README.md`
  - `package.json`
  - `crates/kuzushi-tui/src/app/review_session.rs`
  - `crates/kuzushi-tui/src/app/review_session/tests.rs`

Checkpoint:

```sh
cargo check -p kuzushi-core
git status --short
```

## Phase 1 — Move executor bindings to `BuiltinModule`

### `modules/descriptor/metadata.rs`

- Add `use std::collections::BTreeMap;`.
- Keep the `ToolExecutor` import because metadata is the registration layer.
- Add two `BuiltinModule` fields, both `pub(in crate::modules)`:

```rust
tool_executors: BTreeMap<String, ToolExecutor>,
dag_executors: BTreeMap<String, ToolExecutor>,
```

- Initialize both maps in the sole `module()` constructor.
- Rewrite `with_executor` to populate both maps by iterating over `self.tools` and `self.dag_nodes` and inserting by `tool.name` and `node.id`.
- Cover DAG nodes because several DAG-bearing modules currently obtain their executors solely through module-wide `with_executor`.
- Add a per-tool override. Insertion must win over a prior module-wide default, while a wrong name fails loudly during registration:

```rust
pub(in crate::modules) fn with_tool_executor(
    mut self,
    name: &str,
    executor: ToolExecutor,
) -> Self {
    debug_assert!(
        self.tools.iter().any(|tool| tool.name == name),
        "with_tool_executor: no tool named {name:?}"
    );
    self.tool_executors.insert(name.to_string(), executor);
    self
}
```

- Delete `executor: None` from `tool_with_options`.

### `modules/descriptor/max_findings_option.rs`

- Delete `executor: None` from `dag()`.

### `modules/descriptor/descriptor_model.rs`

- Remove the `ToolExecutor` registry import.
- Remove the executor fields from `ToolDescriptor` and `DagNodeDescriptor`.
- Preserve the manual `PartialEq` for `ToolDescriptor`, including its existing exclusion of `policy_declared`.

### `builtins/with_v2_builtins/builtin_registration.rs`

- Rewrite tool and DAG registration loops to read the new maps:
  - `builtin.tool_executors.get(&tool.name).copied()`
  - `builtin.dag_executors.get(&node.id).copied()`
- Preserve the exact existing panic messages.
- Preserve the DAG only-if-absent rule: tools register first, so a DAG node ID matching a tool name keeps the tool executor.
- Use `.copied()` for fn-pointer lookups to satisfy Clippy.

All existing module-wide `with_executor` call sites retain their signatures.

Checkpoint tests:

```sh
cargo test -p kuzushi-core registered_builtin_tools_have_executor_metadata
cargo test -p kuzushi-core resolves_representative_ported_tools
cargo test -p kuzushi-core dispatches_report_build_for_run_artifacts
```

## Phase 2 — Give report tools real per-tool executors

### `modules/report_module.rs`

- Move `build_report_tool` verbatim from `registry/dispatch_catalog_tool.rs` into this module.
- Preserve its use of `resolve_tool_target` and `crate::report::build_run_report(&target, run_id)`. It must not use a findings store because `dispatches_report_build_for_run_artifacts` pins behavior with `findings_store: None`.
- Rename the existing two-parameter `execute_report_sarif_tool` to `run_report_sarif_tool`.
- Add two five-parameter `ToolExecutor`-shaped thunks:
  - `execute_report_build_tool`
  - `execute_report_sarif_tool`
- The thunks ignore `_registry`, `_name`, and `_runtime`, then delegate to `build_report_tool` or `run_report_sarif_tool`.
- Do not add `dispatch_result` wrapping; the executor is bound by name at registration and has no unknown-tool path.

### `builtin_registration.rs`

Register report without `with_executor`:

```rust
registry.register(
    report_module()
        .with_tool_executor("report:build", execute_report_build_tool)
        .with_tool_executor("report:sarif", execute_report_sarif_tool),
);
```

Report has no DAG nodes, so missing bindings independently fail registration.

### `registry/dispatch_catalog_tool.rs`

- Delete the `report:build` and `report:sarif` match arms.
- Delete the moved `build_report_tool` helper.

### New tests

1. `registry/tests.rs::report_tools_no_longer_route_through_catch_all`
   - `dispatch_context_workspace_tool("report:build", ...)` and `dispatch_context_workspace_tool("report:sarif", ...)` return `None`.
   - `registry.executors` contains `report:build`.
2. `descriptor/tests.rs::with_tool_executor_binds_named_tool_over_module_default`
   - Build a demo module with two tools.
   - Apply `.with_executor(marker_a).with_tool_executor("demo:special", marker_b)`.
   - Assert the override wins while the default still covers the other tool.
3. `descriptor/tests.rs::descriptor_serde_shape_is_stable`
   - Pin exact JSON for a representative `ToolDescriptor` to protect the fingerprint surface across both field removal and the Phase 3 move.

Checkpoint:

```sh
cargo test -p kuzushi-core report
cargo test -p kuzushi-core
cargo clippy -p kuzushi-core --all-targets -- -D warnings
```

## Phase 3 — Extract descriptor models into `crates/kuzushi-descriptor`

Perform this only after Phase 1 has removed the registry dependency.

The moving code depends only on `serde`, `serde_json`, pure sibling types, and pure prompt-path composition.

### Move to the new crate

- `descriptor_model.rs` wholesale:
  - all 11 types
  - `OptionSpec` builder implementation
  - manual `PartialEq`
  - replace `use super::*` with explicit imports
- `tool_phase.rs` wholesale, including `canonical_tool_phase` and its tests.
- From `tool_policy.rs`, move the types only:
  - `ToolEffect`
  - `ApprovalPolicy`
  - `WorkspaceRequirement`
  - `FindingStoreRequirement`
  - `ToolPolicy`
  - `ToolPolicy::new`
  - the corresponding unit test
- From `metadata.rs`, move the inherent `ToolDescriptor` builders:
  - `with_prompt`
  - `with_continuation`
  - `with_policy`
- From `options/prompt_paths.rs`, move:
  - `PROMPTS_DIR`
  - `relative_prompt_override_path`
  - the other two relative-path helpers

### Keep in `kuzushi-core`

- `metadata.rs`:
  - `BuiltinModule`
  - executor maps
  - authoring helpers such as `module`, `tool_with_options`, and `opt`
- Policy constructor sugar such as `workspace_policy`, `read_policy`, and `target_write_policy`:
  - keep these as free `const fn`s calling public `ToolPolicy::new`
  - shrink core's `tool_policy.rs` to these helpers plus a `pub use kuzushi_descriptor::{...}` shim
- Validation:
  - convert `ToolDescriptor::validate_declared_policy` and `validate_prompt_options` into free functions in `modules/descriptor/descriptor_validation.rs`
  - update all three call sites, including `dynamic_loader.rs`
  - keep the extracted crate free of `anyhow`

### Crate scaffolding

- Add `crates/kuzushi-descriptor` as a workspace member in alphabetical order.
- Use workspace version, edition, Rust version, license, authors, and repository metadata.
- Use `serde` and `serde_json` from `[workspace.dependencies]`.
- Add `[lints] workspace = true`.
- Do not add a nested `[workspace]` table.
- Add `kuzushi-descriptor` to `kuzushi-core/Cargo.toml` dependencies.

### Compatibility shims

In `modules/descriptor/mod.rs`, replace the local model and tool-phase modules/re-exports with:

```rust
pub use kuzushi_descriptor::{
    canonical_tool_phase, ContinuationSupport, DagNodeDescriptor,
    FileReferenceSemantics, ModuleKind, ModuleMetadata, OptionSpec, OptionType,
    PathSemantics, PromptSpec, RuntimeRequirement, ToolDescriptor, ToolPhase,
};
```

This keeps `contracts/mod.rs`, `modules/mod.rs`, and downstream CLI/TUI consumers compiling unchanged.

In `options/prompt_paths.rs`, re-export the moved relative helpers and `PROMPTS_DIR`, while workspace-rooted helpers stay in core and consume the re-export.

Items previously restricted with `pub(in crate::modules)` become public as required by the extracted crate. Mark builders, `OptionSpec::new`, and `policy_declared` as `#[doc(hidden)]` with an authoring-internals comment. The public core surface remains unchanged through the compatibility shim.

## Risks and gotchas

1. Remove exactly two `executor: None` literals: one in `metadata.rs`, one in `max_findings_option.rs`. Confirm no executor field remains under `modules/descriptor/` after Phase 1.
2. Preserve the manual `PartialEq` for `ToolDescriptor`; it intentionally excludes `policy_declared`.
3. Ensure `with_executor` fills `dag_executors` for every node ID or registration will panic for DAG-bearing modules.
4. Use `.copied()` on fn-pointer map lookups and import `BTreeMap` explicitly for Clippy.
5. Preserve every Serde attribute. The exact-JSON test pins fingerprint stability.
6. Update the `dynamic_loader.rs` validation call when validation becomes free functions.
7. Do not revert the unrelated dirty files.

## Verification

Phase checks:

```sh
cargo check -p kuzushi-core
cargo test -p kuzushi-core registered_builtin_tools_have_executor_metadata
cargo test -p kuzushi-core resolves_representative_ported_tools
cargo test -p kuzushi-core dispatches_report_build_for_run_artifacts
cargo test -p kuzushi-core report
cargo test -p kuzushi-core
cargo test -p kuzushi-descriptor
cargo test -p kuzushi-tui
cargo test -p kuzushi-cli
```

Final gate:

```sh
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo fmt --check
pnpm quality:crap-risk
```

Cycle proof:

```sh
grep -rn 'crate::modules::registry' crates/kuzushi-descriptor/
```

The cycle-proof command must return no matches.
