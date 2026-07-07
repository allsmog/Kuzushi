use super::*;
use crate::identity::Blake3Hash;
use crate::incremental_index::{index_workspace_snapshot, IndexedWorkspaceSnapshot};
use crate::plugin_sandbox::{
    record_plugin_findings_with_actor, run_wasm_plugin_invocation, EnvPolicy, GrantedSnapshot,
    NetworkPolicy, PluginObservationContext, PluginSandboxBackend, SandboxPolicy, SubprocessPolicy,
    WasmPluginInvocation,
};
use crate::storage_v3::writer_actor::WriteReceipt;
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const TOOL_NAME: &str = "wasm-plugin:analyze";

pub(in crate::modules) fn wasm_plugin_module() -> BuiltinModule {
    builtin_module(
        "wasm-plugin",
        "Wasm Plugin",
        ModuleKind::Offense,
        "Run a capability-scoped Wasm analyzer against the indexed source snapshot.",
        vec![tool_with_options(
            TOOL_NAME,
            "Run a Wasm analyzer and commit host-checked findings through the v3 writer.",
            wasm_plugin_options(),
        )],
        vec![dag(TOOL_NAME, "findings", &["context:build"])],
    )
}

pub(in crate::modules) fn run_wasm_plugin_analyze(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let workspace = WorkspaceTarget::new(&target)?;
    let module_path = required_input_path(&input, &target)?;
    let snapshot = index_workspace_snapshot(&workspace)?;
    let grant = granted_snapshot(&snapshot)?;
    let policy = sandbox_policy_from_input(&input)?;
    let result = run_wasm_plugin_invocation(WasmPluginInvocation {
        module_path: module_path.clone(),
        policy,
        grant: grant.clone(),
    })?;
    let backend = result.backend;
    let duration_ms = result.duration_ms;
    let receipts = record_plugin_findings_with_actor(
        workspace.event_log_dir(),
        workspace.findings_db_path(),
        &observation_context(ctx, &snapshot),
        &grant,
        result.findings,
    )?;

    Ok(completed_wasm_plugin_result(
        &target,
        &module_path,
        &snapshot,
        &receipts,
        backend,
        duration_ms,
    ))
}

fn completed_wasm_plugin_result(
    target: &Path,
    module_path: &Path,
    snapshot: &IndexedWorkspaceSnapshot,
    receipts: &[WriteReceipt],
    backend: PluginSandboxBackend,
    duration_ms: u64,
) -> Value {
    crate::module_result::completed_output_result(
        format!(
            "wasm-plugin analyzed {} indexed files and committed {} findings",
            snapshot.file_count,
            receipts.len()
        ),
        format!(
            "wasm-plugin: committed {} findings from {}",
            receipts.len(),
            module_path.display()
        ),
        json!({
            "target": target.display().to_string(),
            "modulePath": module_path.display().to_string(),
            "snapshotHash": snapshot.snapshot_hash,
            "treeHash": snapshot.tree_hash,
            "indexedFiles": snapshot.file_count,
            "committedFindings": receipts.len(),
            "receipts": receipts,
            "backend": backend,
            "durationMs": duration_ms,
        }),
    )
}

fn wasm_plugin_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        wasm_module_path_option(),
        max_findings_option(100),
        max_bytes_served_option(),
        max_output_bytes_option(),
        max_field_bytes_option(),
        wasm_memory_limit_option(),
        wasm_fuel_limit_option(),
    ]
}

fn wasm_module_path_option() -> OptionSpec {
    opt(
        "modulePath",
        OptionType::Path,
        "Path to the Wasm analyzer module.",
    )
    .aliases(&["module_path", "wasmPath", "wasm_path"])
    .required()
}

fn max_bytes_served_option() -> OptionSpec {
    opt(
        "maxBytesServed",
        OptionType::Int,
        "Maximum source bytes the host may serve to the Wasm plugin.",
    )
    .aliases(&["max_bytes_served"])
    .default(json!(16 * 1024 * 1024))
    .advanced()
}

fn max_output_bytes_option() -> OptionSpec {
    opt(
        "maxOutputBytes",
        OptionType::Int,
        "Maximum JSON output bytes the Wasm plugin may return.",
    )
    .aliases(&["max_output_bytes"])
    .default(json!(1024 * 1024))
    .advanced()
}

fn max_field_bytes_option() -> OptionSpec {
    opt(
        "maxFieldBytes",
        OptionType::Int,
        "Maximum bytes for each returned finding text field.",
    )
    .aliases(&["max_field_bytes"])
    .default(json!(16 * 1024))
    .advanced()
}

fn wasm_memory_limit_option() -> OptionSpec {
    opt(
        "memoryLimitMb",
        OptionType::Int,
        "Maximum Wasm linear memory in MiB.",
    )
    .aliases(&["memory_limit_mb"])
    .default(json!(256))
    .advanced()
}

fn wasm_fuel_limit_option() -> OptionSpec {
    opt(
        "fuelLimit",
        OptionType::Int,
        "Maximum Wasm fuel for analysis.",
    )
    .aliases(&["fuel_limit"])
    .default(json!(10_000_000))
    .advanced()
}

fn required_input_path(input: &Value, target: &Path) -> Result<PathBuf> {
    let raw = string_input_any(
        input,
        &["modulePath", "module_path", "wasmPath", "wasm_path"],
    )
    .context("wasm-plugin:analyze requires modulePath")?;
    let path = resolve_input_path(target, &raw);
    if path.is_file() {
        Ok(path)
    } else {
        anyhow::bail!(
            "wasm-plugin:analyze modulePath is not a file: {}",
            path.display()
        )
    }
}

fn sandbox_policy_from_input(input: &Value) -> Result<SandboxPolicy> {
    Ok(SandboxPolicy {
        read_snapshot: true,
        read_ast: false,
        write_workspace: false,
        network: NetworkPolicy::None,
        subprocess: SubprocessPolicy::None,
        env: EnvPolicy::None,
        memory_limit_bytes: mb_to_bytes(optional_u64_input(
            input,
            &["memoryLimitMb", "memory_limit_mb"],
            256,
        )?)?,
        fuel_limit: optional_u64_input(input, &["fuelLimit", "fuel_limit"], 10_000_000)?,
        timeout_ms: 5_000,
        max_bytes_served: optional_u64_input(
            input,
            &["maxBytesServed", "max_bytes_served"],
            16 * 1024 * 1024,
        )?,
        max_output_bytes: optional_u64_input(
            input,
            &["maxOutputBytes", "max_output_bytes"],
            1024 * 1024,
        )?,
        max_field_bytes: optional_u64_input(
            input,
            &["maxFieldBytes", "max_field_bytes"],
            16 * 1024,
        )?,
        max_findings_returned: optional_u64_input(input, &["maxFindings", "max_findings"], 100)?
            .min(1_000)
            .try_into()
            .unwrap_or(1_000),
    })
}

fn optional_u64_input(input: &Value, keys: &[&str], default: u64) -> Result<u64> {
    let Some(value) = keys.iter().find_map(|key| input.get(*key)) else {
        return Ok(default);
    };
    let value = value
        .as_u64()
        .with_context(|| format!("wasm-plugin:analyze {} must be a positive integer", keys[0]))?;
    if value == 0 {
        anyhow::bail!("wasm-plugin:analyze {} must be greater than zero", keys[0]);
    }
    Ok(value)
}

fn mb_to_bytes(value: u64) -> Result<u64> {
    value
        .checked_mul(1024 * 1024)
        .context("wasm-plugin:analyze memoryLimitMb is too large")
}

fn granted_snapshot(snapshot: &IndexedWorkspaceSnapshot) -> Result<GrantedSnapshot> {
    let mut blobs = Vec::with_capacity(snapshot.files.len());
    for file in &snapshot.files {
        blobs.push((
            Blake3Hash::new(file.blob_hash.clone())?,
            file.file_size,
            file.storage_path.clone(),
        ));
    }
    Ok(GrantedSnapshot::with_objects(blobs))
}

fn observation_context(
    ctx: &ToolExecutionContext<'_>,
    snapshot: &IndexedWorkspaceSnapshot,
) -> PluginObservationContext {
    PluginObservationContext {
        snapshot_hash: snapshot.snapshot_hash.clone(),
        run_id: ctx
            .run_id()
            .unwrap_or_else(|| "wasm-plugin-run".to_string()),
        tool: TOOL_NAME.to_string(),
        tool_version: None,
        rule_set_hash: None,
        actor: "wasm-plugin".to_string(),
        display_paths: blob_map(snapshot, |file| Some(file.path.clone())),
        languages: blob_map(snapshot, |file| file.language.clone()),
    }
}

fn blob_map(
    snapshot: &IndexedWorkspaceSnapshot,
    value: impl Fn(&crate::incremental_index::IndexedSnapshotFile) -> Option<String>,
) -> BTreeMap<Blake3Hash, String> {
    snapshot
        .files
        .iter()
        .filter_map(|file| {
            let key = Blake3Hash::new(file.blob_hash.clone()).ok()?;
            value(file).map(|value| (key, value))
        })
        .collect()
}

#[cfg(test)]
mod tests;
