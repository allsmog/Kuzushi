use anyhow::Result;
use kuzushi_core::WorkspaceTarget;
use serde_json::Value;
use std::path::Path;

pub(crate) fn reject_shell_only_run_dot(tool: &str) -> Result<()> {
    if tool == "." {
        anyhow::bail!(
            "`kuzushi run .` is shell-only because the terminal command has no focused module. Use `kuzushi shell`, then `use <module>` and `run .`; from a terminal run an explicit tool such as `kuzushi --target . run context:build --input '{{}}'`."
        );
    }
    Ok(())
}

pub(crate) fn run_tool_workspace(
    tool: &str,
    target: Option<&Path>,
) -> Result<Option<WorkspaceTarget>> {
    run_tool_workspace_with_explicit_input_target(tool, target, false)
}

pub(crate) fn run_tool_workspace_for_input(
    tool: &str,
    target: Option<&Path>,
    raw_input: &str,
) -> Result<Option<WorkspaceTarget>> {
    let input_has_target = raw_input_has_target(raw_input);
    if !input_has_target {
        return run_tool_workspace(tool, target);
    }
    run_tool_workspace_with_explicit_input_target(tool, target, input_has_target)
}

fn run_tool_workspace_with_explicit_input_target(
    tool: &str,
    target: Option<&Path>,
    input_has_target: bool,
) -> Result<Option<WorkspaceTarget>> {
    match target {
        Some(target) => Ok(Some(WorkspaceTarget::new(target)?)),
        None if tool_defaults_to_workspace(tool) && !input_has_target => {
            anyhow::bail!(
                "{tool} requires an explicit workspace target. Next: pass `--target <path>` (or `--target .` to use the current directory)."
            )
        }
        None => Ok(None),
    }
}

fn raw_input_has_target(raw_input: &str) -> bool {
    serde_json::from_str::<Value>(raw_input)
        .ok()
        .is_some_and(|input| input_has_target_value(&input))
}

fn input_has_target_value(input: &Value) -> bool {
    ["target", "cwd"].into_iter().any(|key| {
        input
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|target| !target.trim().is_empty())
    })
}

pub(crate) fn tool_defaults_to_workspace(tool: &str) -> bool {
    kuzushi_core::tool_defaults_to_workspace(tool)
}

pub(crate) fn tool_needs_finding_store(tool: &str) -> bool {
    kuzushi_core::tool_needs_finding_store(tool)
}

/// Whether `kuzushi run <tool>` needs to construct an agent runtime
/// before dispatch. Thin re-export of `kuzushi_core::tool_needs_runtime`
/// — the canonical name + input-aware combiner shared with the shell.
#[cfg(test)]
pub(crate) fn tool_needs_runtime(tool: &str, input: &serde_json::Value) -> bool {
    kuzushi_core::tool_needs_runtime(tool, input)
}
