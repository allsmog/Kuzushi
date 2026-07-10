use crate::support::target_or_global;
use anyhow::Result;
use kuzushi_core::WorkspaceTarget;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Resolve the workspace target for `kuzushi run` through the shared CLI
/// precedence policy (`target_or_global`: explicit command target, else the
/// global `--target` default). `Command::Run` declares no command-level
/// `--target`, so the command slot is structurally `None` and the global flag
/// is the only source. Routing through the shared helper keeps run on the
/// same resolution policy as scan and shell instead of a parallel code path;
/// an unresolved target stays `None` — never a silent cwd fallback (the
/// workspace gate in `run_tool_workspace` errors instead).
pub(crate) fn resolve_run_target(global_target: Option<PathBuf>) -> Option<PathBuf> {
    let run_command_target: Option<PathBuf> = None;
    target_or_global(run_command_target, global_target)
}

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

#[cfg(test)]
mod resolve_run_target_tests {
    use super::{resolve_run_target, run_tool_workspace};
    use crate::support::target_or_global;
    use std::path::PathBuf;

    #[test]
    fn run_resolution_matches_the_shared_policy_for_an_explicit_target() {
        let explicit = Some(PathBuf::from("/tmp/kuzushi-audit-target"));
        assert_eq!(
            resolve_run_target(explicit.clone()),
            target_or_global(None, explicit.clone())
        );
        assert_eq!(resolve_run_target(explicit.clone()), explicit);
    }

    #[test]
    fn run_resolution_matches_the_shared_policy_for_target_dot() {
        let dot = Some(PathBuf::from("."));
        assert_eq!(
            resolve_run_target(dot.clone()),
            target_or_global(None, dot.clone())
        );
        assert_eq!(resolve_run_target(dot.clone()), dot);
    }

    #[test]
    fn run_resolution_matches_the_shared_policy_with_only_a_global_default() {
        // `kuzushi --target <path> run <tool>`: no command-level target exists,
        // so the global default is the resolved target — same as the shared path.
        let global = Some(PathBuf::from("/tmp/kuzushi-global-default"));
        assert_eq!(
            resolve_run_target(global.clone()),
            target_or_global(None, global.clone())
        );
        assert_eq!(resolve_run_target(global.clone()), global);
    }

    #[test]
    fn target_dot_builds_a_workspace_at_the_explicitly_chosen_cwd() {
        let resolved = resolve_run_target(Some(PathBuf::from(".")));
        let workspace = run_tool_workspace("sast:scan", resolved.as_deref())
            .expect("--target . is an explicit cwd opt-in")
            .expect("explicit target must produce a workspace");
        let cwd = std::fs::canonicalize(std::env::current_dir().expect("cwd")).expect("canonical");
        assert_eq!(workspace.root(), cwd.as_path());
    }

    #[test]
    fn unresolved_run_target_never_falls_back_to_cwd_for_workspace_tools() {
        let resolved = resolve_run_target(None);
        assert_eq!(resolved, None);
        let error = run_tool_workspace("sast:scan", resolved.as_deref())
            .expect_err("workspace-default tools must demand an explicit target");
        assert!(error.to_string().contains("--target"), "error: {error}");
    }
}
