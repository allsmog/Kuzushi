use crate::support::target_or_global;
use anyhow::Result;
use kuzushi_core::{ModuleRegistry, WorkspaceTarget};
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
            "`kuzushi run .` is shell-only because the terminal command has no focused module. Use `kuzushi shell`, then `use <module>` and `run .`; from a terminal run an explicit tool such as `kuzushi --target . run context:build`."
        );
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn run_tool_workspace(
    tool: &str,
    target: Option<&Path>,
) -> Result<Option<WorkspaceTarget>> {
    let registry = ModuleRegistry::with_v2_builtins();
    run_tool_workspace_with_inline_target(&registry, tool, target, None)
}

#[cfg(test)]
pub(crate) fn run_tool_workspace_for_input(
    tool: &str,
    target: Option<&Path>,
    raw_input: &str,
) -> Result<Option<WorkspaceTarget>> {
    let registry = ModuleRegistry::with_v2_builtins();
    run_tool_workspace_for_invocation(&registry, tool, target, raw_input, &[])
}

pub(crate) fn run_tool_workspace_for_invocation(
    registry: &ModuleRegistry,
    tool: &str,
    target: Option<&Path>,
    raw_input: &str,
    option_overrides: &[String],
) -> Result<Option<WorkspaceTarget>> {
    let inline_target = invocation_target_path(registry, tool, raw_input, option_overrides)?;
    run_tool_workspace_with_inline_target(registry, tool, target, inline_target.as_deref())
}

fn invocation_target_path(
    registry: &ModuleRegistry,
    tool: &str,
    raw_input: &str,
    option_overrides: &[String],
) -> Result<Option<PathBuf>> {
    let target_is_path = registry.tool_option_is_path(tool, "target");
    let cwd_is_path = registry.tool_option_is_path(tool, "cwd");
    inline_target_path(raw_input, target_is_path, cwd_is_path)?.map_or_else(
        || option_override_target_path(option_overrides, target_is_path, cwd_is_path),
        |target| Ok(Some(target)),
    )
}

fn run_tool_workspace_with_inline_target(
    registry: &ModuleRegistry,
    tool: &str,
    global_target: Option<&Path>,
    inline_target: Option<&Path>,
) -> Result<Option<WorkspaceTarget>> {
    let global_workspace = global_target.map(WorkspaceTarget::new).transpose()?;
    if !registry.tool_requires_workspace(tool) {
        return Ok(global_workspace);
    }

    match (global_workspace, inline_target) {
        (Some(workspace), Some(inline_target)) => {
            ensure_inline_target_is_nested(&workspace, inline_target)?;
            Ok(Some(workspace))
        }
        (Some(workspace), None) => Ok(Some(workspace)),
        (None, Some(inline_target)) => Ok(Some(WorkspaceTarget::new(inline_target)?)),
        (None, None) => anyhow::bail!(
            "{tool} requires an explicit workspace target. Next: pass `--target <path>` (or `--target .` to use the current directory)."
        ),
    }
}

fn inline_target_path(
    raw_input: &str,
    target_is_path: bool,
    cwd_is_path: bool,
) -> Result<Option<PathBuf>> {
    let Some(input) = serde_json::from_str::<Value>(raw_input).ok() else {
        return Ok(None);
    };
    let target = target_is_path
        .then(|| inline_target_value(&input, "target"))
        .flatten();
    let cwd = cwd_is_path
        .then(|| inline_target_value(&input, "cwd"))
        .flatten();
    target_path_from_values(target, cwd, "inline")
}

fn option_override_target_path(
    options: &[String],
    target_is_path: bool,
    cwd_is_path: bool,
) -> Result<Option<PathBuf>> {
    let mut target = None;
    let mut cwd = None;
    for option in options {
        let Some((name, value)) = option.split_once('=') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "target" if target_is_path => target = Some(non_empty_option_target(value, "target")?),
            "cwd" if cwd_is_path => cwd = Some(non_empty_option_target(value, "cwd")?),
            _ => {}
        }
    }
    target_path_from_values(target, cwd, "--option")
}

fn non_empty_option_target<'a>(value: &'a str, name: &str) -> Result<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("--option {name} must not be empty");
    }
    Ok(value)
}

fn target_path_from_values(
    target: Option<&str>,
    cwd: Option<&str>,
    source: &str,
) -> Result<Option<PathBuf>> {
    match (target, cwd) {
        (Some(target), Some(cwd)) => {
            let target = WorkspaceTarget::new(target)?;
            let cwd = WorkspaceTarget::new(cwd)?;
            if target.root() != cwd.root() {
                anyhow::bail!(
                    "{source} target {} conflicts with cwd {}. Pass one canonical workspace target.",
                    target.root().display(),
                    cwd.root().display(),
                );
            }
            Ok(Some(target.root().to_path_buf()))
        }
        (Some(path), None) | (None, Some(path)) => Ok(Some(PathBuf::from(path))),
        (None, None) => Ok(None),
    }
}

fn inline_target_value<'a>(input: &'a Value, name: &str) -> Option<&'a str> {
    input
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|target| !target.is_empty())
}

fn ensure_inline_target_is_nested(workspace: &WorkspaceTarget, inline_target: &Path) -> Result<()> {
    let inline_workspace = WorkspaceTarget::new(inline_target)?;
    if inline_workspace.root().starts_with(workspace.root()) {
        return Ok(());
    }
    anyhow::bail!(
        "inline target {} is outside the explicit workspace {}. Use one canonical workspace target, or choose a nested path inside it.",
        inline_workspace.root().display(),
        workspace.root().display(),
    )
}

#[cfg(test)]
pub(crate) fn tool_defaults_to_workspace(tool: &str) -> bool {
    kuzushi_core::tool_defaults_to_workspace(tool)
}

#[cfg(test)]
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
    use super::{resolve_run_target, run_tool_workspace, run_tool_workspace_for_input};
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

    #[test]
    fn inline_target_becomes_the_workspace_for_workspace_backed_tools() {
        let target = tempfile::tempdir().unwrap();
        let input = serde_json::json!({ "target": target.path() }).to_string();

        let workspace = run_tool_workspace_for_input("semgrep:scan", None, &input)
            .unwrap()
            .expect("inline target should establish workspace context");

        assert_eq!(workspace.root(), target.path().canonicalize().unwrap());
    }

    #[test]
    fn inline_nested_scope_keeps_the_explicit_workspace_root() {
        let workspace_root = tempfile::tempdir().unwrap();
        let nested = workspace_root.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let input = serde_json::json!({ "target": nested }).to_string();

        let workspace =
            run_tool_workspace_for_input("semgrep:scan", Some(workspace_root.path()), &input)
                .unwrap()
                .expect("nested scan scope should retain the explicit workspace");

        assert_eq!(
            workspace.root(),
            workspace_root.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn inline_target_outside_explicit_workspace_is_rejected() {
        let workspace_root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let input = serde_json::json!({ "target": outside.path() }).to_string();

        let error =
            run_tool_workspace_for_input("semgrep:scan", Some(workspace_root.path()), &input)
                .unwrap_err()
                .to_string();

        assert!(error.contains("outside the explicit workspace"), "{error}");
    }

    #[test]
    fn conflicting_inline_target_and_cwd_are_rejected() {
        let target = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        let input = serde_json::json!({ "target": target.path(), "cwd": cwd.path() }).to_string();

        let error = run_tool_workspace_for_input("semgrep:scan", None, &input)
            .unwrap_err()
            .to_string();

        assert!(error.contains("conflicts with cwd"), "{error}");
    }

    #[test]
    fn equivalent_inline_target_and_cwd_are_accepted() {
        let target = tempfile::tempdir().unwrap();
        let equivalent = target.path().join(".");
        let input = serde_json::json!({ "target": target.path(), "cwd": equivalent }).to_string();

        let workspace = run_tool_workspace_for_input("semgrep:scan", None, &input)
            .unwrap()
            .expect("equivalent canonical paths should establish a workspace");

        assert_eq!(workspace.root(), target.path().canonicalize().unwrap());
    }
}
