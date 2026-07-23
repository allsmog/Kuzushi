use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde_json::{json, Value};

use super::ToolExecutionContext;

pub(in crate::modules) fn resolve_tool_target(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PathBuf> {
    if let Some(target) = input.get("target").and_then(Value::as_str) {
        let trimmed = target.trim();
        if trimmed.is_empty() {
            anyhow::bail!("target must not be empty; pass an explicit path or active workspace")
        }
        let candidate = PathBuf::from(trimmed);
        let path = if candidate.is_absolute() {
            candidate
        } else if let Some(workspace) = ctx.workspace {
            workspace.root().join(candidate)
        } else {
            anyhow::bail!(
                "relative target {trimmed:?} requires an explicit active workspace; cwd fallback is forbidden"
            )
        };
        return Ok(path);
    }

    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }

    anyhow::bail!("tool requires an explicit target or active workspace; cwd fallback is forbidden")
}

pub(in crate::modules) fn failed_tool_output(
    tool: &str,
    target: &Path,
    error: anyhow::Error,
) -> Value {
    let error = error.to_string();
    crate::module_result::failed_output_result(
        format!("{tool} failed for {}", target.display()),
        error,
        json!({
            "target": target.display().to_string(),
            "tool": tool,
        }),
    )
}

pub(in crate::modules) fn should_skip_path(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".kuzushi"
            | ".next"
            | ".turbo"
            | "coverage"
            | "dist"
            | "native"
            | "node_modules"
            | "target"
    ) || crate::incremental_index::is_bazel_output_component(name)
}

pub(in crate::modules) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::workspace::WorkspaceTarget;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn resolves_explicit_absolute_target_before_workspace() {
        let explicit = tempdir().unwrap();
        let workspace_root = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_root.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let resolved = resolve_tool_target(
            &json!({"target": explicit.path().display().to_string()}),
            &ctx,
        )
        .unwrap();

        assert_eq!(resolved, explicit.path());
    }

    #[test]
    fn resolves_workspace_target_when_input_omits_target() {
        let workspace_root = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_root.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let resolved = resolve_tool_target(&Value::Null, &ctx).unwrap();

        assert_eq!(resolved, workspace.root());
    }

    #[test]
    fn recognizes_generated_and_dependency_directories_to_skip() {
        for name in [".git", ".kuzushi", "node_modules", "target", "dist"] {
            assert!(should_skip_path(name), "{name} should be skipped");
        }

        assert!(!should_skip_path("src"));
    }

    #[test]
    fn missing_and_empty_targets_never_fall_back_to_cwd() {
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        assert!(resolve_tool_target(&Value::Null, &ctx)
            .unwrap_err()
            .to_string()
            .contains("cwd fallback is forbidden"));
        assert!(resolve_tool_target(&json!({"target": "  "}), &ctx)
            .unwrap_err()
            .to_string()
            .contains("target must not be empty"));
    }
}
