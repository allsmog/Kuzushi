//! Resolve everything a chain run needs from operator input + the workspace.
//!
//! The scope is read inline from the tool input or from
//! `.kuzushi/engagement-scope.json`; the chain spec inline or from
//! `.kuzushi/plays/<name>.json`. Resolution is pure given the file contents,
//! so the only side effect (reading the files) is isolated to one function and
//! the parsing/validation is fully testable.

use super::chain::AttackChain;
use super::engagement_scope::EngagementScope;
use super::spec::ChainSpec;
use serde_json::Value;
use std::path::{Component, Path, PathBuf};

const MAX_ENGAGEMENT_FILE_BYTES: usize = 1024 * 1024;

/// A ready-to-run chain: the authorized-scope policy, the target host string,
/// and the executable chain, all resolved and checked.
#[derive(Debug)]
pub struct PreparedChainRun {
    pub scope: EngagementScope,
    pub target_host: String,
    pub chain: AttackChain,
}

/// Resolve a chain run from tool input rooted at `workspace_root`.
pub fn prepare_chain_run(input: &Value, workspace_root: &Path) -> Result<PreparedChainRun, String> {
    let (scope, target_host) = resolve_engagement(input, workspace_root)?;
    let spec = resolve_chain_spec(input, workspace_root)?;
    let chain = spec.build()?;
    Ok(PreparedChainRun {
        scope,
        target_host,
        chain,
    })
}

/// Resolve just the engagement scope and target host — the floor both the
/// declarative chain and the LLM-planned loop need before authorizing.
pub fn resolve_engagement(
    input: &Value,
    workspace_root: &Path,
) -> Result<(EngagementScope, String), String> {
    let target_host = string_field(input, &["target", "targetHost", "target_host"])
        .ok_or_else(|| "offense:chain requires a target host".to_string())?;
    let scope = resolve_scope(input, workspace_root)?;
    Ok((scope, target_host))
}

fn resolve_scope(input: &Value, workspace_root: &Path) -> Result<EngagementScope, String> {
    if let Some(inline) = input.get("scope").filter(|value| !value.is_null()) {
        return serde_json::from_value(inline.clone())
            .map_err(|err| format!("invalid inline scope: {err}"));
    }
    let path = workspace_root.join(".kuzushi/engagement-scope.json");
    let contents = read_required(workspace_root, &path, "engagement scope")?;
    serde_json::from_str(&contents).map_err(|err| format!("invalid {}: {err}", path.display()))
}

fn resolve_chain_spec(input: &Value, workspace_root: &Path) -> Result<ChainSpec, String> {
    if let Some(inline) = input.get("chain").filter(|value| !value.is_null()) {
        return serde_json::from_value(inline.clone())
            .map_err(|err| format!("invalid inline chain spec: {err}"));
    }
    let name = string_field(input, &["chainFile", "chain_file", "play"])
        .ok_or_else(|| "offense:chain requires a chain (inline) or chainFile name".to_string())?;
    let path = chain_file_path(workspace_root, &name)?;
    let contents = read_required(workspace_root, &path, "chain spec")?;
    serde_json::from_str(&contents).map_err(|err| format!("invalid {}: {err}", path.display()))
}

/// `.kuzushi/plays/<name>.json`, accepting `name`, `name.json`, or a relative
/// path under the workspace. Rejects absolute paths and `..` traversal.
fn chain_file_path(workspace_root: &Path, name: &str) -> Result<PathBuf, String> {
    let trimmed = name.trim().trim_end_matches(".json");
    let relative = Path::new(trimmed);
    if trimmed.is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("chainFile must be a non-empty relative path without traversal".to_string());
    }
    Ok(workspace_root
        .join(".kuzushi/plays")
        .join(format!("{trimmed}.json")))
}

fn read_required(workspace_root: &Path, path: &Path, label: &str) -> Result<String, String> {
    crate::workspace::read_workspace_text(workspace_root, path, MAX_ENGAGEMENT_FILE_BYTES).map_err(
        |err| {
            format!(
                "could not read {label} at {}: {err}; declare it inline or create the file",
                path.display()
            )
        },
    )
}

fn string_field(input: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| input.get(*key))
        .find_map(Value::as_str)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inline_scope() -> Value {
        json!({"authorized": true, "authorizationRef": "HTB:lab", "inScope": ["10.0.0.5"]})
    }

    fn inline_chain() -> Value {
        json!({"name": "probe", "plays": [{"name": "p", "path": "/", "expectStatus": 200}]})
    }

    #[test]
    fn resolves_a_fully_inline_run() {
        let input = json!({
            "target": "10.0.0.5",
            "scope": inline_scope(),
            "chain": inline_chain(),
        });
        let prepared = prepare_chain_run(&input, Path::new("/tmp/ws")).unwrap();
        assert_eq!(prepared.target_host, "10.0.0.5");
        assert_eq!(prepared.chain.len(), 1);
        assert!(prepared.scope.authorized);
    }

    #[test]
    fn missing_target_is_rejected() {
        let input = json!({"scope": inline_scope(), "chain": inline_chain()});
        let err = prepare_chain_run(&input, Path::new("/tmp/ws")).unwrap_err();
        assert!(err.contains("target host"));
    }

    #[test]
    fn loads_scope_and_chain_from_workspace_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".kuzushi/plays")).unwrap();
        std::fs::write(
            root.join(".kuzushi/engagement-scope.json"),
            inline_scope().to_string(),
        )
        .unwrap();
        std::fs::write(
            root.join(".kuzushi/plays/probe.json"),
            inline_chain().to_string(),
        )
        .unwrap();

        let input = json!({"target": "10.0.0.5", "chainFile": "probe"});
        let prepared = prepare_chain_run(&input, root).unwrap();
        assert_eq!(prepared.chain.name(), "probe");
        assert!(prepared.scope.authorized);
    }

    #[test]
    fn missing_scope_file_explains_how_to_fix() {
        let dir = tempfile::tempdir().unwrap();
        let input = json!({"target": "10.0.0.5", "chain": inline_chain()});
        let err = prepare_chain_run(&input, dir.path()).unwrap_err();
        assert!(err.contains("engagement scope"));
        assert!(err.contains("inline"));
    }

    #[test]
    fn chain_file_name_cannot_traverse() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".kuzushi/engagement-scope.json"),
            inline_scope().to_string(),
        )
        .ok();
        std::fs::create_dir_all(dir.path().join(".kuzushi")).ok();
        std::fs::write(
            dir.path().join(".kuzushi/engagement-scope.json"),
            inline_scope().to_string(),
        )
        .unwrap();
        let input = json!({"target": "10.0.0.5", "chainFile": "../../etc/passwd"});
        let err = prepare_chain_run(&input, dir.path()).unwrap_err();
        assert!(err.contains("chainFile"));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_scope_and_chain_do_not_follow_symlinks() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(workspace.path().join(".kuzushi/plays")).unwrap();
        let secret = outside.path().join("secret.json");
        std::fs::write(&secret, inline_chain().to_string()).unwrap();
        symlink(&secret, workspace.path().join(".kuzushi/plays/probe.json")).unwrap();

        let input = json!({
            "target": "10.0.0.5",
            "scope": inline_scope(),
            "chainFile": "probe"
        });
        let error = prepare_chain_run(&input, workspace.path()).unwrap_err();

        assert!(error.contains("chain spec"));
    }
}
