use anyhow::Result;
use serde_json::Value;
use std::path::PathBuf;

pub(crate) fn ensure_repo_path(args: &Value) -> Result<PathBuf> {
    let raw = args
        .get("repoPath")
        .and_then(Value::as_str)
        .or_else(|| args.get("repo_path").and_then(Value::as_str))
        .ok_or_else(|| anyhow::anyhow!("missing required argument: repoPath"))?;
    Ok(PathBuf::from(raw))
}

pub(crate) fn optional_repo_path(args: &Value) -> Option<PathBuf> {
    args.get("repoPath")
        .and_then(Value::as_str)
        .or_else(|| args.get("repo_path").and_then(Value::as_str))
        .map(PathBuf::from)
}

pub(crate) fn require_string<'a>(args: &'a Value, name: &str) -> Result<&'a str> {
    args.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing required argument: {name}"))
}
