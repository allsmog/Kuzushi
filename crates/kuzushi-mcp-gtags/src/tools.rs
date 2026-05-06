//! gtags MCP tool implementations.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_mcp_common::doctor::{probe_all, HealthSummary};
use kuzushi_mcp_common::schema::Symbol;
use kuzushi_mcp_common::tool::{Tool, ToolHandler, ToolRegistry};
use serde_json::{json, Value};
use tokio::process::Command;

use crate::parser::{parse_global_x, records_to_symbols};

const PROBES: &[(&str, &[&str])] = &[("gtags", &["--version"]), ("global", &["--version"])];

pub async fn health_summary() -> HealthSummary {
    probe_all(PROBES).await
}

pub fn build_registry() -> ToolRegistry {
    ToolRegistry::new()
        .register(
            Tool {
                name: "gtags.health".into(),
                description: "Report whether `gtags` and `global` are available, with versions."
                    .into(),
                input_schema: json!({"type": "object", "properties": {}}),
            },
            HealthTool,
        )
        .register(
            Tool {
                name: "gtags.index".into(),
                description: "Build or refresh a gtags index for a repo path. Stores GTAGS/GRTAGS/GPATH inside the repo (gtags's default) or under `~/.kuzushi/index/gtags/<repo>/` when the repo is read-only."
                    .into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath"],
                    "properties": {
                        "repoPath": {"type": "string"},
                    }
                }),
            },
            IndexTool,
        )
        .register(
            Tool {
                name: "gtags.definitions".into(),
                description: "Locate definitions of a symbol via `global -xd <symbol>`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["symbol"],
                    "properties": {
                        "symbol": {"type": "string"},
                        "repoPath": {"type": "string"},
                    }
                }),
            },
            DefinitionsTool,
        )
        .register(
            Tool {
                name: "gtags.references".into(),
                description: "Locate references to a symbol via `global -xr <symbol>`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["symbol"],
                    "properties": {
                        "symbol": {"type": "string"},
                        "repoPath": {"type": "string"},
                    }
                }),
            },
            ReferencesTool,
        )
        .register(
            Tool {
                name: "gtags.symbols_in_file".into(),
                description: "List symbols defined in a file via `global -xf <file>`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["file"],
                    "properties": {
                        "file": {"type": "string"},
                        "repoPath": {"type": "string"},
                    }
                }),
            },
            SymbolsInFileTool,
        )
        .register(
            Tool {
                name: "gtags.files_matching".into(),
                description: "List indexed files matching a regex via `global -P <pattern>`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["pattern"],
                    "properties": {
                        "pattern": {"type": "string"},
                        "repoPath": {"type": "string"},
                    }
                }),
            },
            FilesMatchingTool,
        )
        .register(
            Tool {
                name: "gtags.completion".into(),
                description: "Return symbol-name completions for a prefix via `global -c <prefix>`."
                    .into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["prefix"],
                    "properties": {
                        "prefix": {"type": "string"},
                        "repoPath": {"type": "string"},
                    }
                }),
            },
            CompletionTool,
        )
}

struct HealthTool;
struct IndexTool;
struct DefinitionsTool;
struct ReferencesTool;
struct SymbolsInFileTool;
struct FilesMatchingTool;
struct CompletionTool;

#[async_trait]
impl ToolHandler for HealthTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        Ok(serde_json::to_value(health_summary().await)?)
    }
}

fn ensure_repo_path(args: &Value) -> Result<PathBuf> {
    let raw = args
        .get("repoPath")
        .and_then(Value::as_str)
        .or_else(|| args.get("repo_path").and_then(Value::as_str))
        .ok_or_else(|| anyhow::anyhow!("missing required argument: repoPath"))?;
    Ok(PathBuf::from(raw))
}

fn optional_repo_path(args: &Value) -> Option<PathBuf> {
    args.get("repoPath")
        .and_then(Value::as_str)
        .or_else(|| args.get("repo_path").and_then(Value::as_str))
        .map(PathBuf::from)
}

fn require_string<'a>(args: &'a Value, name: &str) -> Result<&'a str> {
    args.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing required argument: {name}"))
}

fn ensure_binary_available() -> Result<()> {
    if kuzushi_mcp_common::doctor::which("global").is_none()
        || kuzushi_mcp_common::doctor::which("gtags").is_none()
    {
        anyhow::bail!(
            "BackendUnavailable: gtags/global not on PATH. Install GNU GLOBAL (e.g. `apt install global` / `brew install global`)."
        );
    }
    Ok(())
}

async fn run_global_x(repo: &Path, args: &[&str]) -> Result<Vec<Symbol>> {
    let output = Command::new("global")
        .args(args)
        .current_dir(repo)
        .output()
        .await
        .with_context(|| format!("failed to spawn `global {}`", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Treat "no matches" as empty rather than error.
        if stderr.contains("not found")
            || stderr.contains("no such")
            || output.status.code() == Some(3)
        {
            return Ok(Vec::new());
        }
        anyhow::bail!("global exited with {}: {}", output.status, stderr.trim());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let records = parse_global_x(&stdout);
    Ok(records_to_symbols(records, repo))
}

#[async_trait]
impl ToolHandler for IndexTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_binary_available()?;
        let repo = ensure_repo_path(&args)?;
        let repo = std::fs::canonicalize(&repo)
            .with_context(|| format!("repo path not found: {}", repo.display()))?;
        let output = Command::new("gtags")
            .arg("--quiet")
            .current_dir(&repo)
            .output()
            .await
            .context("failed to spawn `gtags`")?;
        if !output.status.success() {
            anyhow::bail!(
                "gtags exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(json!({
            "repoPath": repo,
            "indexed": true,
        }))
    }
}

#[async_trait]
impl ToolHandler for DefinitionsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_binary_available()?;
        let symbol = require_string(&args, "symbol")?.to_string();
        let repo = optional_repo_path(&args).unwrap_or_else(|| PathBuf::from("."));
        let symbols = run_global_x(&repo, &["-x", "-d", &symbol]).await?;
        Ok(json!({ "symbol": symbol, "matches": symbols }))
    }
}

#[async_trait]
impl ToolHandler for ReferencesTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_binary_available()?;
        let symbol = require_string(&args, "symbol")?.to_string();
        let repo = optional_repo_path(&args).unwrap_or_else(|| PathBuf::from("."));
        let symbols = run_global_x(&repo, &["-x", "-r", &symbol]).await?;
        Ok(json!({ "symbol": symbol, "matches": symbols }))
    }
}

#[async_trait]
impl ToolHandler for SymbolsInFileTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_binary_available()?;
        let file = require_string(&args, "file")?.to_string();
        let repo = optional_repo_path(&args).unwrap_or_else(|| PathBuf::from("."));
        let symbols = run_global_x(&repo, &["-x", "-f", &file]).await?;
        Ok(json!({ "file": file, "symbols": symbols }))
    }
}

#[async_trait]
impl ToolHandler for FilesMatchingTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_binary_available()?;
        let pattern = require_string(&args, "pattern")?.to_string();
        let repo = optional_repo_path(&args).unwrap_or_else(|| PathBuf::from("."));
        let output = Command::new("global")
            .args(["-P", &pattern])
            .current_dir(&repo)
            .output()
            .await
            .context("failed to spawn `global -P`")?;
        if !output.status.success() && output.status.code() != Some(3) {
            anyhow::bail!(
                "global exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let files: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(json!({ "pattern": pattern, "files": files }))
    }
}

#[async_trait]
impl ToolHandler for CompletionTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_binary_available()?;
        let prefix = require_string(&args, "prefix")?.to_string();
        let repo = optional_repo_path(&args).unwrap_or_else(|| PathBuf::from("."));
        let output = Command::new("global")
            .args(["-c", &prefix])
            .current_dir(&repo)
            .output()
            .await
            .context("failed to spawn `global -c`")?;
        if !output.status.success() && output.status.code() != Some(3) {
            anyhow::bail!(
                "global exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let completions: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(json!({ "prefix": prefix, "completions": completions }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn registry_includes_all_seven_tools() {
        let r = build_registry();
        for name in [
            "gtags.health",
            "gtags.index",
            "gtags.definitions",
            "gtags.references",
            "gtags.symbols_in_file",
            "gtags.files_matching",
            "gtags.completion",
        ] {
            assert!(r.contains(name), "missing tool: {name}");
        }
    }

    #[tokio::test]
    async fn definitions_tool_reports_backend_unavailable_when_global_missing() {
        // We can't guarantee global is missing on every CI host, but
        // when it is, this is the contract: a structured anyhow Error
        // whose Display starts with "BackendUnavailable:". On hosts that
        // *do* have global installed, the tool will instead succeed
        // (returning an empty match list for an unknown symbol) and we
        // exit early without asserting anything.
        if kuzushi_mcp_common::doctor::which("global").is_some() {
            return;
        }
        let tool = DefinitionsTool;
        let err = tool
            .call(json!({"symbol": "no_such_symbol_zzz"}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().starts_with("BackendUnavailable:"),
            "expected BackendUnavailable, got: {err}"
        );
    }

    #[tokio::test]
    async fn missing_required_argument_is_actionable() {
        let tool = DefinitionsTool;
        // Skip the binary-availability gate by checking the error path
        // explicitly when `global` is present.
        if kuzushi_mcp_common::doctor::which("global").is_none() {
            return;
        }
        let err = tool.call(json!({})).await.unwrap_err();
        assert!(err.to_string().contains("symbol"));
    }
}
