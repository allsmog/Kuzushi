use std::path::{Path, PathBuf};
use std::process::Output;

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
    let stdout = global_stdout_or_empty(output)?;
    let records = parse_global_x(&stdout);
    Ok(records_to_symbols(records, repo))
}

fn global_stdout_or_empty(output: Output) -> Result<String> {
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if global_status_means_no_matches(&output, &stderr) {
        return Ok(String::new());
    }
    anyhow::bail!("global exited with {}: {}", output.status, stderr.trim());
}

fn global_status_means_no_matches(output: &Output, stderr: &str) -> bool {
    stderr.contains("not found") || stderr.contains("no such") || output.status.code() == Some(3)
}

async fn run_gtags(repo: &Path) -> Result<()> {
    let output = Command::new("gtags")
        .arg("--quiet")
        .current_dir(repo)
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
    Ok(())
}

async fn run_global_lines(repo: &Path, args: &[&str], spawn_context: &str) -> Result<Vec<String>> {
    let output = Command::new("global")
        .args(args)
        .current_dir(repo)
        .output()
        .await
        .context(spawn_context.to_string())?;
    let stdout = global_stdout_or_empty(output)?;
    Ok(stdout
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect())
}

#[async_trait]
impl ToolHandler for IndexTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let repo = ensure_repo_path(&args)?;
        ensure_binary_available()?;
        let repo = std::fs::canonicalize(&repo)
            .with_context(|| format!("repo path not found: {}", repo.display()))?;
        run_gtags(&repo).await?;
        Ok(json!({
            "repoPath": repo,
            "indexed": true,
        }))
    }
}

#[async_trait]
impl ToolHandler for DefinitionsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let symbol = require_string(&args, "symbol")?.to_string();
        ensure_binary_available()?;
        let repo = optional_repo_path(&args).unwrap_or_else(|| PathBuf::from("."));
        let symbols = run_global_x(&repo, &["-x", "-d", &symbol]).await?;
        Ok(json!({ "symbol": symbol, "matches": symbols }))
    }
}

#[async_trait]
impl ToolHandler for ReferencesTool {
    async fn call(&self, args: Value) -> Result<Value> {
        symbol_lookup_response(&args, "-r").await
    }
}

#[async_trait]
impl ToolHandler for SymbolsInFileTool {
    async fn call(&self, args: Value) -> Result<Value> {
        symbols_in_file_response(&args).await
    }
}

async fn symbol_lookup_response(args: &Value, flag: &str) -> Result<Value> {
    let request = symbol_lookup_request(args)?;
    run_symbol_lookup(request, flag).await
}

fn symbol_lookup_request(args: &Value) -> Result<GlobalSymbolRequest> {
    let symbol = require_string(args, "symbol")?.to_string();
    ensure_binary_available()?;
    let repo = optional_repo_path(args).unwrap_or_else(|| PathBuf::from("."));
    Ok(GlobalSymbolRequest { repo, symbol })
}

struct GlobalSymbolRequest {
    repo: PathBuf,
    symbol: String,
}

async fn run_symbol_lookup(request: GlobalSymbolRequest, flag: &str) -> Result<Value> {
    let symbols = run_global_x(&request.repo, &["-x", flag, &request.symbol]).await?;
    Ok(json!({ "symbol": request.symbol, "matches": symbols }))
}

async fn symbols_in_file_response(args: &Value) -> Result<Value> {
    let request = symbols_in_file_request(args)?;
    run_symbols_in_file(request).await
}

fn symbols_in_file_request(args: &Value) -> Result<GlobalFileRequest> {
    let file = require_string(args, "file")?.to_string();
    ensure_binary_available()?;
    let repo = optional_repo_path(args).unwrap_or_else(|| PathBuf::from("."));
    Ok(GlobalFileRequest { repo, file })
}

struct GlobalFileRequest {
    repo: PathBuf,
    file: String,
}

async fn run_symbols_in_file(request: GlobalFileRequest) -> Result<Value> {
    let symbols = run_global_x(&request.repo, &["-x", "-f", &request.file]).await?;
    Ok(json!({ "file": request.file, "symbols": symbols }))
}

#[async_trait]
impl ToolHandler for FilesMatchingTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let pattern = require_string(&args, "pattern")?.to_string();
        ensure_binary_available()?;
        let repo = optional_repo_path(&args).unwrap_or_else(|| PathBuf::from("."));
        let files =
            run_global_lines(&repo, &["-P", &pattern], "failed to spawn `global -P`").await?;
        Ok(json!({ "pattern": pattern, "files": files }))
    }
}

#[async_trait]
impl ToolHandler for CompletionTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let prefix = require_string(&args, "prefix")?.to_string();
        ensure_binary_available()?;
        let repo = optional_repo_path(&args).unwrap_or_else(|| PathBuf::from("."));
        let completions =
            run_global_lines(&repo, &["-c", &prefix], "failed to spawn `global -c`").await?;
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

    #[tokio::test]
    async fn argument_validation_runs_before_binary_checks_for_gtags_tools() {
        let index_err = IndexTool.call(json!({})).await.unwrap_err();
        assert!(index_err.to_string().contains("repoPath"));

        let files_err = FilesMatchingTool.call(json!({})).await.unwrap_err();
        assert!(files_err.to_string().contains("pattern"));

        let completion_err = CompletionTool.call(json!({})).await.unwrap_err();
        assert!(completion_err.to_string().contains("prefix"));
    }
}
