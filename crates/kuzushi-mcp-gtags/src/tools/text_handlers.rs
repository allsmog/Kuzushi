use anyhow::Result;
use async_trait::async_trait;
use kuzushi_mcp_common::tool::ToolHandler;
use serde_json::{json, Value};
use std::path::PathBuf;

use super::arguments::{optional_repo_path, require_string};
use super::global_command::{ensure_binary_available, run_global_lines};
use super::tool_types::{CompletionTool, FilesMatchingTool};

#[async_trait]
impl ToolHandler for FilesMatchingTool {
    async fn call(&self, args: Value) -> Result<Value> {
        files_matching_response(args).await
    }
}

async fn files_matching_response(args: Value) -> Result<Value> {
    let request = global_text_request(&args, "pattern")?;
    let files = run_global_text_lines(&request, "-P", "failed to spawn `global -P`").await?;
    Ok(json!({ "pattern": request.value, "files": files }))
}

#[async_trait]
impl ToolHandler for CompletionTool {
    async fn call(&self, args: Value) -> Result<Value> {
        completion_response(args).await
    }
}

async fn completion_response(args: Value) -> Result<Value> {
    let request = global_text_request(&args, "prefix")?;
    let completions = run_global_text_lines(&request, "-c", "failed to spawn `global -c`").await?;
    Ok(json!({ "prefix": request.value, "completions": completions }))
}

struct GlobalTextRequest {
    repo: PathBuf,
    value: String,
}

fn global_text_request(args: &Value, field: &str) -> Result<GlobalTextRequest> {
    let value = require_string(args, field)?.to_string();
    ensure_binary_available()?;
    Ok(GlobalTextRequest {
        repo: optional_repo_path(args).unwrap_or_else(|| PathBuf::from(".")),
        value,
    })
}

async fn run_global_text_lines(
    request: &GlobalTextRequest,
    flag: &str,
    spawn_error: &str,
) -> Result<Vec<String>> {
    run_global_lines(&request.repo, &[flag, &request.value], spawn_error).await
}
