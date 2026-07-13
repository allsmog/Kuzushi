use anyhow::Result;
use async_trait::async_trait;
use kuzushi_mcp_common::tool::ToolHandler;
use serde_json::{json, Value};

use crate::queries;
use crate::server::{parse_repo, run_query};

use super::availability::{ensure_joern_available, parse_raw_json_or_string, require_str};
use super::health::extended_health;
use super::tool_types::{CallersOfTool, DefinitionsTool, HealthTool, ParseTool};

#[async_trait]
impl ToolHandler for HealthTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        Ok(extended_health().await)
    }
}

#[async_trait]
impl ToolHandler for ParseTool {
    async fn call(&self, args: Value) -> Result<Value> {
        parse_tool_response(&self.read_capability, args).await
    }
}

pub(crate) async fn parse_tool_response(
    read_capability: &kuzushi_mcp_common::ReadRootCapability,
    args: Value,
) -> Result<Value> {
    let repo = parse_repo_path(read_capability, &args)?;
    ensure_joern_available()?;
    parse_repo_handle_value(&repo).await
}

pub(crate) fn parse_repo_path(
    read_capability: &kuzushi_mcp_common::ReadRootCapability,
    args: &Value,
) -> Result<std::path::PathBuf> {
    read_capability.resolve(std::path::Path::new(require_str(args, "repoPath")?))
}

pub(crate) async fn parse_repo_handle_value(repo: &std::path::Path) -> Result<Value> {
    let handle = parse_repo(repo).await?;
    Ok(serde_json::to_value(handle)?)
}

#[async_trait]
impl ToolHandler for CallersOfTool {
    async fn call(&self, args: Value) -> Result<Value> {
        callers_of_response(args).await
    }
}

#[async_trait]
impl ToolHandler for DefinitionsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_joern_available()?;
        function_query_response(&args, queries::definitions, "matches").await
    }
}

pub(crate) async fn callers_of_response(args: Value) -> Result<Value> {
    ensure_joern_available()?;
    function_query_response(&args, queries::callers_of, "callers").await
}

pub(crate) async fn function_query_response(
    args: &Value,
    query: fn(&str) -> String,
    field_name: &str,
) -> Result<Value> {
    let fn_name = require_str(args, "fn")?.to_string();
    let raw = run_query(&query(&fn_name)).await?;
    Ok(function_query_json(fn_name, field_name, raw))
}

pub(crate) fn function_query_json(fn_name: String, field_name: &str, raw: String) -> Value {
    let mut response = json!({ "fn": fn_name });
    response[field_name] = parse_raw_json_or_string(raw);
    response
}
