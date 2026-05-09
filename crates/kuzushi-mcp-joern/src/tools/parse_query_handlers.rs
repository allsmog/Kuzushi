use anyhow::Result;
use async_trait::async_trait;
use kuzushi_mcp_common::tool::ToolHandler;
use serde_json::{json, Value};

use crate::queries;
use crate::server::{parse_repo, run_query};

use super::availability::{ensure_joern_available, parse_raw_json_or_string, require_str};
use super::health::extended_health;
use super::tool_types::{CallersOfTool, HealthTool, ParseTool, QueryTool};

#[async_trait]
impl ToolHandler for HealthTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        Ok(extended_health().await)
    }
}

#[async_trait]
impl ToolHandler for ParseTool {
    async fn call(&self, args: Value) -> Result<Value> {
        parse_tool_response(args).await
    }
}

pub(crate) async fn parse_tool_response(args: Value) -> Result<Value> {
    ensure_joern_available()?;
    parse_repo_response(&args).await
}

pub(crate) async fn parse_repo_response(args: &Value) -> Result<Value> {
    let repo = parse_repo_path(args)?;
    parse_repo_handle_value(&repo).await
}

pub(crate) fn parse_repo_path(args: &Value) -> Result<std::path::PathBuf> {
    Ok(std::path::PathBuf::from(require_str(args, "repoPath")?))
}

pub(crate) async fn parse_repo_handle_value(repo: &std::path::Path) -> Result<Value> {
    let handle = parse_repo(repo).await?;
    Ok(serde_json::to_value(handle)?)
}

#[async_trait]
impl ToolHandler for QueryTool {
    async fn call(&self, args: Value) -> Result<Value> {
        query_tool_response(args).await
    }
}

pub(crate) async fn query_tool_response(args: Value) -> Result<Value> {
    ensure_joern_available()?;
    query_response(&args).await
}

pub(crate) async fn query_response(args: &Value) -> Result<Value> {
    let scala = require_str(args, "scala")?.to_string();
    let raw = run_query(&scala).await?;
    Ok(json!({ "result": parse_raw_json_or_string(raw) }))
}

#[async_trait]
impl ToolHandler for CallersOfTool {
    async fn call(&self, args: Value) -> Result<Value> {
        callers_of_response(args).await
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
