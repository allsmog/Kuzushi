use anyhow::Result;
use async_trait::async_trait;
use kuzushi_mcp_common::tool::ToolHandler;
use serde_json::{json, Value};

use crate::queries;
use crate::server::run_query;

use super::availability::{ensure_joern_available, parse_raw_json_or_string, require_str};
use super::tool_types::{
    CpgSizeTool, FfiBoundariesTool, ReachingDefTool, TaintPathsTool, UnsafeBlocksTool,
};

#[async_trait]
impl ToolHandler for CpgSizeTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let raw = run_query(queries::cpg_size_query()).await?;
        Ok(parse_raw_json_or_string(raw))
    }
}

#[async_trait]
impl ToolHandler for ReachingDefTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let request = reaching_def_request(&args)?;
        let raw = run_query(&queries::reaching_def(
            &request.file,
            request.line,
            &request.var,
        ))
        .await?;
        Ok(json!({
            "var": request.var,
            "file": request.file,
            "line": request.line,
            "definitions": parse_raw_json_or_string(raw),
        }))
    }
}

struct ReachingDefRequest {
    file: String,
    line: u32,
    var: String,
}

fn reaching_def_request(args: &Value) -> Result<ReachingDefRequest> {
    Ok(ReachingDefRequest {
        file: require_str(args, "file")?.to_string(),
        line: required_u32(args, "line")?,
        var: require_str(args, "var")?.to_string(),
    })
}

#[async_trait]
impl ToolHandler for TaintPathsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let source = require_str(&args, "source")?.to_string();
        let sink = require_str(&args, "sink")?.to_string();
        let max_paths = optional_max_paths(&args);
        let raw = run_query(&queries::taint_paths(&source, &sink, max_paths)).await?;
        Ok(json!({
            "source": source,
            "sink": sink,
            "maxPaths": max_paths,
            "paths": parse_raw_json_or_string(raw),
        }))
    }
}

fn optional_max_paths(args: &Value) -> usize {
    args.get("maxPaths")
        .or_else(|| args.get("max_paths"))
        .and_then(Value::as_u64)
        .unwrap_or(50) as usize
}

#[async_trait]
impl ToolHandler for UnsafeBlocksTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let file = args.get("file").and_then(Value::as_str);
        let raw = run_query(&queries::unsafe_blocks(file)).await?;
        Ok(json!({ "file": file, "blocks": parse_raw_json_or_string(raw) }))
    }
}

#[async_trait]
impl ToolHandler for FfiBoundariesTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let raw = run_query(queries::ffi_boundaries()).await?;
        Ok(json!({ "boundaries": parse_raw_json_or_string(raw) }))
    }
}

pub(crate) fn required_u32(args: &Value, name: &str) -> Result<u32> {
    let value = args
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("missing required integer argument: {name}"))?;
    Ok(value as u32)
}
