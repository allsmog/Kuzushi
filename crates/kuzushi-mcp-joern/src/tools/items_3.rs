use super::prelude::*;
use super::*;

#[async_trait]
impl ToolHandler for CalleesOfTool {
    async fn call(&self, args: Value) -> Result<Value> {
        callees_of_response(args).await
    }
}

pub(crate) async fn callees_of_response(args: Value) -> Result<Value> {
    ensure_joern_available()?;
    function_query_response(&args, queries::callees_of, "callees").await
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

pub(crate) fn parse_raw_json_or_string(raw: String) -> Value {
    serde_json::from_str(&raw).unwrap_or(Value::String(raw))
}

#[async_trait]
impl ToolHandler for CpgSizeTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let raw = run_query(queries::cpg_size_query()).await?;
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
        Ok(parsed)
    }
}

#[async_trait]
impl ToolHandler for ReachingDefTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let file = require_str(&args, "file")?.to_string();
        let line = args
            .get("line")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("missing required integer argument: line"))?
            as u32;
        let var = require_str(&args, "var")?.to_string();
        let raw = run_query(&queries::reaching_def(&file, line, &var)).await?;
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
        Ok(json!({ "var": var, "file": file, "line": line, "definitions": parsed }))
    }
}

#[async_trait]
impl ToolHandler for TaintPathsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let source = require_str(&args, "source")?.to_string();
        let sink = require_str(&args, "sink")?.to_string();
        let max_paths = args
            .get("maxPaths")
            .or_else(|| args.get("max_paths"))
            .and_then(Value::as_u64)
            .unwrap_or(50) as usize;
        let raw = run_query(&queries::taint_paths(&source, &sink, max_paths)).await?;
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
        Ok(json!({
            "source": source,
            "sink": sink,
            "maxPaths": max_paths,
            "paths": parsed,
        }))
    }
}

#[async_trait]
impl ToolHandler for UnsafeBlocksTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let file = args.get("file").and_then(Value::as_str);
        let raw = run_query(&queries::unsafe_blocks(file)).await?;
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
        Ok(json!({
            "file": file,
            "blocks": parsed,
        }))
    }
}

#[async_trait]
impl ToolHandler for FfiBoundariesTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let raw = run_query(queries::ffi_boundaries()).await?;
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
        Ok(json!({ "boundaries": parsed }))
    }
}

#[async_trait]
impl ToolHandler for MethodAtTool {
    async fn call(&self, args: Value) -> Result<Value> {
        method_at_tool_response(args).await
    }
}

pub(crate) async fn method_at_tool_response(args: Value) -> Result<Value> {
    ensure_joern_available()?;
    method_at_response(&args).await
}
