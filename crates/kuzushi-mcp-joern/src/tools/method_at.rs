use anyhow::Result;
use async_trait::async_trait;
use kuzushi_mcp_common::tool::ToolHandler;
use serde_json::{json, Value};

use crate::queries;
use crate::server::run_query;

use super::availability::{ensure_joern_available, parse_raw_json_or_string, require_str};
use super::graph_handlers::required_u32;
use super::tool_types::MethodAtTool;

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

pub(crate) async fn method_at_response(args: &Value) -> Result<Value> {
    let request = method_at_request(args)?;
    method_at_query_response(request).await
}

pub(crate) struct MethodAtRequest {
    pub(crate) file: String,
    pub(crate) line: u32,
}

pub(crate) fn method_at_request(args: &Value) -> Result<MethodAtRequest> {
    Ok(MethodAtRequest {
        file: require_str(args, "file")?.to_string(),
        line: method_at_line(args)?,
    })
}

pub(crate) fn method_at_line(args: &Value) -> Result<u32> {
    required_u32(args, "line")
}

pub(crate) async fn method_at_query_response(request: MethodAtRequest) -> Result<Value> {
    let raw = run_query(&queries::method_at(&request.file, request.line)).await?;
    Ok(method_at_json(request, raw))
}

pub(crate) fn method_at_json(request: MethodAtRequest, raw: String) -> Value {
    json!({
        "file": request.file,
        "line": request.line,
        "method": parse_raw_json_or_string(raw),
    })
}
