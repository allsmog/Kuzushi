use anyhow::Result;
use async_trait::async_trait;
use kuzushi_mcp_common::tool::ToolHandler;
use serde_json::{json, Value};

use crate::clangd::ClangdClient;

use super::arguments::{ensure_clangd, PositionRequest};
use super::document::{open_document, position_arg};
use super::health_handle::ClangdHandle;
use super::tool_types::{CalleesTool, CallersTool};

pub(crate) async fn prepare_call_hierarchy(
    client: &ClangdClient,
    file: &std::path::Path,
    line: u32,
    column: u32,
) -> Result<Value> {
    open_document(client, file).await?;
    client
        .request(
            "textDocument/prepareCallHierarchy",
            position_arg(file, line, column),
        )
        .await
}

#[async_trait]
impl ToolHandler for CallersTool {
    async fn call(&self, args: Value) -> Result<Value> {
        call_hierarchy_response(
            &self.handle,
            &args,
            "callHierarchy/incomingCalls",
            "incomingCalls",
        )
        .await
    }
}

#[async_trait]
impl ToolHandler for CalleesTool {
    async fn call(&self, args: Value) -> Result<Value> {
        call_hierarchy_response(
            &self.handle,
            &args,
            "callHierarchy/outgoingCalls",
            "outgoingCalls",
        )
        .await
    }
}

pub(crate) async fn call_hierarchy_response(
    handle: &ClangdHandle,
    args: &Value,
    method: &str,
    field_name: &str,
) -> Result<Value> {
    let request = checked_call_hierarchy_request(args)?;
    let client = request.client(handle).await?;
    call_hierarchy_response_for_client(&client, &request, method, field_name).await
}

fn checked_call_hierarchy_request(args: &Value) -> Result<PositionRequest> {
    ensure_clangd()?;
    PositionRequest::from_args(args)
}

pub(crate) async fn call_hierarchy_response_for_client(
    client: &ClangdClient,
    request: &PositionRequest,
    method: &str,
    field_name: &str,
) -> Result<Value> {
    let items =
        prepare_call_hierarchy(client, &request.file.file, request.line, request.column).await?;
    Ok(json!({ field_name: collect_call_hierarchy_calls(client, method, &items).await? }))
}

pub(crate) async fn collect_call_hierarchy_calls(
    client: &ClangdClient,
    method: &str,
    items: &Value,
) -> Result<Vec<Value>> {
    let mut calls = Vec::new();
    for item in json_array(items) {
        let response = client.request(method, json!({ "item": item })).await?;
        extend_with_json_array(&mut calls, &response);
    }
    Ok(calls)
}

pub(crate) fn json_array(value: &Value) -> &[Value] {
    value.as_array().map(Vec::as_slice).unwrap_or_default()
}

pub(crate) fn extend_with_json_array(target: &mut Vec<Value>, value: &Value) {
    if let Some(items) = value.as_array() {
        target.extend(items.iter().cloned());
    }
}
