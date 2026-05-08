use anyhow::Result;
use async_trait::async_trait;
use kuzushi_mcp_common::tool::ToolHandler;
use serde_json::{json, Value};

use super::arguments::{ensure_clangd, FileRequest, PositionRequest};
use super::document::open_document;
use super::tool_types::{DiagnosticsTool, MacroExpandTool, SemanticTokensTool};

#[async_trait]
impl ToolHandler for MacroExpandTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = PositionRequest::from_args(&args)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file.file).await?;
        let hover = client
            .request("textDocument/hover", request.params())
            .await?;
        let expansion = extract_first_code_fence(&hover);
        Ok(json!({ "hover": hover, "expansion": expansion }))
    }
}

#[async_trait]
impl ToolHandler for SemanticTokensTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = FileRequest::from_args(&args)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file).await?;
        let raw = client
            .request("textDocument/semanticTokens/full", request.text_document())
            .await?;
        Ok(json!({ "tokens": raw }))
    }
}

#[async_trait]
impl ToolHandler for DiagnosticsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = FileRequest::from_args(&args)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file).await?;
        let raw = client
            .request("textDocument/diagnostic", request.text_document())
            .await?;
        Ok(json!({ "diagnostics": raw }))
    }
}

pub(crate) fn extract_first_code_fence(hover: &Value) -> Option<String> {
    let value = hover
        .get("contents")
        .and_then(|c| c.get("value"))
        .or_else(|| hover.get("contents"))
        .and_then(Value::as_str)?;
    let mut lines = value.lines();
    while let Some(line) = lines.next() {
        if line.trim_start().starts_with("```") {
            let mut body = Vec::new();
            for inner in lines.by_ref() {
                if inner.trim_start().starts_with("```") {
                    return Some(body.join("\n"));
                }
                body.push(inner.to_string());
            }
        }
    }
    None
}
