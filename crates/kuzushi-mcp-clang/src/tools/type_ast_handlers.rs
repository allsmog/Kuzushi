use anyhow::Result;
use async_trait::async_trait;
use kuzushi_mcp_common::tool::ToolHandler;
use serde_json::{json, Value};

use super::arguments::{ensure_clangd, PositionRequest};
use super::document::open_document;
use super::tool_types::{AstTool, TypeAtTool};

#[async_trait]
impl ToolHandler for TypeAtTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = PositionRequest::from_args(&args, &self.handle)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file.file, &request.file.source_text).await?;
        let raw = client
            .request("textDocument/hover", request.params()?)
            .await?;
        Ok(json!({ "hover": raw }))
    }
}

#[async_trait]
impl ToolHandler for AstTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = PositionRequest::from_args_with_default_column(&args, 1, &self.handle)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file.file, &request.file.source_text).await?;
        let raw = client
            .request("textDocument/ast", request.params()?)
            .await?;
        Ok(json!({ "ast": raw }))
    }
}
