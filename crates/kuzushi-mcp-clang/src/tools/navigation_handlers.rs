use anyhow::Result;
use async_trait::async_trait;
use kuzushi_mcp_common::schema::{Position, Range};
use kuzushi_mcp_common::tool::ToolHandler;
use serde_json::{json, Value};
use std::path::PathBuf;

use crate::clangd::parse_locations;

use super::arguments::{ensure_clangd, PositionRequest};
use super::document::open_document;
use super::tool_types::{DefinitionTool, ReferencesTool};

#[async_trait]
impl ToolHandler for DefinitionTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = PositionRequest::from_args(&args, &self.handle)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file.file, &request.file.source_text).await?;
        let raw = client
            .request("textDocument/definition", request.params()?)
            .await?;
        Ok(json!({ "locations": position_locations(&raw) }))
    }
}

#[async_trait]
impl ToolHandler for ReferencesTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = PositionRequest::from_args(&args, &self.handle)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file.file, &request.file.source_text).await?;
        let mut params = request.params()?;
        params["context"] = json!({ "includeDeclaration": true });
        let raw = client.request("textDocument/references", params).await?;
        Ok(json!({ "locations": range_locations(&raw) }))
    }
}

pub(crate) fn position_locations(raw: &Value) -> Vec<Position> {
    parse_locations(raw)
        .into_iter()
        .map(|(p, l, c)| Position::new(PathBuf::from(p), l).with_column(c))
        .collect()
}

pub(crate) fn range_locations(raw: &Value) -> Vec<Range> {
    parse_locations(raw)
        .into_iter()
        .map(|(p, l, c)| Range {
            start: Position::new(PathBuf::from(&p), l).with_column(c),
            end: Position::new(PathBuf::from(p), l).with_column(c),
        })
        .collect()
}
