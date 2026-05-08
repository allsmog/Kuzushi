use anyhow::Result;
use async_trait::async_trait;
use kuzushi_mcp_common::tool::ToolHandler;
use serde_json::Value;

use super::tool_types::NotYetImplemented;

#[async_trait]
impl ToolHandler for NotYetImplemented {
    async fn call(&self, _args: Value) -> Result<Value> {
        anyhow::bail!(
            "NotYetImplemented: tool `{}` is part of the planned clang MCP surface but is not yet wired.",
            self.0
        )
    }
}
