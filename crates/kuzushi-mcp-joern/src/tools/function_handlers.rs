use anyhow::Result;
use async_trait::async_trait;
use kuzushi_mcp_common::tool::ToolHandler;
use serde_json::Value;

use crate::queries;

use super::availability::ensure_joern_available;
use super::parse_query_handlers::function_query_response;
use super::tool_types::CalleesOfTool;

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
