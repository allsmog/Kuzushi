use anyhow::Result;
use async_trait::async_trait;
use kuzushi_mcp_common::tool::ToolHandler;
use serde_json::Value;
use std::path::PathBuf;

use crate::compile_db;

use super::arguments::require_str;
use super::health_handle::health_summary;
use super::tool_types::{CompileCommandsTool, HealthTool};

#[async_trait]
impl ToolHandler for HealthTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        Ok(serde_json::to_value(health_summary().await)?)
    }
}

#[async_trait]
impl ToolHandler for CompileCommandsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        compile_commands_response(&args).await
    }
}

pub(crate) async fn compile_commands_response(args: &Value) -> Result<Value> {
    Ok(serde_json::to_value(resolve_compile_commands(args).await?)?)
}

async fn resolve_compile_commands(args: &Value) -> Result<compile_db::CompileDb> {
    let repo = compile_commands_repo(args)?;
    compile_db::resolve(&repo).await
}

pub(crate) fn compile_commands_repo(args: &Value) -> Result<PathBuf> {
    Ok(PathBuf::from(require_str(args, "repoPath")?))
}
