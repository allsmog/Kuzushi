use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_mcp_common::tool::ToolHandler;
use serde_json::Value;
use std::path::Path;

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
        compile_commands_response(self, &args).await
    }
}

pub(crate) async fn compile_commands_response(
    tool: &CompileCommandsTool,
    args: &Value,
) -> Result<Value> {
    validate_compile_arguments(args)?;
    let repo = tool
        .read_capability
        .authorize_directory(Path::new(require_str(args, "repoPath")?))?;
    if let Some(selected) = compile_db::selected_snapshot(args, &repo, &tool.read_capability)? {
        let receipt = selected.receipt();
        let mut result = serde_json::to_value(compile_db::CompileDb {
            path: receipt.source_path.clone(),
            generator: compile_db::Generator::PreExisting,
            entries: receipt.entries,
        })?;
        result["configuration"] = serde_json::to_value(receipt)?;
        return Ok(result);
    }
    let database = compile_db::resolve(&repo).await?;
    Ok(serde_json::to_value(database)?)
}

fn validate_compile_arguments(args: &Value) -> Result<()> {
    let object = args
        .as_object()
        .context("clang.compile_commands arguments must be an object")?;
    if let Some(name) = object
        .keys()
        .find(|name| !matches!(name.as_str(), "repoPath" | "compileCommandsPath"))
    {
        anyhow::bail!("unknown clang.compile_commands argument: {name}");
    }
    Ok(())
}
