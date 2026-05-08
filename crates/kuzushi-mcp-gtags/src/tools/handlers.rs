use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_mcp_common::tool::ToolHandler;
use serde_json::{json, Value};
use std::path::PathBuf;

use super::arguments::ensure_repo_path;
use super::global_command::{ensure_binary_available, run_gtags};
use super::health::health_summary;
use super::tool_types::{HealthTool, IndexTool};

#[async_trait]
impl ToolHandler for HealthTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        Ok(serde_json::to_value(health_summary().await)?)
    }
}

#[async_trait]
impl ToolHandler for IndexTool {
    async fn call(&self, args: Value) -> Result<Value> {
        index_response(args).await
    }
}

async fn index_response(args: Value) -> Result<Value> {
    let repo = canonical_index_repo(&args)?;
    run_gtags(&repo).await?;
    Ok(indexed_repo_response(repo))
}

fn canonical_index_repo(args: &Value) -> Result<PathBuf> {
    let repo = ensure_repo_path(args)?;
    ensure_binary_available()?;
    canonical_repo_path(&repo)
}

fn canonical_repo_path(repo: &std::path::Path) -> Result<PathBuf> {
    std::fs::canonicalize(repo).with_context(|| format!("repo path not found: {}", repo.display()))
}

fn indexed_repo_response(repo: PathBuf) -> Value {
    json!({
        "repoPath": repo,
        "indexed": true,
    })
}
