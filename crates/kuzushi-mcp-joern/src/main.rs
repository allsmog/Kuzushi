//! `kuzushi-mcp-joern` — MCP server fronting joern's CPG.
//!
//! Joern's heavy-but-rich Code Property Graph (AST + CFG + DDG) backs the
//! `joern.*` tool family. This server shells out to `joern-parse` to build
//! a CPG once per repo, persists the result under `~/.kuzushi/index/joern/`,
//! and answers queries by speaking to a `joern --server` HTTP endpoint.
//!
//! When joern is missing from PATH, every query returns
//! `BackendUnavailable` and `health` reports `ready: false`.

use std::env;

use anyhow::Result;
use kuzushi_mcp_common::{serve_stdio, ServerInfo};

mod queries;
mod server;
mod tools;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    if env::args().any(|a| a == "--health") {
        let summary = tools::health_summary().await;
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }

    let info = ServerInfo::new("kuzushi-mcp-joern", PKG_VERSION);
    let registry = tools::build_registry();
    serve_stdio(info, registry).await
}
