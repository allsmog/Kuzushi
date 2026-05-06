//! `kuzushi-mcp-gtags` — local MCP server backed by GNU GLOBAL.
//!
//! Exposes seven tools (`health`, `index`, `definitions`, `references`,
//! `symbols_in_file`, `files_matching`, `completion`) over JSON-RPC stdio.
//! When the `gtags`/`global` binaries aren't installed, every query returns
//! a structured `BackendUnavailable` error and `health` reports
//! `ready: false` — never panics.
//!
//! Run with `--health` to short-circuit the MCP loop and print a JSON
//! health summary, useful for `kuzushi doctor` integration.

use std::env;

use anyhow::Result;
use kuzushi_mcp_common::{serve_stdio, ServerInfo};

mod parser;
mod tools;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    if env::args().any(|a| a == "--health") {
        let summary = tools::health_summary().await;
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }

    let info = ServerInfo::new("kuzushi-mcp-gtags", PKG_VERSION);
    let registry = tools::build_registry();
    serve_stdio(info, registry).await
}
