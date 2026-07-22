use anyhow::Result;
use kuzushi_mcp_common::schema::Symbol;
use serde_json::Value;
use std::path::Path;

use crate::backend_calls::{
    backend_failure_diagnostic, callees_call, callers_call, definition_call, references_call,
    symbol_matches, BackendToolCall,
};
use crate::client::McpClient;
use crate::router::{Backend, Query, RoutingTable};
use crate::FilePosition;

mod backend_routing;
mod clang_queries;
mod construction;
mod cpg_queries;
mod symbol_queries;

#[derive(Default)]
pub struct IndexFacade {
    pub gtags: Option<McpClient>,
    pub clang: Option<McpClient>,
    pub cpg: Option<McpClient>,
    pub(crate) routing: RoutingTable,
    diagnostics: Vec<String>,
}
