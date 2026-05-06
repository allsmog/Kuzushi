//! Shared scaffolding for Kuzushi's local MCP servers (joern, clang AST, gtags).
//!
//! Each backend crate uses [`server::serve_stdio`] with a [`tool::ToolRegistry`]
//! to expose JSON-RPC 2.0 over stdio (newline-delimited JSON, per the MCP
//! stdio transport). Shared schemas in [`schema`] keep query results
//! interchangeable across backends so the [`kuzushi-codeindex`] facade can
//! route queries without per-backend leakage.

pub mod cache;
pub mod doctor;
pub mod jsonrpc;
pub mod schema;
pub mod server;
pub mod tool;

pub use cache::{index_root, manifest_path, repo_hash, RepoFingerprint};
pub use doctor::{which, BinaryProbe};
pub use jsonrpc::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, ERROR_INTERNAL, ERROR_INVALID_PARAMS,
    ERROR_INVALID_REQUEST, ERROR_METHOD_NOT_FOUND, ERROR_PARSE,
};
pub use schema::{
    EdgeKind, FileSpan, Method, Path as PathResult, Position, Range, Symbol, SymbolKind,
};
pub use server::{serve_stdio, ServerInfo};
pub use tool::{Tool, ToolHandler, ToolRegistry};
