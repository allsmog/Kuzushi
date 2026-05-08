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
