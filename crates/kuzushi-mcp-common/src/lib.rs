mod bundle_identity;
pub mod cache;
mod codeql_bundle_root;
pub mod doctor;
pub mod jsonrpc;
pub mod process;
mod read_capability;
pub mod read_only_sandbox;
pub mod schema;
pub mod server;
pub mod standalone_health;
pub mod tool;

pub use bundle_identity::{bounded_bundle_identity, copy_bounded_bundle, BundleIdentityConfig};
pub use cache::{index_root, manifest_path, repo_hash, RepoFingerprint};
pub use codeql_bundle_root::resolve_codeql_bundle_root;
pub use doctor::{which, BinaryProbe};
pub use jsonrpc::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, ERROR_INTERNAL, ERROR_INVALID_PARAMS,
    ERROR_INVALID_REQUEST, ERROR_METHOD_NOT_FOUND, ERROR_PARSE,
};
pub use read_capability::{
    AuthorizedDirectory, BoundedReadFile, ReadFileIdentity, ReadRootCapability, MCP_READ_ROOTS_ENV,
};
pub use schema::{
    EdgeKind, FileSpan, Method, Path as PathResult, Position, Range, Symbol, SymbolKind,
};
pub use server::{serve_stdio, ServerInfo};
pub use standalone_health::exit_after_standalone_health_if_requested;
pub use tool::{Tool, ToolHandler, ToolRegistry};
