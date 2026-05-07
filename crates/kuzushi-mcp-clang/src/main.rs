//! `kuzushi-mcp-clang` — MCP server bridging clangd LSP.
//!
//! When clangd is missing from PATH, every tool returns a structured
//! `BackendUnavailable` error and `health` reports `ready: false`.

include!("__main_impl.inc");
