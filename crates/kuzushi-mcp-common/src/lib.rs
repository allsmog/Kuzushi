//! Shared scaffolding for Kuzushi's local MCP servers (joern, clang AST, gtags).
//!
//! Each backend crate uses [`server::serve_stdio`] with a [`tool::ToolRegistry`]
//! to expose JSON-RPC 2.0 over stdio (newline-delimited JSON, per the MCP
//! stdio transport). Shared schemas in [`schema`] keep query results
//! interchangeable across backends so the [`kuzushi-codeindex`] facade can
//! route queries without per-backend leakage.

include!("__lib_impl.inc");
