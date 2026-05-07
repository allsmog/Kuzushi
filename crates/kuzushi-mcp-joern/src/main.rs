//! `kuzushi-mcp-joern` — MCP server fronting joern's CPG.
//!
//! Joern's heavy-but-rich Code Property Graph (AST + CFG + DDG) backs the
//! `joern.*` tool family. This server shells out to `joern-parse` to build
//! a CPG once per repo, persists the result under `~/.kuzushi/index/joern/`,
//! and answers queries by speaking to a `joern --server` HTTP endpoint.
//!
//! When joern is missing from PATH, every query returns
//! `BackendUnavailable` and `health` reports `ready: false`.

include!("__main_impl.inc");
