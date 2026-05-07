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

include!("__main_impl.inc");
