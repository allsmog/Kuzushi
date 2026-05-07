//! Unified code-index facade.
//!
//! Other Kuzushi modules call into this crate without caring which MCP
//! backend (joern, clang, gtags) actually answered the query. The facade:
//!
//! 1. Spawns each MCP server as a child process on demand.
//! 2. Speaks JSON-RPC client to it over stdio.
//! 3. Routes high-level queries to the best-available backend per the
//!    routing table in [`router`].
//! 4. Exposes a single [`IndexFacade`] surface so consumers (systems-hunt,
//!    future verify, future taint) stay backend-agnostic.

include!("__lib_impl.inc");
