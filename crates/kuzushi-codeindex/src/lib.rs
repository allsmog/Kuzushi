/// Top-level facade. Holds at most one running MCP client per backend.

/// Convenience input for the position-aware facade methods. Accepts a
/// repo path + file (relative to the repo) + 1-based line/column.
pub mod client;
pub mod router;

mod backend_calls;
mod index_facade;
#[cfg(test)]
mod tests;

pub use backend_calls::FilePosition;
pub use client::{ClientError, McpClient};
pub use index_facade::IndexFacade;
pub use router::{Backend, BackendCapability, Query, RoutingTable};

#[cfg(test)]
pub(crate) use backend_calls::{callees_call, callers_call, definition_call, symbol_matches};
