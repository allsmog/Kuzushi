/// Top-level facade. Holds at most one running MCP client per backend.

/// Convenience input for the position-aware facade methods. Accepts a
/// repo path + file (relative to the repo) + 1-based line/column.
pub mod client;
pub mod router;

mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod indexfacade;
mod items_2;
mod new;
#[cfg(test)]
mod tests;

pub use client::{ClientError, McpClient};
pub use indexfacade::IndexFacade;
pub use items_2::FilePosition;
pub use router::{Backend, BackendCapability, Query, RoutingTable};
