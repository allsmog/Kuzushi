mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
/// Server identification reported in `initialize` response.

/// Run the MCP server loop on stdio until EOF. Blocks until stdin closes.

/// Loop driver factored out for testing — accepts any `AsyncRead`/`AsyncWrite`.

/// Process a single request line. Returns `None` for notifications (which
/// must not produce a response per JSON-RPC 2.0).

/// Build a JSON-RPC error response with no id (e.g. for top-level fatal
/// errors that aren't tied to a specific request).

#[cfg(test)]
mod tests;

pub use items_1::serve_stdio;
pub use items_1::serve_streams;
pub use items_1::ServerInfo;
pub use items_2::unbound_error;
