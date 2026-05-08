/// Logical role assigned to an agent call. Each role maps to one
/// [`ModelRoute`] in `models.toml`.
///
/// Adding a new role requires:
///   1. Add the variant here.
///   2. Add a `[roles.<snake_case>]` example in the docs above.
///   3. Update [`AgentRole::as_key`] / [`AgentRole::from_key`].

/// Loaded routing table.

/// Wraps an existing [`AgentRuntime`] and substitutes the model based on
/// the agent role. Implements `AgentRuntime` itself so legacy callers see
/// a transparent passthrough.
mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
mod new;
mod query_blocking;
#[cfg(test)]
mod tests;

pub use items_1::AgentRole;
pub use items_2::AgentRouter;
pub use items_2::ModelRoute;
pub use items_3::RoutedRuntime;
