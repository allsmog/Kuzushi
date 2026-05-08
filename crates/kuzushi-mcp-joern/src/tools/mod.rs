use super::prelude::*;
use super::*;

mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod build_registry;
mod items_1;
mod items_2;
mod items_3;
mod items_4;
/// Build a placeholder descriptor used by tools that don't have their
/// implementation wired yet. Currently unused (all five planned tools
/// are now live) but kept as a reusable helper for the next round of
/// additions.

/// Sentinel handler kept for any future stubs we register before
/// implementing. No tool is currently registered as a stub.

#[cfg(test)]
mod tests;
pub use build_registry::build_registry;
pub use items_1::health_summary;
