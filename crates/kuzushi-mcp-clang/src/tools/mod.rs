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
mod items_5;
/// One process-wide cached clangd connection per repo. Hand-built because
/// we don't want to require a shared async-runtime context across tool
/// callers; tools acquire+lock the connection per call.

/// Kept for any future stub we register before wiring; unused now that
/// all 11 planned tools are live.

/// Run `textDocument/prepareCallHierarchy` to get a CallHierarchyItem at
/// the given position; clangd needs this handle before answering
/// `incomingCalls` / `outgoingCalls`.

/// Pull the first ```...``` code-fence body out of a clangd hover
/// markdown response. Used by `clang.macro_expand` to expose the
/// expanded macro text directly without forcing the caller to parse
/// markdown.

#[cfg(test)]
mod tests;
pub use crate::clangd::ClangdClient;
pub use build_registry::build_registry;
pub use items_1::health_summary;
