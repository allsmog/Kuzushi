/// Build a [`ToolBox`] populated with handlers for the four code-nav
/// tools, all rooted at `cfg.root`. Failures from individual tool calls
/// are surfaced as `is_error: true` results, never panics.
mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
#[cfg(test)]
mod tests;

pub use items_1::find_references_tool;
pub use items_1::list_definitions_tool;
pub use items_1::read_source_tool;
pub use items_1::CodeNavConfig;
pub use items_1::CodeNavTool;
pub use items_2::code_nav_tool_specs;
pub use items_2::code_nav_toolbox;
pub use items_2::read_definition_tool;
