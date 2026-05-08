/// Build a [`ToolBox`] populated with handlers for the four code-nav
/// tools, all rooted at `cfg.root`. Failures from individual tool calls
/// are surfaced as `is_error: true` results, never panics.
use super::file_io::{read_source, ReadSourceInput};
use super::ripgrep::{find_references, FindReferencesInput};
use super::symbol_index::{
    list_definitions, read_definition, ListDefinitionsInput, ReadDefinitionInput,
};
use crate::runtime::{AgentTool, ToolBox, ToolCall, ToolResult};
use anyhow::Result;
pub(in crate::code_nav) use handle_read_definition::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
mod handle_read_definition;
mod name;
mod read_definition_tool;
#[cfg(test)]
mod tests;

pub use name::find_references_tool;
pub use name::list_definitions_tool;
pub use name::read_source_tool;
pub use name::CodeNavConfig;
pub use name::CodeNavTool;
pub use read_definition_tool::code_nav_tool_specs;
pub use read_definition_tool::code_nav_toolbox;
pub use read_definition_tool::read_definition_tool;
