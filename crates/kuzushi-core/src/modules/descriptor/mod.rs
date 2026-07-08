use super::*;

pub(in crate::modules) use max_findings_option::*;
pub(in crate::modules) use mcp_options::*;
pub(in crate::modules) use metadata::*;
mod descriptor_model;
mod max_findings_option;
mod mcp_options;
mod metadata;
mod tool_phase;
use serde::{Deserialize, Serialize};
#[cfg(test)]
mod tests;
pub use descriptor_model::{
    DagNodeDescriptor, ModuleKind, ModuleMetadata, OptionSpec, OptionType, RuntimeRequirement,
    ToolDescriptor,
};
pub use metadata::BuiltinModule;
pub use tool_phase::{canonical_tool_phase, ToolPhase};
