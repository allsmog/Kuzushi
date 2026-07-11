use super::*;

pub(in crate::modules) use max_findings_option::*;
pub(in crate::modules) use mcp_options::*;
pub(in crate::modules) use metadata::*;
mod descriptor_model;
mod max_findings_option;
mod mcp_options;
mod metadata;
mod tool_policy;
mod tool_phase;
use serde::{Deserialize, Serialize};
#[cfg(test)]
mod tests;
pub use descriptor_model::{
    DagNodeDescriptor, FileReferenceSemantics, ModuleKind, ModuleMetadata, OptionSpec, OptionType,
    PathSemantics, PromptSpec, RuntimeRequirement, ToolDescriptor,
};
pub use metadata::BuiltinModule;
pub use tool_policy::{
    ApprovalPolicy, FindingStoreRequirement, ToolEffect, ToolPolicy, WorkspaceRequirement,
};
pub(in crate::modules) use tool_policy::{
    external_action_policy, read_policy, target_write_policy, tool_policy, workspace_policy,
};
pub use tool_phase::{canonical_tool_phase, ToolPhase};
