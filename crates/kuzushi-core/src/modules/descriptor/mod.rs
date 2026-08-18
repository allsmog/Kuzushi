use super::*;

pub(in crate::modules) use max_findings_option::*;
pub(in crate::modules) use mcp_options::*;
pub(in crate::modules) use metadata::*;
pub(in crate::modules) use descriptor_validation::validate_prompt_options;
mod descriptor_validation;
mod max_findings_option;
mod mcp_options;
mod metadata;
mod module_maturity;
mod tool_policy;
#[cfg(test)]
mod tests;
pub use kuzushi_descriptor::{
    ContinuationSupport, DagNodeDescriptor, FileReferenceSemantics, ModuleKind, ModuleMetadata,
    OptionSpec, OptionType, PathSemantics, PromptSpec, RuntimeRequirement, ToolDescriptor,
    ToolPhase, canonical_tool_phase,
};
pub use metadata::BuiltinModule;
pub use module_maturity::ModuleMaturity;
pub(in crate::modules) use tool_policy::{
    external_action_policy, read_policy, repository_execute_policy, target_write_policy,
    tool_policy, workspace_policy,
};
pub use tool_policy::{
    ApprovalPolicy, FindingStoreRequirement, ToolEffect, ToolPolicy, WorkspaceRequirement,
};
