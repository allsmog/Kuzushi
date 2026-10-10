mod descriptor_model;
mod module_maturity;
pub mod prompt_paths;
mod tool_phase;
mod tool_policy;

pub use descriptor_model::{
    AllowanceCategory, ContinuationSupport, DagNodeDescriptor, FileReferenceSemantics, ModuleKind,
    ModuleMetadata, OptionSpec, OptionType, PathSemantics, PromptSpec, RuntimeRequirement,
    ToolDescriptor,
};
pub use module_maturity::ModuleMaturity;
pub use tool_phase::{canonical_tool_phase, ToolPhase};
pub use tool_policy::{
    ApprovalPolicy, FindingStoreRequirement, ToolEffect, ToolPolicy, WorkspaceRequirement,
};
