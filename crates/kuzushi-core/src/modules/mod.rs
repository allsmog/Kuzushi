use self::support::resolve_tool_target;
use crate::findings::FindingStore;
use crate::runtime::AgentRuntime;
use anyhow::{Context, Result};
pub(in crate::modules) use bounty_module::*;
pub(in crate::modules) use campaign_module::*;
pub(in crate::modules) use carlini_threat_hunt_module::*;
pub(in crate::modules) use codeql_db_module::*;
pub(in crate::modules) use coverage_module::*;
pub(in crate::modules) use cpg_module::*;
pub(in crate::modules) use descriptor::*;
pub(in crate::modules) use engagement_module::*;
pub(in crate::modules) use entry_points_module::*;
pub(in crate::modules) use findings_module::*;
pub(in crate::modules) use fleet_module::*;
pub(in crate::modules) use fuzz_module::*;
pub(in crate::modules) use full_mode_config_paths::*;
pub(in crate::modules) use full_mode_dry_run::*;
pub(in crate::modules) use full_mode_module::*;
pub(in crate::modules) use full_mode_tool_input::*;
pub(in crate::modules) use input::*;
pub(in crate::modules) use offense_module::*;
pub(in crate::modules) use offense_review_module::*;
pub(in crate::modules) use options::*;
pub(in crate::modules) use patch_module::*;
pub(in crate::modules) use pipeline_module::*;
pub(in crate::modules) use plugin_resolution::*;
pub(in crate::modules) use pwn::*;
pub(in crate::modules) use recon_module::*;
pub(in crate::modules) use pack_module::*;
pub(in crate::modules) use report_module::*;
pub(in crate::modules) use resolve_tool_model::*;
pub(in crate::modules) use router_module::*;
pub(in crate::modules) use router_show_tool::*;
pub(in crate::modules) use run_deep_audit_tool::*;
pub(in crate::modules) use sast_run::*;
use serde_json::{json, Value};
pub(in crate::modules) use support::*;
pub(in crate::modules) use suppress_module::*;
pub(in crate::modules) use suppress_run::*;
pub(in crate::modules) use taint_iris::*;
pub(in crate::modules) use taint_iris_next::*;
pub(in crate::modules) use threat_intel_module::*;
pub(in crate::modules) use threat_leads_module::*;
pub(in crate::modules) use threat_model_module::*;
pub(in crate::modules) use triage::*;
pub(in crate::modules) use triage_module::*;
pub(in crate::modules) use uaf_hunt_module::*;
pub(in crate::modules) use verify::*;
pub(in crate::modules) use verify_module::*;
pub(in crate::modules) use workspace_module::*;
mod agentic_sast;
mod application;
pub mod autonomy;
mod builtins;
mod catalog_query;
mod chrome_rce;
pub(crate) mod context;
mod contracts;
mod descriptor;
pub mod display_name;
mod dynamic_loader;
mod engagement_module;
mod execution_context;
mod findings_module;
mod fleet_module;
mod fuzz_module;
mod input;
mod native_scanners;
mod offense_module;
mod offense_review_module;
mod options;
mod patch_module;
mod pipeline;
mod plugin_adapters;
mod plugin_resolution;
mod prompt_armor;
mod pwn;
mod registry;
mod pack_module;
mod report_module;
mod runtime_requirements;
mod sast_run;
mod support;
mod taint_iris;
mod taint_iris_next;
mod triage;
mod vendor_assessment;
mod verify;
mod workspace_tools;

mod bounty_module;
mod campaign_module;
mod carlini_threat_hunt_module;
mod codeql_db_module;
mod coverage_module;
mod cpg_module;
mod entry_points_module;
mod full_mode_config_paths;
mod full_mode_dry_run;
mod full_mode_module;
mod full_mode_tool_input;
mod pipeline_module;
mod recon_module;
mod resolve_tool_model;
mod router_module;
mod router_show_tool;
mod run_deep_audit_tool;
mod suppress_module;
mod suppress_run;
#[cfg(test)]
mod tests;
mod threat_intel_module;
mod threat_leads_module;
mod threat_model_module;
mod triage_module;
mod uaf_hunt_module;
mod verify_module;
mod workspace_module;

pub use agentic_sast::{AgenticSastPersistedRun, AgenticSastReport};
pub use autonomy::{
    gate as autonomy_gate, tool_phase, AutonomyDecision, AutonomyPosture, AutonomyRefusal,
    WorkflowPhase,
};
pub use builtins::{
    ApplicationToolCall, ObservedDispatchOutcome, PendingToolCallCompletion, PreparedToolInput,
    ToolCallIdentity,
};
pub use catalog_query::{RuntimeFilter, ToolQuery};
pub use contracts::{
    canonical_tool_phase, ApprovalPolicy, BuiltinModule, DagNodeDescriptor, FileReferenceSemantics,
    FindingStoreRequirement, ModuleKind, ModuleMetadata, OptionSpec, OptionType, PathSemantics,
    PromptSpec, RuntimeRequirement, ToolDescriptor, ToolEffect, ToolPhase, ToolPolicy,
    WorkspaceRequirement,
};
pub use contracts::{ExecutionAuthorization, ToolExecutionContext};
pub use display_name::tool_display_name;
pub use dynamic_loader::{
    approve_dynamic_module, default_dynamic_lockfile_path, inspect_dynamic_module,
    revoke_dynamic_module, DynamicModuleInspection, DynamicModuleLoadOptions,
};
pub use options::coerce_option_value;
pub use registry::ModuleRegistry;
pub use runtime_requirements::{
    agent_runtime_tool_names, tool_defaults_to_workspace, tool_execution_model,
    tool_needs_finding_store, tool_needs_runtime, tool_requires_agent_runtime,
    tool_uses_agent_runtime, tool_uses_finding_store, tool_wants_runtime, wants_sast_runtime,
};
