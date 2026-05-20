/// Adapter: turn a borrowed `&dyn AgentRuntime` into an `Arc<dyn AgentRuntime>`
/// so it can be wrapped by [`RoutedRuntime`]. The borrow's lifetime
/// determines the safety: callers must keep the underlying value alive
/// for the duration of the call.
///
/// Implementation note: we wrap the reference in a thin static-lifetime
/// trait object that delegates everything to the borrowed runtime. This
/// avoids the need to take ownership while still satisfying
/// `RoutedRuntime`'s `Arc<dyn AgentRuntime>` constructor.
use self::support::resolve_tool_target;
use crate::findings::FindingStore;
use crate::runtime::AgentRuntime;
use anyhow::{Context, Result};
pub(in crate::modules) use bounty_module::*;
pub(in crate::modules) use carlini_threat_hunt_module::*;
pub(in crate::modules) use descriptor::*;
pub(in crate::modules) use full_mode_config_paths::*;
pub(in crate::modules) use full_mode_dry_run::*;
pub(in crate::modules) use full_mode_module::*;
pub(in crate::modules) use input::*;
pub(in crate::modules) use options::*;
pub(in crate::modules) use offense_review_module::*;
pub(in crate::modules) use pipeline_module::*;
pub(in crate::modules) use plugin_resolution::*;
pub(in crate::modules) use pwn::*;
pub(in crate::modules) use recon_module::*;
pub(in crate::modules) use report_module::*;
pub(in crate::modules) use resolve_tool_model::*;
pub(in crate::modules) use router_show_tool::*;
pub(in crate::modules) use run_deep_audit_tool::*;
pub(in crate::modules) use run_smoke_next_step_tool::*;
pub(in crate::modules) use sast_pipeline::*;
pub(in crate::modules) use sast_run::*;
use serde_json::{json, Value};
pub(in crate::modules) use support::*;
pub(in crate::modules) use taint_iris::*;
pub(in crate::modules) use taint_iris_next::*;
pub(in crate::modules) use threat_intel_module::*;
pub(in crate::modules) use threat_leads_module::*;
pub(in crate::modules) use threat_model_module::*;
pub(in crate::modules) use triage::*;
pub(in crate::modules) use triage_module::*;
pub(in crate::modules) use uaf_hunt_module::*;
pub(in crate::modules) use unsafe_clone_runtime_ref::*;
pub(in crate::modules) use verify::*;
pub(in crate::modules) use workspace_module::*;
mod agentic_sast;
mod application;
mod builtins;
mod chrome_rce;
mod context;
mod contracts;
mod descriptor;
mod execution_context;
mod input;
mod native_scanners;
mod offense_review_module;
mod options;
mod pipeline;
mod plugin_adapters;
mod plugin_resolution;
mod prompt_armor;
mod pwn;
mod registry;
mod report_module;
mod runtime_requirements;
mod sast_pipeline;
mod sast_run;
mod support;
mod taint_iris;
mod taint_iris_next;
mod triage;
mod vendor_assessment;
mod verify;
mod workspace_tools;

mod bounty_module;
mod carlini_threat_hunt_module;
mod full_mode_config_paths;
mod full_mode_dry_run;
mod full_mode_module;
mod pipeline_module;
mod recon_module;
mod resolve_tool_model;
mod router_show_tool;
mod run_deep_audit_tool;
mod run_smoke_next_step_tool;
#[cfg(test)]
mod tests;
mod threat_intel_module;
mod threat_leads_module;
mod threat_model_module;
mod triage_module;
mod uaf_hunt_module;
mod unsafe_clone_runtime_ref;
mod workspace_module;

pub use agentic_sast::{AgenticSastPersistedRun, AgenticSastReport};
pub use contracts::ToolExecutionContext;
pub use contracts::{
    BuiltinModule, DagNodeDescriptor, ModuleKind, ModuleMetadata, OptionSpec, OptionType,
    ToolDescriptor,
};
pub use registry::ModuleRegistry;
pub use runtime_requirements::{
    agent_runtime_tool_names, tool_needs_runtime, tool_requires_agent_runtime,
    tool_uses_agent_runtime, wants_sast_runtime, RUNTIME_TOOL_NAMES,
};
