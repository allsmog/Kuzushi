/// Adapter: turn a borrowed `&dyn AgentRuntime` into an `Arc<dyn AgentRuntime>`
/// so it can be wrapped by [`RoutedRuntime`]. The borrow's lifetime
/// determines the safety: callers must keep the underlying value alive
/// for the duration of the call.
///
/// Implementation note: we wrap the reference in a thin static-lifetime
/// trait object that delegates everything to the borrowed runtime. This
/// avoids the need to take ownership while still satisfying
/// `RoutedRuntime`'s `Arc<dyn AgentRuntime>` constructor.
mod prelude;
use prelude::*;
mod siblings;
pub(in crate::modules) use siblings::*;
mod agentic_sast;
mod chrome_rce;
mod context;
mod descriptor;
mod execution_context;
mod generic_findings;
mod input;
mod json_fields;
mod native_scanners;
mod options;
mod pipeline;
mod plugin_adapters;
mod plugin_resolution;
mod prompt_armor;
mod registry;
mod sast_pipeline;
mod sast_run;
mod support;
mod taint_iris;
mod taint_iris_next;
mod triage;
mod vendor_assessment;
mod verify;
mod workspace_tools;

mod items_1;
mod items_10;
mod items_11;
mod items_12;
mod items_13;
mod items_2;
mod items_3;
mod items_4;
mod items_6;
mod items_7;
mod items_8;
mod items_9;
mod recon_module;
mod run_deep_audit_tool;
#[cfg(test)]
mod tests;

pub use agentic_sast::{AgenticSastPersistedRun, AgenticSastReport};
pub use descriptor::{
    BuiltinModule, DagNodeDescriptor, ModuleKind, ModuleMetadata, OptionSpec, OptionType,
    ToolDescriptor,
};
pub use execution_context::ToolExecutionContext;
pub use registry::ModuleRegistry;
