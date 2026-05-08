mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod apply_whitebox_static_sast_policy;
mod items_1;
mod items_2;
mod items_3;
pub use apply_whitebox_static_sast_policy::apply_whitebox_static_sast_policy;
pub(in crate::whitebox_static) use apply_whitebox_static_sast_policy::{
    is_execution_proof_state, normalize_agent_tool_name, truthy_bool,
};
#[cfg(test)]
mod tests;

pub use items_1::AnalysisMode;
pub use items_1::WhiteboxStaticPolicy;
pub use items_1::WHITEBOX_STATIC_AGENT_TOOL_PROFILE;
pub use items_1::WHITEBOX_STATIC_READ_ONLY_AGENT_TOOLS;
pub use items_1::WHITEBOX_STATIC_TRIAGE_PROMPT_BLOCK;
pub use items_1::WHITEBOX_STATIC_TRIAGE_SYSTEM_PROMPT;
pub use items_2::agent_tool_policy_for_input;
pub use items_2::analysis_mode_from_input;
pub use items_2::default_whitebox_static_agent_tool_policy;
pub use items_2::validate_whitebox_static_agent_tool_policy;
pub use items_2::whitebox_static_enabled;
pub use items_2::whitebox_static_profile_requested;
pub use items_2::whitebox_static_proof_state_from_str;
pub use items_2::whitebox_static_triage_prompt_block;
pub use items_2::whitebox_static_triage_system_prompt;
pub use items_3::mark_whitebox_static_findings;
pub use items_3::whitebox_static_proof_state_from_input;
