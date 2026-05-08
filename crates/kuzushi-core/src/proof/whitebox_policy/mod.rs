use crate::findings::{Finding, StaticProofState};
use crate::runtime::AgentToolPolicy;
use anyhow::{Context, Result};
pub(crate) use policy_contract::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
pub(crate) use whitebox_static_proof_state_from_input::*;
mod analysis_mode_from_input;
mod apply_whitebox_static_sast_policy;
mod policy_contract;
mod whitebox_static_proof_state_from_input;
pub use apply_whitebox_static_sast_policy::apply_whitebox_static_sast_policy;
pub(in crate::proof::whitebox_policy) use apply_whitebox_static_sast_policy::{
    is_execution_proof_state, normalize_agent_tool_name, truthy_bool,
};
#[cfg(test)]
mod tests;

pub use analysis_mode_from_input::agent_tool_policy_for_input;
pub use analysis_mode_from_input::analysis_mode_from_input;
pub use analysis_mode_from_input::default_whitebox_static_agent_tool_policy;
pub use analysis_mode_from_input::validate_whitebox_static_agent_tool_policy;
pub use analysis_mode_from_input::whitebox_static_enabled;
pub use analysis_mode_from_input::whitebox_static_profile_requested;
pub use analysis_mode_from_input::whitebox_static_proof_state_from_str;
pub use analysis_mode_from_input::whitebox_static_triage_prompt_block;
pub use analysis_mode_from_input::whitebox_static_triage_system_prompt;
pub use policy_contract::AnalysisMode;
pub use policy_contract::WhiteboxStaticPolicy;
pub use policy_contract::WHITEBOX_STATIC_AGENT_TOOL_PROFILE;
pub use policy_contract::WHITEBOX_STATIC_READ_ONLY_AGENT_TOOLS;
pub use policy_contract::WHITEBOX_STATIC_TRIAGE_PROMPT_BLOCK;
pub use policy_contract::WHITEBOX_STATIC_TRIAGE_SYSTEM_PROMPT;
pub use whitebox_static_proof_state_from_input::mark_whitebox_static_findings;
pub use whitebox_static_proof_state_from_input::whitebox_static_proof_state_from_input;
