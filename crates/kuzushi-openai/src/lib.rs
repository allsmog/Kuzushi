/// Translate the loop driver's [`LoopHistoryEntry`] sequence into Anthropic's
/// Messages API shape. The first message is always the user's initial
/// prompt; subsequent messages alternate assistant/user as the loop ran.
pub mod anthropic_oauth;
pub mod auth;
pub mod bridge;
pub mod oauth;
pub mod runtime;

mod anthropic_messages;
mod bridge_payloads;
mod bridge_process;
mod bridge_triage;
mod next_step_bridge;
mod query_blocking;
mod runtime_config;
#[cfg(test)]
mod tests;

pub use anthropic_oauth::{AnthropicOAuthRuntime, AnthropicOAuthRuntimeOptions};
pub use oauth::{probe as probe_anthropic_oauth, OauthReadiness};
pub use runtime_config::PiAgentCoreRuntime;

pub(crate) use anthropic_messages::build_messages_for_anthropic;
pub(crate) use bridge_payloads::{
    BridgeRequest, BridgeResponse, BridgeTool, NextStepBridgeRequest, NextStepBridgeResponse,
};
pub(crate) use bridge_process::{default_bridge_command, run_bridge, run_next_step_bridge};
pub(crate) use bridge_triage::{
    clamp_outcome, fallback_triage_outcome, triage_prompt, TRIAGE_SYSTEM_PROMPT,
};
pub(crate) use next_step_bridge::next_step_blocking;
