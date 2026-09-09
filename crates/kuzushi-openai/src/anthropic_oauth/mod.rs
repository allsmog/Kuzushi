mod client;
mod options;
mod response;
mod runtime_impl;

#[cfg(test)]
mod tests;

pub use options::{AnthropicOAuthRuntime, AnthropicOAuthRuntimeOptions};
pub(crate) use response::estimate_cost_usd_with_cache;

#[cfg(test)]
pub(crate) use client::{
    anthropic_messages_body, ensure_anthropic_success, parse_anthropic_messages_response,
};
#[cfg(test)]
pub(crate) use response::{maybe_parse_json, strip_provider_prefix};
#[cfg(test)]
pub(crate) use runtime_impl::{build_triage_prompt, clamp_outcome, triage_outcome_from_response};
