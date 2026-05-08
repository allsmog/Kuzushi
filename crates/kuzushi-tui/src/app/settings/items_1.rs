use super::prelude::*;
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ModelChoice {
    pub index: usize,
    pub id: &'static str,
    pub label: &'static str,
    pub provider: &'static str,
    pub auth: &'static str,
    pub thinking_level: &'static str,
}

pub(crate) const MODEL_CHOICES: &[ModelChoice] = &[
    ModelChoice {
        index: 1,
        id: "openai:gpt-5.5",
        label: "GPT-5.5",
        provider: "openai",
        auth: "OPENAI_API_KEY",
        thinking_level: "xhigh",
    },
    ModelChoice {
        index: 2,
        id: "openai:gpt-5.5-mini",
        label: "GPT-5.5 mini",
        provider: "openai",
        auth: "OPENAI_API_KEY",
        thinking_level: "high",
    },
    ModelChoice {
        index: 3,
        id: "openai-codex:gpt-5.5",
        label: "Codex GPT-5.5",
        provider: "openai-codex",
        auth: "OAuth",
        thinking_level: "xhigh",
    },
    ModelChoice {
        index: 4,
        id: "openai-codex:gpt-5.5-mini",
        label: "Codex GPT-5.5 mini",
        provider: "openai-codex",
        auth: "OAuth",
        thinking_level: "high",
    },
    ModelChoice {
        index: 5,
        id: "anthropic:claude-sonnet-4-6",
        label: "Claude Sonnet 4.6",
        provider: "anthropic",
        auth: "ANTHROPIC_API_KEY or OAuth",
        thinking_level: "high",
    },
    ModelChoice {
        index: 6,
        id: "anthropic:claude-opus-4-7",
        label: "Claude Opus 4.7",
        provider: "anthropic",
        auth: "ANTHROPIC_API_KEY or OAuth",
        thinking_level: "xhigh",
    },
];

pub(crate) fn model_choices() -> &'static [ModelChoice] {
    MODEL_CHOICES
}

pub(crate) fn preferred_model_choice_index(config: &V2Config) -> usize {
    preferred_model_choice_index_for_state(
        config.model.as_deref(),
        oauth_provider_status("openai-codex").starts_with("stored"),
        env::var_os("OPENAI_API_KEY").is_some(),
        env::var_os("ANTHROPIC_API_KEY").is_some()
            || oauth_provider_status("anthropic").starts_with("stored"),
    )
}
