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
        id: "openai-codex:gpt-5.4",
        label: "OpenAI OAuth GPT-5.4",
        provider: "openai-codex",
        auth: "OAuth",
        thinking_level: "xhigh",
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

pub(crate) fn oauth_model_choice_for_provider(provider: &str) -> Option<&'static ModelChoice> {
    if AuthProvider::from_scene_provider(provider) != Some(AuthProvider::OpenAi) {
        return None;
    }
    MODEL_CHOICES
        .iter()
        .find(|choice| choice.provider == AuthProvider::OpenAi.oauth_model_provider())
}

pub(crate) fn api_key_model_choice_for_provider(provider: &str) -> Option<&'static ModelChoice> {
    if AuthProvider::from_scene_provider(provider) != Some(AuthProvider::OpenAi) {
        return None;
    }
    MODEL_CHOICES
        .iter()
        .find(|choice| choice.provider == AuthProvider::OpenAi.api_key_provider())
}

pub(crate) fn visible_model_choice_indexes(configured_model: Option<&str>) -> Vec<usize> {
    let mut seen = std::collections::BTreeSet::new();
    [visible_primary_openai_choice(configured_model), 1, 2, 3, 4]
        .into_iter()
        .filter(|index| seen.insert(*index))
        .collect()
}

pub(crate) fn visible_model_choices(configured_model: Option<&str>) -> Vec<&'static ModelChoice> {
    visible_model_choice_indexes(configured_model)
        .into_iter()
        .filter_map(|index| MODEL_CHOICES.get(index))
        .collect()
}

fn visible_primary_openai_choice(configured_model: Option<&str>) -> usize {
    match configured_model {
        Some("openai-codex:gpt-5.4") => 2,
        Some("openai:gpt-5.5") => 0,
        _ if auth_ready_for_provider("openai-codex") => 2,
        _ => 0,
    }
}

pub(crate) fn display_model_selector(model: &str) -> String {
    model
        .strip_prefix("openai-codex:")
        .map(|name| format!("openai-oauth:{name}"))
        .unwrap_or_else(|| model.to_string())
}

pub(crate) fn display_model_provider(provider: &str) -> &str {
    auth_provider_label(provider)
}

pub(crate) fn model_choice_display_selector(choice: &ModelChoice) -> String {
    display_model_selector(choice.id)
}

pub(crate) fn preferred_model_choice_index(config: &V2Config) -> usize {
    preferred_model_choice_index_for_state(
        config.model.as_deref(),
        auth_ready_for_provider("openai-codex"),
        auth_ready_for_provider("openai"),
        auth_ready_for_provider("anthropic"),
    )
}

/// Cursor position inside the *visible* onboarding list for the preferred
/// model. The preferred selector above intentionally returns an index into
/// `MODEL_CHOICES`; the picker renders a reordered subset, so feeding that
/// absolute index directly to its cursor can highlight one row while Enter
/// selects another.
pub(crate) fn preferred_visible_model_choice_cursor(config: &V2Config) -> usize {
    let preferred = preferred_model_choice_index(config);
    visible_model_choice_indexes(config.model.as_deref())
        .iter()
        .position(|index| *index == preferred)
        .unwrap_or(0)
}
