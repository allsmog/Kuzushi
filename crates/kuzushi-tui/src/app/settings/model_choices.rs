use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ModelChoice {
    pub index: usize,
    pub id: &'static str,
    pub label: &'static str,
    pub provider: &'static str,
    pub auth: &'static str,
    pub thinking_level: &'static str,
    pub aliases: &'static [&'static str],
    /// Legacy selectors stay resolvable without being offered as suggestions.
    pub catalog_note: Option<&'static str>,
}

pub(crate) const MODEL_CHOICES: &[ModelChoice] = &[
    ModelChoice {
        index: 1,
        id: "openai:gpt-5.5",
        label: "GPT-5.5",
        provider: "openai",
        auth: "OPENAI_API_KEY",
        thinking_level: "xhigh",
        aliases: &["gpt-5.5", "5.5"],
        catalog_note: None,
    },
    ModelChoice {
        index: 11,
        id: "openai:gpt-5.4-mini",
        label: "GPT-5.4 mini",
        provider: "openai",
        auth: "OPENAI_API_KEY",
        thinking_level: "high",
        aliases: &["gpt-5.4-mini", "5.4-mini"],
        catalog_note: None,
    },
    ModelChoice {
        index: 7,
        id: "openai-codex:gpt-5.6-terra",
        label: "OpenAI OAuth GPT-5.6 Terra",
        provider: "openai-codex",
        auth: "OAuth",
        thinking_level: "medium",
        aliases: &[
            "terra",
            "gpt-5.6-terra",
            "openai-oauth:gpt-5.6-terra",
            "oauth:gpt-5.6-terra",
        ],
        catalog_note: None,
    },
    ModelChoice {
        index: 8,
        id: "openai-codex:gpt-5.6-sol",
        label: "OpenAI OAuth GPT-5.6 Sol",
        provider: "openai-codex",
        auth: "OAuth",
        thinking_level: "medium",
        aliases: &[
            "sol",
            "gpt-5.6-sol",
            "openai-oauth:gpt-5.6-sol",
            "oauth:gpt-5.6-sol",
        ],
        catalog_note: None,
    },
    ModelChoice {
        index: 9,
        id: "openai-codex:gpt-5.6-luna",
        label: "OpenAI OAuth GPT-5.6 Luna",
        provider: "openai-codex",
        auth: "OAuth",
        thinking_level: "medium",
        aliases: &[
            "luna",
            "gpt-5.6-luna",
            "openai-oauth:gpt-5.6-luna",
            "oauth:gpt-5.6-luna",
        ],
        catalog_note: None,
    },
    ModelChoice {
        index: 10,
        id: "openai-codex:gpt-6-astra",
        label: "OpenAI OAuth GPT-6 Astra",
        provider: "openai-codex",
        auth: "OAuth",
        thinking_level: "medium",
        aliases: &[
            "astra",
            "gpt-6-astra",
            "openai-oauth:gpt-6-astra",
            "oauth:gpt-6-astra",
        ],
        catalog_note: None,
    },
    ModelChoice {
        index: 12,
        id: "openai-codex:gpt-5.5",
        label: "OpenAI OAuth GPT-5.5",
        provider: "openai-codex",
        auth: "OAuth",
        thinking_level: "medium",
        aliases: &["openai-oauth:gpt-5.5", "oauth:gpt-5.5"],
        catalog_note: None,
    },
    ModelChoice {
        index: 4,
        id: "openai-codex:gpt-5.3-codex-spark",
        label: "OpenAI OAuth GPT-5.3 Codex Spark",
        provider: "openai-codex",
        auth: "OAuth (ChatGPT Pro preview access)",
        thinking_level: "high",
        aliases: &[
            "spark",
            "gpt-5.3-codex-spark",
            "openai-oauth:gpt-5.3-codex-spark",
            "oauth:gpt-5.3-codex-spark",
        ],
        catalog_note: None,
    },
    ModelChoice {
        index: 5,
        id: "anthropic:claude-sonnet-4-6",
        label: "Claude Sonnet 4.6",
        provider: "anthropic",
        auth: "ANTHROPIC_API_KEY or OAuth",
        thinking_level: "high",
        aliases: &["sonnet", "claude-sonnet", "claude-sonnet-4-6"],
        catalog_note: None,
    },
    ModelChoice {
        index: 6,
        id: "anthropic:claude-opus-4-7",
        label: "Claude Opus 4.7",
        provider: "anthropic",
        auth: "ANTHROPIC_API_KEY or OAuth",
        thinking_level: "xhigh",
        aliases: &["opus", "claude-opus", "claude-opus-4-7"],
        catalog_note: None,
    },
    ModelChoice {
        index: 2,
        id: "openai:gpt-5.5-mini",
        label: "GPT-5.5 mini",
        provider: "openai",
        auth: "OPENAI_API_KEY",
        thinking_level: "high",
        aliases: &["gpt-5.5-mini", "5.5-mini", "mini"],
        catalog_note: Some("Not in the current reference catalog; availability is unverified."),
    },
    ModelChoice {
        index: 3,
        id: "openai-codex:gpt-5.4",
        label: "OpenAI OAuth GPT-5.4",
        provider: "openai-codex",
        auth: "OAuth",
        thinking_level: "xhigh",
        aliases: &["openai-oauth:gpt-5.4", "oauth:gpt-5.4"],
        catalog_note: Some(
            "Retired for ChatGPT sign-in on August 31, 2026. Choose a current model.",
        ),
    },
];

pub(crate) fn model_choices() -> &'static [ModelChoice] {
    MODEL_CHOICES
}

/// The explicit model change offered when a credential screen belongs to a
/// provider namespace whose OAuth transport uses a different model namespace.
/// Merely opening the picker never applies this selection.
pub(crate) fn oauth_model_switch_for_provider(provider: &str) -> Option<AuthModelSwitch> {
    let oauth_provider = AuthProvider::from_scene_provider(provider)?.oauth_model_provider();
    if oauth_provider == provider {
        return None;
    }
    MODEL_CHOICES
        .iter()
        .find(|choice| choice.provider == oauth_provider && choice.catalog_note.is_none())
        .map(|choice| AuthModelSwitch {
            model: choice.id.to_string(),
            thinking_level: choice.thinking_level.to_string(),
        })
}

/// The public selector of the model an OAuth credential choice would switch
/// to, for copy that must name the real target rather than a stale one.
pub(crate) fn oauth_model_switch_target_label(provider: &str) -> Option<String> {
    oauth_model_switch_for_provider(provider)
        .map(|selection| crate::app::display_model_selector(&selection.model))
}

pub(crate) fn visible_model_choice_indexes(config: &V2Config) -> Vec<usize> {
    let preferred = preferred_model_choice_index(config);
    std::iter::once(preferred)
        .chain((0..MODEL_CHOICES.len()).filter(|index| *index != preferred))
        .filter(|index| MODEL_CHOICES[*index].catalog_note.is_none())
        .collect()
}

pub(crate) fn visible_model_choices(config: &V2Config) -> Vec<&'static ModelChoice> {
    visible_model_choice_indexes(config)
        .into_iter()
        .filter_map(|index| MODEL_CHOICES.get(index))
        .collect()
}

pub(crate) fn model_catalog_note(model: &str) -> Option<&'static str> {
    match model_choice_index_by_id(model) {
        Some(index) => MODEL_CHOICES[index].catalog_note,
        None => Some("Not in the current reference catalog; availability is unverified."),
    }
}

pub(crate) fn display_model_selector(model: &str) -> String {
    let model = model.trim();
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
        auth_ready_for_provider(config, "openai-codex"),
        auth_ready_for_provider(config, "openai"),
        auth_ready_for_provider(config, "anthropic"),
    )
}

pub(crate) fn model_picker_cursor(app: &ShellApp) -> usize {
    let selected = app.router.model_picker().selected_id();
    visible_model_choices(app.config())
        .iter()
        .position(|choice| Some(choice.id) == selected)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
