use super::*;

pub(crate) fn preferred_model_choice_index_for_state(
    configured_model: Option<&str>,
    openai_oauth_ready: bool,
    openai_key_ready: bool,
    anthropic_ready: bool,
) -> usize {
    configured_model
        .and_then(model_choice_index_by_id)
        .or_else(|| ready_provider_choice_index(openai_oauth_ready, "openai-codex"))
        .or_else(|| ready_provider_choice_index(openai_key_ready, "openai"))
        .or_else(|| ready_provider_choice_index(anthropic_ready, "anthropic"))
        .unwrap_or(0)
}

pub(crate) fn model_choice_index_by_id(model: &str) -> Option<usize> {
    MODEL_CHOICES.iter().position(|choice| choice.id == model)
}

pub(crate) fn ready_provider_choice_index(ready: bool, provider: &str) -> Option<usize> {
    ready.then(|| {
        MODEL_CHOICES
            .iter()
            .position(|choice| choice.provider == provider)
    })?
}
