use super::*;

pub(crate) fn preferred_model_choice_index_for_state(
    configured_model: Option<&str>,
    codex_oauth_ready: bool,
    openai_key_ready: bool,
    anthropic_ready: bool,
) -> usize {
    if let Some(index) = configured_model.and_then(model_choice_index_by_id) {
        return index;
    }
    if let Some(index) = ready_provider_choice_index(codex_oauth_ready, "openai-codex") {
        return index;
    }
    if let Some(index) = ready_provider_choice_index(openai_key_ready, "openai") {
        return index;
    }
    if let Some(index) = ready_provider_choice_index(anthropic_ready, "anthropic") {
        return index;
    }
    0
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
