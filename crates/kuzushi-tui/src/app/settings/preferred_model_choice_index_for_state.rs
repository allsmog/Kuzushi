use super::*;

pub(crate) fn preferred_model_choice_index_for_state(
    configured_model: Option<&str>,
    openai_oauth_ready: bool,
    openai_key_ready: bool,
    anthropic_ready: bool,
) -> usize {
    configured_model
        .and_then(model_choice_index_by_id)
        .filter(|index| MODEL_CHOICES[*index].catalog_note.is_none())
        .or_else(|| configured_provider_choice_index(configured_model))
        .or_else(|| ready_provider_choice_index(openai_oauth_ready, "openai-codex"))
        .or_else(|| ready_provider_choice_index(openai_key_ready, "openai"))
        .or_else(|| ready_provider_choice_index(anthropic_ready, "anthropic"))
        .unwrap_or(0)
}

fn configured_provider_choice_index(model: Option<&str>) -> Option<usize> {
    let canonical = kuzushi_core::runtime::canonical_model_spec(model?).ok()?;
    let (provider, _) = canonical.split_once(':')?;
    ready_provider_choice_index(true, provider)
}

pub(crate) fn model_choice_index_by_id(model: &str) -> Option<usize> {
    let canonical = kuzushi_core::runtime::canonical_model_spec(model).ok()?;
    MODEL_CHOICES
        .iter()
        .position(|choice| choice.id == canonical)
}

pub(crate) fn ready_provider_choice_index(ready: bool, provider: &str) -> Option<usize> {
    ready.then(|| {
        MODEL_CHOICES
            .iter()
            .position(|choice| choice.provider == provider && choice.catalog_note.is_none())
    })?
}
