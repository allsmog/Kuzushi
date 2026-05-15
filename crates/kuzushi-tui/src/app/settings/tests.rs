#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn preferred_model_choice_state_respects_configured_then_oauth_openai_anthropic() {
        assert_eq!(
            preferred_model_choice_index_for_state(
                Some("anthropic:claude-opus-4-7"),
                true,
                true,
                true
            ),
            5
        );
        assert_eq!(
            preferred_model_choice_index_for_state(None, true, true, true),
            2
        );
        assert_eq!(
            preferred_model_choice_index_for_state(None, false, true, true),
            0
        );
        assert_eq!(
            preferred_model_choice_index_for_state(None, false, false, true),
            4
        );
        assert_eq!(
            preferred_model_choice_index_for_state(Some("unknown:model"), false, false, false),
            0
        );
    }

    #[test]
    fn legacy_codex_shorthands_are_not_public_selectors() {
        assert!(normalize_auth_provider("codex").is_err());
        assert!(normalize_auth_provider("openai-codex").is_err());
        assert!(resolve_model_selector("codex:gpt-5.5").is_none());
        assert!(resolve_model_selector("codex-mini").is_none());
        assert!(resolve_model_selector("openai-codex:gpt-5.5").is_none());
        assert_eq!(
            resolve_model_selector("openai-oauth:gpt-5.5").map(|choice| choice.index),
            Some(3)
        );
    }
}
