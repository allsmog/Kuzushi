#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn preferred_model_choice_state_respects_configured_then_codex_openai_anthropic() {
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
}
