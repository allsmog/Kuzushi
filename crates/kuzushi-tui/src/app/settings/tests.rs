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
            4
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
            3
        );
        assert_eq!(
            preferred_model_choice_index_for_state(Some("unknown:model"), false, false, false),
            0
        );
    }

    #[test]
    fn onboarding_cursor_selects_the_same_stable_model_identity_it_highlights() {
        for configured in [
            "openai:gpt-5.5",
            "openai:gpt-5.5-mini",
            "openai-codex:gpt-5.4",
            "anthropic:claude-sonnet-4-6",
            "anthropic:claude-opus-4-7",
        ] {
            let mut config = V2Config::default();
            config.model = Some(configured.to_string());
            let visible = visible_model_choices(config.model.as_deref());
            let cursor = preferred_visible_model_choice_cursor(&config);
            assert_eq!(
                visible.get(cursor).map(|choice| choice.id),
                Some(configured),
                "visible picker cursor drifted for {configured}"
            );
        }
    }

    #[test]
    fn legacy_codex_shorthands_are_not_public_selectors() {
        assert!(normalize_auth_provider("codex").is_err());
        assert!(normalize_auth_provider("openai-codex").is_err());
        assert!(resolve_model_selector("codex:gpt-5.5").is_none());
        assert!(resolve_model_selector("codex-mini").is_none());
        assert!(resolve_model_selector("openai-codex:gpt-5.5").is_none());
        assert_eq!(
            resolve_model_selector("openai-oauth:gpt-5.4").map(|choice| choice.index),
            Some(3)
        );
    }

    #[test]
    fn each_login_provider_resolves_its_supported_default_method() {
        assert_eq!(normalize_auth_method("openai-codex", None), Ok("browser"));
        assert_eq!(normalize_auth_method("anthropic", None), Ok("browser"));
        assert_eq!(normalize_auth_method("github-copilot", None), Ok("device"));
    }

    #[test]
    fn oauth_credentials_display_uses_shared_leaf_name() {
        assert_eq!(
            default_oauth_credentials_path_display(),
            format!(
                "~/.kuzushi/{}",
                kuzushi_core::config::OAUTH_CREDENTIALS_FILE
            )
        );
    }
}
