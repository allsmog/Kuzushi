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
    fn onboarding_cursor_selects_the_same_stable_model_identity_it_highlights() {
        for configured in [
            "openai:gpt-5.5",
            "openai:gpt-5.5-mini",
            "openai-codex:gpt-5.4",
            "openai-codex:gpt-5.3-codex-spark",
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
    fn visible_catalog_contains_every_choice_once_with_configured_choice_first() {
        let configured = "anthropic:claude-opus-4-7";
        let visible = visible_model_choices(Some(" anthropic:claude-opus-4-7 "));
        let ids = visible.iter().map(|choice| choice.id).collect::<Vec<_>>();
        let unique = ids
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(ids.first().copied(), Some(configured));
        assert_eq!(ids.len(), MODEL_CHOICES.len());
        assert_eq!(unique.len(), MODEL_CHOICES.len());
        assert!(MODEL_CHOICES.iter().all(|choice| ids.contains(&choice.id)));
    }

    #[test]
    fn codex_oauth_selectors_expose_gpt_5_4_and_spark_without_legacy_provider_aliases() {
        assert!(normalize_auth_provider("codex").is_err());
        assert!(normalize_auth_provider("openai-codex").is_err());
        assert!(resolve_model_selector("codex:gpt-5.5").is_none());
        assert!(resolve_model_selector("codex-mini").is_none());
        assert!(resolve_model_selector("openai-codex:gpt-5.5").is_none());
        assert_eq!(
            resolve_model_selector("openai-oauth:gpt-5.4").map(|choice| choice.index),
            Some(3)
        );
        assert_eq!(
            resolve_model_selector("spark").map(|choice| choice.index),
            Some(4)
        );
        assert_eq!(
            resolve_model_selector("openai-oauth:gpt-5.3-codex-spark").map(|choice| choice.id),
            Some("openai-codex:gpt-5.3-codex-spark")
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
