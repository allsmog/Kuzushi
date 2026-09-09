#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn preferred_model_choice_state_respects_configured_then_oauth_openai_anthropic() {
        let selected = |model, oauth, key, anthropic| {
            MODEL_CHOICES[preferred_model_choice_index_for_state(model, oauth, key, anthropic)].id
        };
        assert_eq!(
            selected(Some("anthropic:claude-opus-4-7"), true, true, true),
            "anthropic:claude-opus-4-7"
        );
        assert_eq!(
            selected(None, true, true, true),
            "openai-codex:gpt-5.6-terra"
        );
        assert_eq!(selected(None, false, true, true), "openai:gpt-5.5");
        assert_eq!(
            selected(None, false, false, true),
            "anthropic:claude-sonnet-4-6"
        );
        assert_eq!(
            selected(Some("unknown:model"), false, false, false),
            "openai:gpt-5.5"
        );
    }

    #[test]
    fn onboarding_cursor_selects_the_same_stable_model_identity_it_highlights() {
        for configured in MODEL_CHOICES
            .iter()
            .filter(|choice| choice.catalog_note.is_none())
            .map(|choice| choice.id)
        {
            let mut config = V2Config::default();
            config.model = Some(configured.to_string());
            let visible = visible_model_choices(&config);
            let mut app = ShellApp::new(config, None);
            app.open_model_picker();
            let cursor = model_picker_cursor(&app);
            assert_eq!(
                visible.get(cursor).map(|choice| choice.id),
                Some(configured),
                "visible picker cursor drifted for {configured}"
            );
            assert_eq!(app.router.model_picker().selected_id(), Some(configured));
        }
    }

    #[test]
    fn visible_catalog_contains_every_choice_once_with_configured_choice_first() {
        let configured = "anthropic:claude-opus-4-7";
        let mut config = V2Config::default();
        config.model = Some(" anthropic:claude-opus-4-7 ".to_string());
        let visible = visible_model_choices(&config);
        let ids = visible.iter().map(|choice| choice.id).collect::<Vec<_>>();
        let unique = ids
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(ids.first().copied(), Some(configured));
        let suggested = MODEL_CHOICES
            .iter()
            .filter(|choice| choice.catalog_note.is_none())
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), suggested.len());
        assert_eq!(unique.len(), suggested.len());
        assert!(suggested.iter().all(|choice| ids.contains(&choice.id)));
    }

    #[test]
    fn codex_oauth_selectors_preserve_legacy_ids_and_offer_gpt_5_5() {
        assert!(normalize_auth_provider("codex").is_err());
        assert!(normalize_auth_provider("openai-codex").is_err());
        assert!(resolve_model_selector("codex:gpt-5.5").is_none());
        assert!(resolve_model_selector("codex-mini").is_none());
        assert_eq!(
            resolve_model_selector("openai-codex:gpt-5.5").map(|choice| choice.index),
            Some(12)
        );
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
