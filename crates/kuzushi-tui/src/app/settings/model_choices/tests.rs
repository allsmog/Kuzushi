use super::*;

#[test]
fn model_catalog_public_oauth_command_preserves_an_uncatalogued_model() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let effects = app.reduce_model_command(&Some(
        "global openai-oauth:operator-custom-model medium".to_string(),
    ));
    assert_eq!(
        app.config().model.as_deref(),
        Some("openai-codex:operator-custom-model")
    );
    assert_eq!(
        app.session_thinking_level_owned().as_deref(),
        Some("medium")
    );
    assert_eq!(effects.len(), 1);
}

#[test]
fn model_catalog_numeric_ids_and_aliases_are_unique_and_keep_identity() {
    let mut selectors = std::collections::BTreeSet::new();
    for choice in MODEL_CHOICES {
        for selector in std::iter::once(choice.index.to_string())
            .chain(std::iter::once(choice.id.to_string()))
            .chain(choice.aliases.iter().map(|alias| alias.to_string()))
        {
            assert!(selectors.insert(selector.clone()), "duplicate {selector}");
            assert_eq!(
                resolve_model_selector(&selector).map(|row| row.id),
                Some(choice.id)
            );
        }
    }
}

#[test]
fn model_catalog_suggestions_exclude_retired_and_unverified_legacy_entries() {
    let config = V2Config::default();
    let ids = visible_model_choices(&config)
        .iter()
        .map(|choice| choice.id)
        .collect::<Vec<_>>();
    assert!(!ids.contains(&"openai-codex:gpt-5.4"));
    assert!(!ids.contains(&"openai:gpt-5.5-mini"));
}

#[test]
fn model_catalog_offers_current_oauth_models_and_distinct_api_mini() {
    let config = V2Config::default();
    let choices = visible_model_choices(&config);
    for id in [
        "openai-codex:gpt-5.6-terra",
        "openai-codex:gpt-5.6-sol",
        "openai-codex:gpt-5.6-luna",
        "openai-codex:gpt-6-astra",
        "openai-codex:gpt-5.5",
        "openai:gpt-5.4-mini",
    ] {
        assert!(choices.iter().any(|choice| choice.id == id), "missing {id}");
    }
}

#[test]
fn model_catalog_legacy_aliases_keep_the_original_model_identity() {
    for (selector, expected) in [
        ("3", "openai-codex:gpt-5.4"),
        ("openai-oauth:gpt-5.4", "openai-codex:gpt-5.4"),
        ("2", "openai:gpt-5.5-mini"),
        ("mini", "openai:gpt-5.5-mini"),
        ("5.5", "openai:gpt-5.5"),
        ("12", "openai-codex:gpt-5.5"),
        ("openai-oauth:gpt-5.5", "openai-codex:gpt-5.5"),
    ] {
        assert_eq!(
            resolve_model_selector(selector).map(|choice| choice.id),
            Some(expected)
        );
    }
}

#[test]
fn model_catalog_recommends_current_identity_without_changing_retired_selection() {
    let mut config = V2Config::default();
    config.model = Some("openai-codex:gpt-5.4".to_string());
    let preferred =
        preferred_model_choice_index_for_state(config.model.as_deref(), true, false, false);
    assert_eq!(MODEL_CHOICES[preferred].id, "openai-codex:gpt-5.6-terra");
    assert_eq!(config.model.as_deref(), Some("openai-codex:gpt-5.4"));
}

#[test]
fn model_catalog_preferred_identity_normalizes_whitespace_consistently() {
    let configured = " anthropic:claude-opus-4-7 ";
    let preferred = preferred_model_choice_index_for_state(Some(configured), false, false, false);
    assert_eq!(MODEL_CHOICES[preferred].id, "anthropic:claude-opus-4-7");
}

#[test]
fn model_catalog_unknown_configured_model_prefers_its_own_provider() {
    let preferred = preferred_model_choice_index_for_state(
        Some("openai:operator-custom-model"),
        true,
        false,
        true,
    );
    assert_eq!(MODEL_CHOICES[preferred].id, "openai:gpt-5.5");
}

#[test]
fn model_picker_escape_keeps_model_drafts_target_and_setup_state() {
    let target = tempfile::tempdir().unwrap();
    let mut config = V2Config::default();
    config.model = Some("openai-codex:gpt-5.4".to_string());
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(target.path().to_path_buf()));
    app.set_input("held shell command".to_string());
    app.router
        .answers_mut()
        .draft
        .insert("held question α\nsecond line");
    let draft = app.router.answers().draft.clone();
    app.router.setup_mut().set_cursor(3);
    let selected = app.engagement.planning_picker().selected().clone();
    app.open_model_picker();
    assert_eq!(app.config().model.as_deref(), Some("openai-codex:gpt-5.4"));

    let update = app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Esc,
        crossterm::event::KeyModifiers::NONE,
    ));

    assert!(update.effects.is_empty());
    assert_eq!(app.config().model.as_deref(), Some("openai-codex:gpt-5.4"));
    assert_eq!(app.input(), "held shell command");
    assert_eq!(app.router.answers().draft, draft);
    assert_eq!(app.target(), Some(target.path()));
    assert_eq!(app.router.setup().cursor(), 3);
    assert_eq!(app.router.setup().editor(), None);
    assert_eq!(app.engagement.planning_picker().selected(), &selected);
}

#[test]
fn model_picker_keeps_selection_identity_after_catalog_order_changes() {
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-5.5".to_string());
    let mut app = ShellApp::new(config, None);
    app.open_model_picker();
    app.config_mut().model = Some("anthropic:claude-opus-4-7".to_string());

    let update = app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Enter,
        crossterm::event::KeyModifiers::NONE,
    ));

    assert!(update.handled);
    assert_eq!(app.config().model.as_deref(), Some("openai:gpt-5.5"));
    assert!(
        matches!(update.effects.as_slice(), [ShellEffect::PersistGlobalModelSelection(selection)]
        if selection.model == "openai:gpt-5.5")
    );
}
