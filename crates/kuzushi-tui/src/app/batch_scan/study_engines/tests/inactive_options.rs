use super::*;

#[test]
fn unknown_engine_cannot_authorize_removing_saved_options() {
    let (_root, mut app) = fixture(false);
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .scan_input = Some(json!({
        "taskMode":"manual","tasks":["unknown-engine"],"semgrepJobs":2,
    }));
    app.open_study_engine_picker();
    let original = app.study_engine_picker().unwrap().input.clone();
    app.handle_study_engine_key(KeyCode::Char('c'));
    let picker = app.study_engine_picker().unwrap();
    assert_eq!(picker.input, original);
    assert!(picker
        .notice
        .as_ref()
        .unwrap()
        .contains("Options unchanged"));
}

#[test]
fn changing_from_agentic_to_native_keeps_model_context_and_global_reasoning() {
    let (_root, mut app) = fixture(true);
    {
        let input = app
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap()
            .study
            .scan_input
            .as_mut()
            .unwrap();
        input.as_object_mut().unwrap().remove("semgrepConfig");
        input["taskMode"] = json!("manual");
        input["tasks"] = json!(["agentic"]);
        input["agenticMaxModelTurns"] = json!(3);
        input["model"] = json!("openai-codex:gpt-5.5");
        input["thinkingLevel"] = json!("medium");
        input["mcps"] = json!(false);
    }
    app.open_study_engine_picker();
    focus(&mut app, "agentic");
    app.handle_study_engine_key(KeyCode::Enter);
    focus(&mut app, "secret-scan");
    app.handle_study_engine_key(KeyCode::Enter);
    app.handle_study_engine_key(KeyCode::Char('c'));
    app.handle_study_engine_key(KeyCode::Char('a'));
    let input = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .scan_input
        .as_ref()
        .unwrap();
    assert!(input.get("agenticMaxModelTurns").is_none());
    assert_eq!(input["model"], json!("openai-codex:gpt-5.5"));
    assert_eq!(input["thinkingLevel"], json!("medium"));
    assert!(input.get("scanScopeRef").is_some());
}

#[test]
fn inactive_engine_options_block_apply_without_losing_the_original_study() {
    let (_root, mut app) = fixture(true);
    let original = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .clone();
    focus(&mut app, "secret-scan");
    app.handle_study_engine_key(KeyCode::Enter);
    app.handle_study_engine_key(KeyCode::Char('a'));
    let picker = app
        .study_engine_picker()
        .expect("Keep incompatible choices editable");
    assert!(picker.notice.as_ref().unwrap().contains("semgrepConfig"));
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study,
        original
    );
}

#[test]
fn explicit_cleanup_is_local_and_cancel_restores_all_original_options() {
    let (_root, mut app) = fixture(true);
    app.set_input("held engine draft");
    let original = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .clone();
    let options = app.option_store().clone();
    focus(&mut app, "secret-scan");
    app.handle_study_engine_key(KeyCode::Enter);
    assert!(crate::ui_view_models::study_engines::engine_apply_controls(&app).contains("c clear"));
    app.handle_study_engine_key(KeyCode::Char('c'));
    assert!(app
        .study_engine_picker()
        .unwrap()
        .input
        .get("semgrepConfig")
        .is_none());
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study,
        original
    );
    app.handle_study_engine_key(KeyCode::Esc);
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study,
        original
    );
    assert_eq!(app.option_store(), &options);
    assert_eq!(app.input(), "held engine draft");
}

#[test]
fn applying_cleanup_preserves_scope_limits_and_global_engine_settings() {
    use kuzushi_core::{OptionScope, OptionTarget};
    let (_root, mut app) = fixture(true);
    {
        let config = app
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap();
        config.study.max_provider_calls = Some(12);
        config.study.protected_review_calls = Some(4);
        config.study.max_job_attempts = 2;
    }
    app.option_store_mut().set_value(
        OptionScope::Global,
        OptionTarget::Tool("sast:scan".into()),
        "semgrepConfig",
        json!(["global-rules.yml"]),
    );
    let options = app.option_store().clone();
    let original = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .clone();
    focus(&mut app, "secret-scan");
    app.handle_study_engine_key(KeyCode::Enter);
    app.handle_study_engine_key(KeyCode::Char('c'));
    app.handle_study_engine_key(KeyCode::Char('a'));
    assert!(app.study_engine_picker().is_none());
    let current = &app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study;
    let input = current.scan_input.as_ref().unwrap();
    assert!(input.get("semgrepConfig").is_none());
    assert_eq!(input["tasks"], json!(["secret-scan"]));
    for key in ["scanScopeRef", "threatModelRef"] {
        assert_eq!(input[key], original.scan_input.as_ref().unwrap()[key]);
    }
    assert_eq!(current.investigation_id, original.investigation_id);
    assert_eq!(current.max_provider_calls, original.max_provider_calls);
    assert_eq!(
        current.protected_review_calls,
        original.protected_review_calls
    );
    assert_eq!(current.max_job_attempts, original.max_job_attempts);
    assert_eq!(app.option_store(), &options);
}

#[test]
fn selecting_the_original_engine_keeps_its_custom_options_without_cleanup() {
    let (_root, mut app) = fixture(true);
    focus(&mut app, "semgrep");
    app.handle_study_engine_key(KeyCode::Enter);
    let before = app.study_engine_picker().unwrap().clone();
    app.handle_study_engine_key(KeyCode::Char('c'));
    assert_eq!(app.study_engine_picker().unwrap(), &before);
    app.handle_study_engine_key(KeyCode::Char('a'));
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .scan_input
            .as_ref()
            .unwrap()["semgrepConfig"],
        json!(["operator-rules.yml"])
    );
}
