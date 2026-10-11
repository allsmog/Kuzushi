use super::*;

fn reference() -> ThreatModelRef {
    serde_json::from_value(
        json!({"modelId":"test-context", "revisionId":"test-revision",
        "sha256":format!("sha256:{}", "a".repeat(64))}),
    )
    .unwrap()
}

fn saved_result(app: &mut ShellApp, reference: &ThreatModelRef) -> StudyContextGeneration {
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.max_provider_calls = Some(10);
    config.study.protected_review_calls = Some(2);
    config.study.scan_input = Some(json!({"tasks":["secret-scan"]}));
    let generation = config.context_generation.as_mut().unwrap();
    generation.generated = Some(reference.clone());
    generation.campaign_id = Some("existing-context-job".into());
    generation.context_input = json!({"maxElements":10});
    generation.show_options = true;
    generation.scroll = 7;
    generation.clone()
}

#[test]
fn exact_context_inspection_returns_to_the_original_result_without_selecting_context() {
    let (_root, mut app) = fixture();
    let reference = reference();
    let original = saved_result(&mut app, &reference);
    app.set_input("unsent operator draft");
    app.set_cursor(5);
    let update = app.inspect_generated_context(reference.clone());
    assert!(matches!(
        update.effects.as_slice(),
        [ShellEffect::PrepareRunTool(_)]
    ));
    assert!(app.context_generation().is_none());
    assert_eq!(
        app.study_context_picker().unwrap().selected.as_ref(),
        Some(&reference)
    );
    app.handle_study_context_key(KeyCode::Esc);
    assert_eq!(app.context_generation(), Some(&original));
    assert!(app.study_context_picker().is_none());
    let study = &app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study;
    assert_eq!(study.scan_input, Some(json!({"tasks":["secret-scan"]})));
    assert_eq!(
        (study.max_provider_calls, study.protected_review_calls),
        (Some(10), Some(2))
    );
    assert_eq!((app.input(), app.cursor()), ("unsent operator draft", 5));
}

#[test]
fn explicit_context_selection_leaves_inspection_for_the_study_form() {
    let (_root, mut app) = fixture();
    let reference = reference();
    saved_result(&mut app, &reference);
    app.inspect_generated_context(reference.clone());
    app.cache_study_context_preview(
        &json!({"resolvedFrom":"exact-context","target":app.target(),"modelRef":reference,
        "document":{"dfd":{"nodes":[],"flows":[],"trustBoundaries":[]}}}),
    );
    assert!(app.study_context_picker().unwrap().preview.is_some());
    app.handle_study_context_key(KeyCode::Char('a'));
    assert!(app.context_generation().is_none());
    assert!(app.study_context_picker().is_none());
    let study = &app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study;
    assert_eq!(
        study.scan_input.as_ref().unwrap()["threatModelRef"],
        json!(reference)
    );
}
