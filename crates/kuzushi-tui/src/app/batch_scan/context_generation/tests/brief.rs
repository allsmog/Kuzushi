use super::*;

#[test]
fn goal_guidance_is_explicit_and_frozen_text_survives_later_edits() {
    let (root, mut app) = fixture();
    app.set_input("kept composer draft");
    app.handle_context_generation_key(KeyCode::Char('g'));
    assert!(!app.context_generation().unwrap().use_brief_guidance);
    let first = dispatch(
        &app,
        root.path(),
        "campaign:brief",
        json!({"mode":"save","expectedRevision":0,"text":"Owned goal\nKeep source and priority separate."}),
        false,
    );
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .brief = serde_json::from_value(first["data"]["brief"].clone()).unwrap();
    app.handle_context_generation_key(KeyCode::Char('g'));
    assert!(app.context_generation().unwrap().use_brief_guidance);
    let planned = prepare(&mut app, root.path());
    app.cache_tool_snapshot("campaign:context-study", &planned);
    dispatch(
        &app,
        root.path(),
        "campaign:brief",
        json!({"mode":"save","expectedRevision":1,"text":"Later goal must not replace frozen input"}),
        false,
    );
    app.handle_context_generation_key(KeyCode::Char('g'));
    assert!(app.context_generation().unwrap().use_brief_guidance);
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .context_generation
        .as_mut()
        .unwrap()
        .scroll = 5;
    app.handle_context_generation_key(KeyCode::Char('b'));
    let lines = crate::ui_view_models::context_generation::generation_lines(&app, 80).join("\n");
    assert!(lines.contains("GOAL IN THIS CONTEXT PLAN"));
    assert!(lines.contains("exact revision 1"));
    assert!(lines.contains("Owned goal"));
    assert!(!lines.contains("Later goal must not replace"));
    assert!(app.capture_bound_brief_paste());
    app.handle_context_generation_key(KeyCode::Enter);
    assert!(app.context_generation().unwrap().show_brief_guidance);
    app.handle_context_generation_key(KeyCode::Esc);
    assert_eq!(app.context_generation().unwrap().scroll, 5);
    assert_eq!(app.input(), "kept composer draft");
    assert!(!root
        .path()
        .join(".kuzushi/v3/campaigns")
        .read_dir()
        .unwrap()
        .any(|entry| entry.unwrap().path().join("queue.json").exists()));
}
