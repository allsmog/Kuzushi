use super::*;
use crate::ui_view_models::study_context::context_detail_lines;

fn save_goal(root: &std::path::Path, previous: u32, text: &str) -> Value {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    kuzushi_core::ModuleRegistry::with_v2_builtins()
        .execute_tool(
            "campaign:brief",
            json!({"mode":"save","expectedRevision":previous,"text":text}),
            &ctx,
        )
        .unwrap()["data"]["brief"]
        .clone()
}

#[test]
fn inspected_summary_and_raw_readers_keep_old_goal_and_disclose_unavailable_guidance() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("main.rs"),
        "// Owned inert reader fixture.\n",
    )
    .unwrap();
    let first = save_goal(root.path(), 0, "Original priorities\n東京 owner questions.");
    let document = json!({"version":"1","methodology":"stride","title":"Historical imported context",
        "systemContext":"Labeled imported provenance. Model use unverified.",
        "dfd":{"nodes":[{"id":"greeting","name":"Greeting","type":"process","trustZone":"internal"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{},
        "provenance":{"operatorIntent":{"schemaVersion":1,"reference":first["reference"],
            "textBytes":first["document"]["text"].as_str().unwrap().len(),"purpose":"architecture priorities and open questions",
            "sourceEvidence":false,"findingAuthority":false}}});
    let selected = commit_document(root.path(), "Historical context", &document);
    let active = commit(root.path(), "Other active context");
    save_goal(root.path(), 1, "Latest goal must not be substituted");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.open_batch_scan_config(None);
    app.hydrate_all_view_data_for_test();
    app.open_study_context_picker();
    app.handle_study_context_key(KeyCode::Up);
    assert_eq!(
        app.study_context_picker().unwrap().selected,
        Some(selected.clone())
    );
    let read = inspect(&app, root.path(), &selected);
    app.cache_tool_snapshot("threat-model:read", &read);
    for view in [
        crate::app::StudyContextTextView::Summary,
        crate::app::StudyContextTextView::Document,
    ] {
        app.router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap()
            .context_picker
            .as_mut()
            .unwrap()
            .text_view = view;
        let lines = context_detail_lines(&app, 120).join("\n");
        assert!(lines.contains("Original priorities"));
        assert!(lines.contains("東京 owner questions."));
        assert!(lines.contains("Model use is not independently verified"));
        assert!(!lines.contains("Latest goal must not be substituted"));
        assert!(
            lines.find("RECORDED GOAL GUIDANCE").unwrap()
                < lines.find("Historical imported context").unwrap()
        );
    }
    std::fs::remove_file(
        root.path()
            .join(".kuzushi/v3/investigation-briefs/repository/revisions/1.json"),
    )
    .unwrap();
    let missing = inspect(&app, root.path(), &selected);
    app.cache_tool_snapshot("threat-model:read", &missing);
    let lines = context_detail_lines(&app, 40).join("\n");
    assert!(lines.contains("unavailable"));
    assert!(!lines.contains("Original priorities"));
    assert_eq!(
        app.study_context_picker()
            .unwrap()
            .preview
            .as_ref()
            .unwrap()
            .document,
        read["data"]["document"]
    );
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        active
    );
}
