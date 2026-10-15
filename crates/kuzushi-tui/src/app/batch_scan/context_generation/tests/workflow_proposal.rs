use super::*;

fn recorded_proposal(app: &mut ShellApp, root: &std::path::Path) {
    app.plan_workflow_proposal("Inspect owned source", None)
        .unwrap();
    let prepared = prepare(app, root);
    app.cache_tool_snapshot("campaign:context-study", &prepared);
    let receipt = app.context_generation().unwrap().receipt.clone().unwrap();
    let record = kuzushi_core::run_artifacts::ToolRunRecord::new(
        root,
        "labeled-proposal-result",
        "tool",
        "planner:propose",
    );
    kuzushi_core::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        &receipt.input,
        Some(receipt.model.clone()),
        None,
        vec![],
    )
    .unwrap();
    let result = json!({"ok":true,"status":"completed","summary":"Labeled offline proposal", "data":{"schemaVersion":1,"model":receipt.model,"goal":receipt.input["goal"],"phase":receipt.input["phase"],"proposal":{"summary":"Inspect owned context", "changes":[{"kind":"note","text":"Labeled unapplied note"}],"unsupported":[]}}});
    kuzushi_core::run_artifacts::try_record_tool_run_complete(record, &result).unwrap();
    let path = root
        .join(".kuzushi/v3/campaigns")
        .join(&receipt.campaign_id)
        .join("queue.json");
    std::fs::write(path, serde_json::to_vec(&json!({"jobs":{"context-001":{"state":"completed","runId":"labeled-proposal-result"}}})).unwrap()).unwrap();
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .context_generation
        .as_mut()
        .unwrap()
        .refresh_result(root);
    app.inspect_workflow_proposal();
    assert!(app.engagement.pending_plan().is_some());
}

#[test]
fn source_drift_blocks_pending_proposal_actions_without_discarding_the_draft() {
    let (root, mut app) = fixture();
    recorded_proposal(&mut app, root.path());
    std::fs::write(
        root.path().join("main.rs"),
        "// Owned changed source. Never executed.\n",
    )
    .unwrap();
    assert!(app.reduce_apply_pending_plan().is_empty());
    assert!(app.engagement.pending_plan().is_some());
    assert!(!app.has_running_work());
    assert!(!app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "plan-note"));
}

#[test]
fn current_proposal_note_applies_only_after_the_explicit_action_decision() {
    let (root, mut app) = fixture();
    recorded_proposal(&mut app, root.path());
    assert!(!app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "plan-note"));
    assert!(app.reduce_apply_pending_plan().is_empty());
    assert!(app.engagement.pending_plan().is_none());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.prefix == "plan-note" && line.body == "Labeled unapplied note"));
}

#[test]
fn model_drift_blocks_pending_proposal_actions_without_discarding_the_draft() {
    let (root, mut app) = fixture();
    recorded_proposal(&mut app, root.path());
    app.config_mut().model = Some("openai:operator-changed-model".into());
    assert!(app.reduce_apply_pending_plan().is_empty());
    assert!(app.engagement.pending_plan().is_some());
    assert!(!app.has_running_work());
}

#[test]
fn partial_workflow_proposal_keeps_the_failure_visible_without_repair() {
    let (_root, mut app) = fixture();
    app.plan_workflow_proposal("Inspect owned source", None)
        .unwrap();
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .context_generation
        .as_mut()
        .unwrap()
        .result_error = Some("Malformed proposal output".into());
    let lines = crate::ui_view_models::context_generation::generation_lines(&app, 40).join(" ");
    assert!(lines.contains("Malformed proposal output"));
    assert!(lines.contains("no repair request was made"));
    assert!(!lines.contains("Source excerpts: at most null"));
    assert!(!app.has_running_work());
    assert!(app.engagement.pending_plan().is_none());
}

#[test]
fn workflow_proposal_needs_a_frozen_job_and_separate_approval() {
    let (root, mut app) = fixture();
    app.plan_workflow_proposal(
        "Inspect owned source",
        Some(crate::app::WorkflowPhase::Scan),
    )
    .unwrap();
    let result = prepare(&mut app, root.path());
    app.cache_tool_snapshot("campaign:context-study", &result);
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    let generation = config.context_generation.as_ref().unwrap();
    assert_eq!(generation.receipt.as_ref().unwrap().job_count(), 1);
    assert_eq!(generation.context_input["phase"], "scan");
    assert!(!generation.approved(config));
    assert!(!app.has_running_work());
    assert!(app.engagement.pending_plan().is_none());
    assert!(context_action_input(config).is_err());
}

#[test]
fn workflow_goal_paste_and_escape_preserve_the_draft_cursor_and_origin() {
    let (_root, mut app) = fixture();
    app.close_batch_config();
    app.set_shell_view(ShellView::Report);
    app.set_input_mode(InputMode::Prompt);
    app.set_input("held composer");
    app.set_cursor(4);
    app.plan_workflow_proposal("goal", None).unwrap();
    app.handle_context_generation_key(KeyCode::Char('G'));
    assert!(app.capture_regeneration_guidance_paste("\nowned α"));
    app.handle_regeneration_guidance_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    let text = app
        .context_generation()
        .unwrap()
        .guidance_editor
        .as_ref()
        .unwrap()
        .text()
        .to_string();
    app.handle_regeneration_guidance_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    app.handle_context_generation_key(KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!(app.input(), "held composer");
    assert_eq!(app.cursor(), 4);
    assert!(app.reduce_planner_start("").is_empty());
    let generation = app.context_generation().unwrap();
    assert_eq!(generation.guidance_editor.as_ref().unwrap().text(), text);
    assert!(generation.receipt.is_none());
    app.handle_context_generation_key(KeyCode::Enter);
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .notice
        .as_deref()
        .unwrap()
        .contains("draft is kept"));
}

#[test]
fn workflow_goal_limit_matches_the_declared_byte_limit_and_new_draft_keeps_phase() {
    let (_root, mut app) = fixture();
    app.plan_workflow_proposal("goal", Some(crate::app::WorkflowPhase::Review))
        .unwrap();
    app.handle_context_generation_key(KeyCode::Char('G'));
    assert!(app.capture_regeneration_guidance_paste(&"x".repeat(4092)));
    assert_eq!(
        app.context_generation()
            .unwrap()
            .guidance_editor
            .as_ref()
            .unwrap()
            .text()
            .len(),
        4096
    );
    app.capture_regeneration_guidance_paste("α");
    assert_eq!(
        app.context_generation()
            .unwrap()
            .guidance_editor
            .as_ref()
            .unwrap()
            .text()
            .len(),
        4096
    );
    app.handle_regeneration_guidance_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
    app.handle_context_generation_key(KeyCode::Char('n'));
    let generation = app.context_generation().unwrap();
    assert!(generation.is_workflow_proposal());
    assert_eq!(generation.context_input["phase"], "review");
    assert_eq!(
        generation.context_input["goal"].as_str().unwrap().len(),
        4096
    );
    assert!(generation.receipt.is_none());
}

#[test]
fn workflow_proposal_views_expose_model_bounds_and_next_action_at_every_size() {
    let (_root, mut app) = fixture();
    app.plan_workflow_proposal("Inspect owned source", None)
        .unwrap();
    for (columns, rows) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        let mut terminal = Terminal::new(TestBackend::new(columns, rows)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("WORKFLOW PROPOSAL PLAN"), "{columns}x{rows}");
        let lines =
            crate::ui_view_models::context_generation::generation_lines(&app, columns as usize)
                .join(" ");
        assert!(lines.contains("one proposal job"));
        assert!(lines.contains("Dollar consumption is uncertain"));
        assert!(lines.contains("openai-codex:gpt-5.5"));
    }
}
