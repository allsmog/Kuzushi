use super::*;
use kuzushi_core::workflow_attempts::{
    PhaseAttemptCompleted, PhaseAttemptLedger, PhaseAttemptOutcome, PhaseTargetSnapshot,
};
use serde_json::json;

fn published_context_map() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "fn main() {}\n").unwrap();
    let config = V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let draft = prepare_context_draft(root.path(), &config);
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(root.path().into()));
    app.restore_context_generation(root.path(), "map-draft");
    let completed = persist_context_map(root.path());
    app.cache_context_map_result(&json!({"campaignId":"map-draft",
        "planSha256":draft["data"]["planSha256"],"attemptId":completed.attempt_id}));
    assert_eq!(
        app.engagement
            .unresolved_phase_attempt(WorkflowPhase::Map)
            .unwrap()
            .completed
            .attempt_id,
        completed.attempt_id,
        "The handoff cache must refresh real durable Map history before navigation"
    );
    set_handoff_receipt(&mut app, root.path());
    (root, app)
}

fn persist_context_map(root: &std::path::Path) -> PhaseAttemptCompleted {
    crate::test_support::record_indexed_run(
        root,
        "context-source",
        "threat-model:build",
        json!({"ok":true,"data":{"snapshot":{"filesIndexed":1}}}),
    );
    crate::test_support::append_typed_attempt(
        root,
        WorkflowPhase::Map,
        "context-source",
        PhaseAttemptOutcome::Completed,
    )
}

fn prepare_context_draft(root: &std::path::Path, config: &V2Config) -> serde_json::Value {
    let workspace = kuzushi_core::WorkspaceTarget::new(root).unwrap();
    let registry = kuzushi_core::ModuleRegistry::with_v2_builtins();
    let ctx = kuzushi_core::ToolExecutionContext {
        config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    registry
        .execute_tool(
            "campaign:context-study",
            json!({
                "campaignId":"map-draft","investigationId":"investigation","contextInput":{}
            }),
            &ctx,
        )
        .unwrap()
}

fn set_handoff_receipt(app: &mut ShellApp, root: &std::path::Path) {
    crate::test_support::record_indexed_run(
        root,
        "context-handoff",
        "campaign:context-map",
        json!({"ok":true,"status":"completed","data":{}}),
    );
    let mut session = app.capture_run_focus_origin(ActivitySession::new("context-handoff"));
    session.mark_run_focus_terminal_pending("completed");
    session
        .run_focus_receipt
        .as_mut()
        .unwrap()
        .result_summaries
        .push(
            kuzushi_core::run_artifacts::load_run_result_summary(root, "context-handoff")
                .unwrap()
                .unwrap(),
        );
    app.set_activity(Some(session));
}

fn present(app: &mut ShellApp) {
    let origin = app.activity().unwrap().run_focus_origin;
    app.open_completed_run_destination(origin, None);
}

#[test]
fn context_map_result_opens_map_for_explicit_acceptance_and_arms_empty_input() {
    let (_root, mut app) = published_context_map();
    app.set_input_mode(InputMode::Prompt);
    present(&mut app);
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(
        crate::ui_view_models::active_workbench_page(&app),
        WorkbenchPage::Map
    );
    assert_eq!(app.input_mode(), InputMode::Navigate);
    assert!(app
        .engagement
        .unresolved_phase_attempt(WorkflowPhase::Map)
        .is_some());
    assert!(app
        .engagement
        .selected_phase_attempt(WorkflowPhase::Map)
        .is_none());
    assert!(!app.has_running_work());
}

#[test]
fn context_map_result_preserves_operator_typing_ownership() {
    let (_root, mut app) = published_context_map();
    app.set_input_mode(InputMode::Prompt);
    app.set_input("unfinished\noperator note");
    app.set_cursor(4);
    present(&mut app);
    assert_eq!(app.input_mode(), InputMode::Prompt);
    assert_eq!(
        (app.input(), app.cursor()),
        ("unfinished\noperator note", 4)
    );
    app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('u'),
        crossterm::event::KeyModifiers::NONE,
    ));
    assert!(app
        .engagement
        .selected_phase_attempt(WorkflowPhase::Map)
        .is_none());
}

#[test]
fn context_map_result_requires_its_own_successful_receipt_and_current_healthy_attempt() {
    for changed in ["origin", "receipt", "tool", "status", "attempt", "degraded"] {
        let (_root, mut app) = published_context_map();
        change_handoff_guard(&mut app, changed);
        present(&mut app);
        assert_eq!(app.shell_view(), ShellView::Campaign, "{changed}");
        assert!(app
            .engagement
            .selected_phase_attempt(WorkflowPhase::Map)
            .is_none());
    }
}

fn change_handoff_guard(app: &mut ShellApp, changed: &str) {
    match changed {
        "origin" => {
            app.activity_mut()
                .unwrap()
                .run_focus_origin
                .as_mut()
                .unwrap()
                .view = ShellView::Report
        }
        "receipt" => app.activity_mut().unwrap().run_focus_receipt = None,
        "tool" | "status" => change_handoff_summary(app, changed),
        "attempt" => {
            app.cache_context_map_result(&json!({"campaignId":"map-draft",
                    "planSha256":app.context_generation().unwrap().receipt.as_ref().unwrap().plan_sha256,"attemptId":"other"}));
        }
        _ => {
            let snapshot = PhaseTargetSnapshot::capture(app.target().unwrap());
            app.engagement.set_phase_attempt_projection_health(
                Some(snapshot),
                PhaseAttemptLedger::default(),
                true,
            );
        }
    };
}

fn change_handoff_summary(app: &mut ShellApp, changed: &str) {
    let summary = &mut app
        .activity_mut()
        .unwrap()
        .run_focus_receipt
        .as_mut()
        .unwrap()
        .result_summaries[0];
    if changed == "tool" {
        summary.tool = "threat-model:read".into();
    } else {
        summary.status = "failed".into();
    }
}
