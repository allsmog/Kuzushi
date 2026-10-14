use crate::app::{
    AbortReason, BatchScanConfigRow, ShellApp, ShellEffect, ToolEvent, NOTICE_STALE_AFTER,
};
use crate::ui_view_models::study_config::study_projection;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::V2Config;
use std::time::{Duration, Instant};

fn failed_study() -> (tempfile::TempDir, ShellApp) {
    let target = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.path().to_path_buf()));
    app.open_batch_scan_config(None);
    app.set_input("retained\noperator draft");
    app.set_cursor(4);
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.cursor = 3;
    config.study.max_provider_calls = Some(8);
    config.study.protected_review_calls = Some(2);
    app.apply_tool_event(ToolEvent::Failed {
        tool_name: "campaign:study".into(),
        error: "Plan input inspection failed: owned fixture".into(),
    });
    app.advisory_mut().notice.as_mut().unwrap().since =
        Instant::now() - (NOTICE_STALE_AFTER + Duration::from_secs(1));
    app.tick();
    (target, app)
}

#[test]
fn expired_banner_keeps_preparation_failure_and_blocks_launch_until_dismissal() {
    let (_target, mut app) = failed_study();
    assert!(!app.notice_captures_escape());
    assert!(app.study_notice_captures_escape());
    let projection = study_projection(&app).unwrap();
    assert!(projection
        .notice
        .unwrap()
        .contains("Plan input inspection failed"));
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::NONE));
    assert!(update.effects.is_empty());
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .cursor,
        3
    );
}

#[test]
fn dismissing_retained_failure_preserves_limits_selection_and_composer() {
    let (_target, mut app) = failed_study();
    let before = app.router.campaign().batch_scan_config.clone().unwrap();
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    let after = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(after.study.preparation_error.is_none());
    assert_eq!(after.cursor, before.cursor);
    assert_eq!(after.trials, before.trials);
    assert_eq!(after.study.investigation_id, before.study.investigation_id);
    assert_eq!(after.study.max_provider_calls, Some(8));
    assert_eq!(after.study.protected_review_calls, Some(2));
    assert_eq!(after.selected_row(), BatchScanConfigRow::Context);
    assert_eq!((app.input(), app.cursor()), ("retained\noperator draft", 4));
    assert!(!app.study_notice_captures_escape());
}

#[test]
fn explicit_retry_clears_retained_error_and_only_prepares_a_new_dispatch() {
    let (target, mut app) = failed_study();
    app.clear_notice();
    let update = app.launch_batch_from_config();
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("expected prepared dispatch");
    };
    assert_eq!(request.tool_name, "campaign:study");
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(config.study.preparation_error.is_none());
    assert!(config.notice.as_ref().unwrap().starts_with("Preparing"));
    assert!(!target.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn unrelated_failure_does_not_become_a_study_preparation_error() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.study_preparation_failed("campaign:study", "no open form");
    assert!(!app.study_notice_captures_escape());
    let target = tempfile::tempdir().unwrap();
    app.set_target(Some(target.path().to_path_buf()));
    app.open_batch_scan_config(None);
    app.apply_tool_event(ToolEvent::Failed {
        tool_name: "campaign:allowance".into(),
        error: "Labeled unrelated failure".into(),
    });
    app.clear_notice();
    assert!(!app.study_notice_captures_escape());
}

#[test]
fn canceled_preparation_keeps_its_terminal_reason_after_notice_expiry() {
    let (_target, mut app) = failed_study();
    app.clear_study_preparation_error();
    app.request_tool_abort_flag(AbortReason::Operator);
    app.apply_tool_event(ToolEvent::Failed {
        tool_name: "campaign:study".into(),
        error: "Owned preparation canceled".into(),
    });
    app.clear_notice();
    let projection = study_projection(&app).unwrap();
    let message = projection.notice.unwrap();
    assert!(message.contains("Preparation stopped (operator cancel)"));
    assert!(!message.contains("Preparing the selected action"));
}
