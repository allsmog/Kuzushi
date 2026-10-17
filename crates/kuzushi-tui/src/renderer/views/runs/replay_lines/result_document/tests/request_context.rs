use super::*;
use kuzushi_core::allowance::{AllowanceApprovalV1, AllowanceLimits};

fn allowance_fixture() -> (
    tempfile::TempDir,
    ShellApp,
    kuzushi_core::SpendLimiter,
    AllowanceApprovalV1,
) {
    let (root, mut app) = owned_reader();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let ledger = kuzushi_core::SpendLimiter::open(&workspace.findings_db_path()).unwrap();
    let approval = AllowanceApprovalV1 {
        schema_version: 1,
        investigation_id: "owned-reader".into(),
        expected_revision: 0,
        model: "selected:original".into(),
        limits: AllowanceLimits {
            max_provider_calls: 3,
            protected_review_calls: 1,
        },
        reason: "Offline reader test".into(),
        work_plan: None,
    };
    ledger.approve_allowance(&approval).unwrap();
    kuzushi_core::run_artifacts::write_run_artifact_json(root.path(), RUN, "input.json", "tool input", &json!({
        "paths":["app"],"allowanceRef":{"schemaVersion":1,"investigationId":"owned-reader","revision":1,"workId":"job"}
    })).unwrap();
    app.set_input("");
    press(&mut app, KeyCode::Char('r'));
    app.hydrate_active_view_blocking();
    (root, app, ledger, approval)
}

#[test]
fn explicit_refresh_reads_new_limits_without_losing_draft_scroll_page_or_origin() {
    let (_root, mut app, ledger, mut approval) = allowance_fixture();
    app.set_viewport(crate::TerminalViewport::new(80, 24));
    press(&mut app, KeyCode::Tab);
    app.set_input("held 修正");
    app.set_input_mode(InputMode::Navigate);
    press(&mut app, KeyCode::PageDown);
    let scroll = app.router.default_scroll().offset();
    let cursor = app.cursor();
    let receipt = app.router.replay().full_receipt();
    let before = crate::ui_view_models::replay_request_context(&app, RUN)
        .details
        .join("\n");
    assert!(before.contains("r1; 0/3 calls"), "{before}");
    approval.expected_revision = 1;
    approval.limits.max_provider_calls = 7;
    ledger.approve_allowance(&approval).unwrap();
    assert_eq!(
        crate::ui_view_models::replay_request_context(&app, RUN)
            .details
            .join("\n"),
        before
    );
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
    assert!(update.handled && update.effects.is_empty());
    assert_eq!(app.input(), "held 修正");
    assert_eq!(app.cursor(), cursor);
    assert_eq!(app.router.default_scroll().offset(), scroll);
    assert_eq!(app.router.replay().full_receipt(), receipt);
    app.hydrate_active_view_blocking();
    let after = crate::ui_view_models::replay_request_context(&app, RUN)
        .details
        .join("\n");
    assert!(
        after.contains("Run grant: owned-reader r1; 3 calls"),
        "{after}"
    );
    assert!(
        after.contains("Latest ledger at read: r2; 0/7 calls"),
        "{after}"
    );
    assert_eq!(
        ledger
            .allowance_snapshot("owned-reader")
            .unwrap()
            .committed_calls,
        0
    );
    assert_eq!(app.shell_view(), ShellView::Replay);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!(app.input(), "held 修正");
}

#[test]
fn refresh_letter_belongs_to_a_nonempty_prompt_draft() {
    let (_root, mut app, _ledger, _approval) = allowance_fixture();
    app.set_input("held");
    app.set_input_mode(InputMode::Prompt);
    assert!(!app.view_keybindings().iter().any(|binding| binding.action
        == crate::state_transitions::ViewHotkeyAction::ReplayRefreshContext));
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(app.input(), "heldr");
}

#[test]
fn requested_membership_and_call_limits_are_readable_in_each_viewport_and_plain_receipt() {
    let (_root, mut app, _ledger, _approval) = allowance_fixture();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let text = frame_text(&app, width, height);
        assert!(
            text.contains("calls 0/3 at read") || text.contains("At read r1: 0/3 calls"),
            "{width}: {text}"
        );
        let rows = crate::ui_view_models::rail_sections(&app, 32);
        assert!(!rows.iter().any(|section| section.title == "SESSION COST"));
    }
    let plain = crate::renderer::views::runs::replay_receipt_lines(&app, Rect::new(0, 0, 120, 36))
        .iter()
        .map(|row| row.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(plain.contains("Run grant: owned-reader r1; 3 calls"));
    assert!(plain.contains("does not establish discovery coverage"));
}
