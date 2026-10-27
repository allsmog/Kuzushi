use super::*;
use crate::{AdvisoryState, BudgetHalt, Notice, NoticeSeverity, ThrottleAdvisory};
use std::time::Instant;

#[test]
fn throttle_banner_model_copies_operator_visible_advisory_text() {
    let throttle = ThrottleAdvisory {
        source: "anthropic".to_string(),
        message: "429 retry-after 14s".to_string(),
        since: Instant::now(),
    };

    let model = ThrottleBannerModel::from_advisory(&throttle);

    assert_eq!(model.source, "anthropic");
    assert_eq!(model.message, "429 retry-after 14s");
}

#[test]
fn cost_cap_halt_model_formats_spend_against_limit() {
    let halt = BudgetHalt {
        limit_usd: 1.0,
        spent_usd: 1.5,
    };

    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.session_mut().set_session_cost_usd_for_test(1.5);
    app.advisory_mut().budget_halt = Some(halt);
    let model = cost_cap_halt_model(&app).unwrap();

    assert_eq!(model.header, "■ COST CAP HALT · $1.50 / cap $1.0000");
    assert!(model.compact.contains("Esc inspect"));
}

#[cfg(unix)]
#[test]
fn held_dispatcher_budget_actions_keep_session_and_study_stop_distinct() {
    use crate::app::owned_dispatcher_test_support::HeldDispatcher;
    use crate::ui_view_models::footer_keybindings;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.session_mut().set_session_budget_usd(Some(1.0));
    app.record_cost(2.0);
    let mut held = HeldDispatcher::hold_with_campaign_budget(&mut app, Some(5.0));
    let model = cost_cap_halt_model(&held).unwrap();
    assert!(model.header.contains("SESSION COST CAP HALT"));
    assert!(model.actions.contains("Study allowance is separate"));
    assert!(!model.actions.contains("no allowance"));
    assert!(model.compact.contains("a local"));
    assert!(footer_keybindings(&held)
        .iter()
        .any(|binding| binding.key == "a" && binding.label == "stop session work"));
    held.abort_for_budget();
    assert!(!held.directory().join("dispatcher-stop.json").exists());
    assert!(held.is_budget_halted());
    held.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(cost_cap_halt_model(&held)
        .unwrap()
        .actions
        .contains("cost or report"));

    let update = held.reduce_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(matches!(
        update.effects.as_slice(),
        [crate::app::ShellEffect::CancelActiveJobs]
    ));
    assert!(held.request_active_abort());
    assert!(held.directory().join("dispatcher-stop.json").exists());
    assert!(held.is_budget_halted());
}

#[cfg(unix)]
fn held_study_halt_actions(budget_usd: Option<f64>) -> (String, String) {
    use crate::app::owned_dispatcher_test_support::HeldDispatcher;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.session_mut().set_session_budget_usd(Some(1.0));
    app.record_cost(2.0);
    let mut held = HeldDispatcher::hold_with_campaign_budget(&mut app, budget_usd);
    let halted = cost_cap_halt_model(&held).unwrap().actions.to_string();
    held.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    let acknowledged = cost_cap_halt_model(&held).unwrap().actions.to_string();
    (halted, acknowledged)
}

#[cfg(unix)]
#[test]
fn held_study_without_allowance_is_disclosed_as_unbounded_by_the_session_cap() {
    let (halted, acknowledged) = held_study_halt_actions(None);
    assert!(halted.starts_with("Study has no allowance set and is not bounded by the session cap."));
    assert!(acknowledged
        .contains("the study has no allowance set and is not bounded by the session cap"));
    assert!(
        !halted.contains("allowance is separate") && !acknowledged.contains("its own allowance")
    );
}

#[cfg(unix)]
#[test]
fn held_study_with_allowance_keeps_the_separate_allowance_wording() {
    let (halted, acknowledged) = held_study_halt_actions(Some(5.0));
    assert!(halted.starts_with("Study allowance is separate."));
    assert!(acknowledged.contains("the study uses its own allowance"));
}

#[cfg(unix)]
#[test]
fn held_study_with_unreadable_campaign_state_reports_an_unknown_allowance() {
    use crate::app::owned_dispatcher_test_support::HeldDispatcher;
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.session_mut().set_session_budget_usd(Some(1.0));
    app.record_cost(2.0);
    let held = HeldDispatcher::hold(&mut app);
    let actions = cost_cap_halt_model(&held).unwrap().actions;
    assert!(actions.starts_with("Study allowance could not be determined."));
}

#[test]
fn halt_card_yields_to_budget_editing_and_exit_without_clearing_the_guard() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.session_mut().set_session_budget_usd(Some(1.0));
    app.record_cost(2.0);
    app.set_shell_view(crate::ShellView::Setup);
    app.router.setup_mut().begin_budget_edit(Some(1.0));
    assert!(cost_cap_halt_model(&app).is_none());
    assert!(app.is_budget_halted());
    app.set_shell_view(crate::ShellView::QuitConfirm);
    assert!(cost_cap_halt_model(&app).is_none());
    assert!(app.is_budget_halted());
}

#[test]
fn advisory_models_are_absent_without_active_advisories() {
    let app = ShellApp::new(kuzushi_core::V2Config::default(), None);

    assert!(throttle_banner_model(&app).is_none());
    assert!(cost_cap_halt_model(&app).is_none());
    assert!(notice_banner_model(&app).is_none());
}

#[test]
fn notice_banner_model_copies_source_message_and_severity() {
    let notice = Notice {
        source: "tool".to_string(),
        message: "semgrep:scan failed".to_string(),
        severity: NoticeSeverity::Error,
        since: Instant::now(),
    };

    let model = NoticeBannerModel::from_notice(&notice, true);

    assert_eq!(model.source, "tool");
    assert_eq!(model.message, "semgrep:scan failed");
    assert_eq!(model.severity, NoticeSeverity::Error);
    assert!(model.dismiss_on_escape);
}

fn owned_confirmation() -> crate::PendingConfirm {
    crate::PendingConfirm {
        kind: crate::ConfirmKind::DescriptorEffect,
        tool: "taint-iris-next:catalog-accept".into(),
        target: "owned target".into(),
        rationale: None,
        allowlist: None,
        actor: None,
        remembered: false,
    }
}

#[test]
fn older_notice_yields_to_confirmation_without_losing_history_or_cancel_recovery() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_error_notice("tool", "Owned previous source drift");
    let original = app.advisory().notice.clone();
    app.request_confirm(owned_confirmation());
    assert!(notice_banner_model(&app).is_none());
    assert_eq!(app.advisory().notice, original);
    assert!(!app.notice_captures_escape());
    app.resolve_confirm(false, false).unwrap();
    assert_eq!(
        notice_banner_model(&app).unwrap().message,
        "Owned previous source drift"
    );
    assert!(app.notice_captures_escape());
}

#[test]
fn a_new_error_during_confirmation_stays_visible_without_claiming_escape() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.request_confirm(owned_confirmation());
    app.set_error_notice("storage", "Owned current persistence failure");
    let notice = notice_banner_model(&app).unwrap();
    assert_eq!(notice.message, "Owned current persistence failure");
    assert!(!notice.dismiss_on_escape);
}
