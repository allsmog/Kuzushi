use super::*;
use crate::app::owned_dispatcher_test_support::HeldDispatcher;

fn budget_abort_log(budget_usd: Option<f64>) -> String {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.session_mut().set_session_budget_usd(Some(1.0));
    app.record_cost(2.0);
    let mut held = HeldDispatcher::hold_with_campaign_budget(&mut app, budget_usd);
    held.abort_for_budget();
    let line = held.log_lines().last().unwrap().body.clone();
    assert!(!held.directory().join("dispatcher-stop.json").exists());
    line
}

#[test]
fn budget_abort_discloses_a_study_without_an_allowance() {
    let line = budget_abort_log(None);
    assert!(line.contains(
        "The owned study has no allowance set and is not bounded by the session cap; Ctrl+C requests Stop."
    ));
    assert!(!line.contains("has its own allowance"));
}

#[test]
fn budget_abort_keeps_the_allowance_note_when_the_study_has_one() {
    let line = budget_abort_log(Some(5.0));
    assert!(line.contains("The owned study has its own allowance; Ctrl+C requests Stop."));
}

#[test]
fn budget_abort_without_an_owned_study_makes_no_study_claim() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.abort_for_budget();
    let line = &app.log_lines().last().unwrap().body;
    assert!(line.ends_with("session budget remains halted."));
}
