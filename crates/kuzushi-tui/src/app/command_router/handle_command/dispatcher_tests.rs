use super::*;
use crate::app::owned_dispatcher_test_support::HeldDispatcher;

#[test]
fn held_dispatcher_does_not_queue_an_explicit_operator_run_until_study_exit() {
    let mut app = ShellApp::new(Default::default(), None);
    let mut held = HeldDispatcher::hold(&mut app);
    let update = held.reduce_submitted_line("run sbom-scan:scan");
    assert!(update.handled);
    assert!(held.steer_queue().is_empty());
    assert!(update
        .effects
        .iter()
        .any(|effect| matches!(effect, ShellEffect::PrepareRunTool(_))));
    assert!(held.has_running_work());
}

#[test]
fn held_dispatcher_does_not_hold_an_independent_ready_steer_queue() {
    let mut app = ShellApp::new(Default::default(), None);
    let mut held = HeldDispatcher::hold(&mut app);
    held.enqueue_steer_command("help");
    assert!(held.drain_idle_steer_queue());
    assert!(held.steer_queue().is_empty());
    assert!(held.has_running_work());
}
