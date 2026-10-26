use super::*;
use crate::app::owned_dispatcher_test_support::HeldDispatcher;

#[test]
fn held_dispatcher_does_not_block_explicit_local_tool_preparation() {
    let mut app = ShellApp::new(Default::default(), None);
    let mut held = HeldDispatcher::hold(&mut app);
    assert!(!held.tool_launch_blocked("sbom-scan:scan"));
    assert!(held.has_running_work());
    assert!(!held.directory().join("dispatcher-stop.json").exists());
}
