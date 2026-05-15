use super::*;
use crate::{LiveActivity, LiveActivityPhase};
use kuzushi_core::V2Config;
use std::path::PathBuf;

#[test]
fn active_stage_is_absent_when_idle() {
    let app = ShellApp::new(V2Config::default(), None);

    assert_eq!(active_stage_label(&app), None);
}

#[test]
fn active_stage_reports_scan_running_and_abort() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.scan = Some(scan_panel(true, false));

    assert_eq!(active_stage_label(&app), Some("searching"));

    app.scan = Some(scan_panel(true, true));
    assert_eq!(active_stage_label(&app), Some("aborting"));
}

#[test]
fn active_stage_prefers_live_activity_over_scan() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.scan = Some(scan_panel(true, false));
    app.live_activity = Some(LiveActivity::new(
        LiveActivityPhase::WritingArtifact,
        "report",
        "writing",
    ));

    assert_eq!(active_stage_label(&app), Some("writing artifact"));
}

fn scan_panel(running: bool, abort_requested: bool) -> crate::ScanPanelState {
    crate::ScanPanelState {
        run_id: None,
        target: PathBuf::from("."),
        stage: "scan".to_string(),
        findings_count: 0,
        running,
        abort_requested,
        error: None,
    }
}
