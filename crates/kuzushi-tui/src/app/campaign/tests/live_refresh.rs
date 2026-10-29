use super::*;
use crate::app::campaign::live_progress::CAMPAIGN_LIVE_REFRESH;
use std::time::{Duration, Instant};

fn watched_deck() -> (tempfile::TempDir, ShellApp) {
    let (root, mut app) = deck_app();
    app.open_campaign_view(None);
    app.router.campaign_mut().dispatcher_pid = Some(u32::MAX);
    (root, app)
}

fn record_running_job(root: &Path) {
    let queue = serde_json::json!({
        "jobs": {
            "j1": { "state": "completed", "costUsd": 0.25, "attempts": 1, "exitCode": 0 },
            "j2": { "state": "running", "attempts": 1 }
        }
    });
    let path = kuzushi_core::capabilities::campaign::campaign_queue_path(root, "camp1");
    std::fs::write(path, serde_json::to_vec_pretty(&queue).unwrap()).unwrap();
}

fn job_state(app: &ShellApp, job_id: &str) -> String {
    let jobs = &app.router.campaign().campaigns[0].jobs;
    let job = jobs.iter().find(|job| job.job_id == job_id).unwrap();
    job.state.clone()
}

#[test]
fn a_running_dispatcher_rereads_the_queue_on_its_schedule() {
    let (root, mut app) = watched_deck();
    let start = Instant::now();
    record_running_job(root.path());

    assert!(app.poll_live_campaign_progress(start));
    assert_eq!(job_state(&app, "j2"), "running");
    assert!(!app.poll_live_campaign_progress(start + Duration::from_secs(1)));
    assert!(app.poll_live_campaign_progress(start + CAMPAIGN_LIVE_REFRESH));
}

#[test]
fn a_deck_without_a_dispatcher_is_not_refreshed() {
    let (root, mut app) = watched_deck();
    app.router.campaign_mut().dispatcher_pid = None;
    record_running_job(root.path());

    assert!(!app.poll_live_campaign_progress(Instant::now()));
    assert_ne!(job_state(&app, "j2"), "running");
}

#[test]
fn a_dispatcher_is_not_watched_from_another_view() {
    let (_root, mut app) = watched_deck();
    app.set_shell_view(ShellView::Report);

    assert!(!app.poll_live_campaign_progress(Instant::now()));
    assert!(app.router.campaign().live_refreshed_at.is_none());
}

#[test]
fn a_deck_without_a_target_does_not_record_a_refresh() {
    let (_root, mut app) = watched_deck();
    app.set_target(None);
    app.set_shell_view(ShellView::Campaign);

    assert!(!app.poll_live_campaign_progress(Instant::now()));
    assert!(app.router.campaign().live_refreshed_at.is_none());
}
