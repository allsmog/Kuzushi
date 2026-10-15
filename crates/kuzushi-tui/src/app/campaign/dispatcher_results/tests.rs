use super::*;
use crate::app::campaign::tests::deck_app;

fn failed_dispatcher(app: &mut ShellApp, target: &Path, log: Option<&str>) {
    let directory =
        kuzushi_core::capabilities::campaign::campaign_dir(target, "camp1").join("logs");
    std::fs::create_dir_all(&directory).unwrap();
    if let Some(log) = log {
        std::fs::write(directory.join("dispatcher.log"), log).unwrap();
    }
    let mut child = std::process::Command::new("false").spawn().unwrap();
    child.wait().unwrap();
    app.router.campaign_mut().dispatcher_pid = Some(child.id());
    app.runtime_state
        .hold_dispatcher(child, target.canonicalize().unwrap(), "camp1".into());
}

#[test]
fn failed_dispatcher_survives_refresh_without_changing_focus_or_draft() {
    let (root, mut app) = deck_app();
    app.open_campaign_view(Some("camp1".into()));
    app.router.campaign_mut().read_scroll = 8;
    app.set_input("held draft");
    let origin = app.shell_view();
    failed_dispatcher(
        &mut app,
        root.path(),
        Some("Error: prepared on different source\n"),
    );

    assert!(app.poll_campaign_completion());
    let notice = app.router.campaign().notice.clone().unwrap();
    assert!(notice.contains("different source"));
    assert!(notice.contains("Review the recorded failure"));
    assert!(notice.contains("campaigns/camp1/logs/dispatcher.log"));
    assert_eq!(app.router.campaign().dispatcher_pid, None);
    app.refresh_campaign_deck();
    assert_eq!(app.router.campaign().notice, Some(notice));
    assert_eq!(app.shell_view(), origin);
    assert_eq!(app.input(), "held draft");
    assert_eq!(app.router.campaign().read_scroll, 8);
    assert!(!app.poll_campaign_completion());
}

#[test]
fn recorded_allowance_stop_explains_remaining_work_without_calling_it_a_failure() {
    let (root, mut app) = deck_app();
    park_for_allowance(root.path());
    app.open_campaign_view(Some("camp1".into()));
    failed_dispatcher(
        &mut app,
        root.path(),
        Some("Error: campaign camp1: 1 completed, 1 parked\n"),
    );
    assert!(app.poll_campaign_completion());
    let notice = app.router.campaign().notice.clone().unwrap();
    assert!(notice.contains("Allowance reached: 1 completed, 1 parked"));
    assert!(notice.contains("Finish and report partial work"));
    assert!(notice.contains("press a"));
    assert!(!notice.contains("failure"));
    app.refresh_campaign_deck();
    assert_eq!(app.router.campaign().notice, Some(notice));
}

#[test]
fn old_allowance_park_does_not_mask_a_new_dispatcher_failure() {
    let (root, mut app) = deck_app();
    park_for_allowance(root.path());
    app.open_campaign_view(Some("camp1".into()));
    failed_dispatcher(
        &mut app,
        root.path(),
        Some("Error: prepared on different source\n"),
    );
    assert!(app.poll_campaign_completion());
    let notice = app.router.campaign().notice.as_deref().unwrap();
    assert!(notice.contains("different source"));
    assert!(notice.contains("Review the recorded failure"));
    assert!(!notice.contains("Allowance reached"));
}

fn park_for_allowance(root: &Path) {
    let path = kuzushi_core::capabilities::campaign::campaign_queue_path(root, "camp1");
    let mut queue: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    queue["jobs"]["j2"] =
        serde_json::json!({"state":"parked","reason":"allowance-exhausted","attempts":0});
    std::fs::write(path, serde_json::to_vec(&queue).unwrap()).unwrap();
}

#[test]
fn a_failure_notice_follows_its_campaign_and_target_only() {
    let (root, mut app) = deck_app();
    app.open_campaign_view(Some("camp1".into()));
    failed_dispatcher(&mut app, root.path(), Some("Error: source changed\n"));
    assert!(app.poll_campaign_completion());
    let notice = app.router.campaign().notice.clone().unwrap();
    let mut other = app.router.campaign().campaigns[0].clone();
    other.campaign_id = "other".into();
    app.router.campaign_mut().campaigns.push(other);
    app.router.campaign_mut().detail = false;
    app.move_visible_campaign_cursor(1);
    assert_eq!(app.router.campaign().notice, None);
    app.select_campaign("camp1");
    assert_eq!(app.router.campaign().notice, Some(notice));
    app.select_campaign("missing");
    assert!(app
        .router
        .campaign()
        .notice
        .as_ref()
        .unwrap()
        .contains("missing"));
    let outside = tempfile::tempdir().unwrap();
    app.set_target(Some(outside.path().into()));
    app.refresh_campaign_deck();
    assert!(app.router.campaign().notice.is_none());
}

#[test]
fn unavailable_and_empty_logs_do_not_invent_a_cause() {
    for (log, expected) in [
        (None, "Failure explanation unavailable"),
        (Some("progress only"), "No failure explanation was recorded"),
    ] {
        let (root, mut app) = deck_app();
        app.open_campaign_view(Some("camp1".into()));
        failed_dispatcher(&mut app, root.path(), log);
        assert!(app.poll_campaign_completion());
        assert!(app
            .router
            .campaign()
            .notice
            .as_ref()
            .unwrap()
            .contains(expected));
    }
}

#[test]
fn background_failure_does_not_navigate_to_the_campaign() {
    let (root, mut app) = deck_app();
    app.open_campaign_view(Some("camp1".into()));
    app.open_report_from_current_origin();
    app.set_input("keep this");
    failed_dispatcher(&mut app, root.path(), Some("Error: source changed\n"));
    assert!(app.poll_campaign_completion());
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!(app.input(), "keep this");
}
