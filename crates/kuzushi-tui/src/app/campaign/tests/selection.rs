use super::*;

fn edit_plan(root: &Path, edit: impl FnOnce(&mut serde_json::Value)) {
    let path = kuzushi_core::capabilities::campaign::campaign_plan_path(root, "camp1");
    let mut value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    edit(&mut value);
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

fn add_earlier_campaign(root: &Path) {
    let source = kuzushi_core::capabilities::campaign::campaign_plan_path(root, "camp1");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(source).unwrap()).unwrap();
    value["campaignId"] = serde_json::json!("aaa");
    let path = kuzushi_core::capabilities::campaign::campaign_plan_path(root, "aaa");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

fn selected_app() -> (tempfile::TempDir, ShellApp) {
    let (root, mut app) = deck_app();
    app.open_campaign_view(Some("camp1".into()));
    let deck = app.router.campaign_mut();
    deck.selected_job = 1;
    deck.job_detail = true;
    deck.read_scroll = 7;
    deck.excluded.insert("j1".into());
    app.set_input("retained investigation draft");
    (root, app)
}

#[test]
fn refresh_preserves_campaign_identity_after_an_earlier_campaign_appears() {
    let (root, mut app) = selected_app();
    add_earlier_campaign(root.path());

    app.refresh_campaign_deck();

    let deck = app.router.campaign();
    assert_eq!(deck.selected_campaign().unwrap().campaign_id, "camp1");
    assert_eq!(deck.selected_job().unwrap().job_id, "j2");
    assert_eq!(deck.read_scroll, 7);
    assert!(deck.job_detail && deck.excluded.contains("j1"));
    assert_eq!(app.input(), "retained investigation draft");
    assert_eq!(app.shell_view(), ShellView::Campaign);
}

#[test]
fn refresh_preserves_job_identity_when_recorded_plan_rows_are_reordered() {
    let (root, mut app) = selected_app();
    edit_plan(root.path(), |value| {
        value["jobs"].as_array_mut().unwrap().reverse()
    });

    app.refresh_campaign_deck();

    let deck = app.router.campaign();
    assert_eq!(deck.selected_job().unwrap().job_id, "j2");
    assert_eq!(deck.read_scroll, 7);
    assert!(deck.job_detail && deck.excluded.contains("j1"));
}

#[test]
fn missing_campaign_clears_reader_and_exclusions_with_both_recovery_notices() {
    let (root, mut app) = selected_app();
    add_earlier_campaign(root.path());
    let path = kuzushi_core::capabilities::campaign::campaign_plan_path(root.path(), "camp1");
    std::fs::remove_file(path).unwrap();

    app.refresh_campaign_deck();

    let deck = app.router.campaign();
    assert!(!deck.detail && !deck.job_detail);
    assert!(deck.excluded.is_empty());
    assert_eq!(deck.read_scroll, 0);
    let notice = deck.notice.as_deref().unwrap();
    assert!(
        notice.contains("campaign \"camp1\" is unavailable"),
        "{notice}"
    );
    assert_eq!(
        deck.history_coverage.as_ref().unwrap().unreadable_campaigns,
        1
    );
    assert_eq!(app.input(), "retained investigation draft");
}

#[test]
fn missing_job_returns_to_the_same_campaign_list_without_reusing_the_old_reader() {
    let (root, mut app) = selected_app();
    edit_plan(root.path(), |value| {
        value["jobs"].as_array_mut().unwrap().truncate(1)
    });

    app.refresh_campaign_deck();

    let deck = app.router.campaign();
    assert_eq!(deck.selected_campaign().unwrap().campaign_id, "camp1");
    assert!(deck.detail && !deck.job_detail);
    assert_eq!(deck.read_scroll, 0);
    assert!(deck.excluded.contains("j1"));
    assert!(deck
        .notice
        .as_deref()
        .unwrap()
        .contains("job \"j2\" is unavailable"));
}

#[test]
fn switching_targets_does_not_reuse_matching_campaign_ids_or_old_exclusions() {
    let (_root, mut app) = selected_app();
    let other = tempfile::tempdir().unwrap();
    write_fixture_campaign(other.path());

    app.set_target(Some(other.path().into()));
    app.refresh_campaign_deck();

    let deck = app.router.campaign();
    assert!(!deck.detail && !deck.job_detail);
    assert_eq!(deck.selected_job().unwrap().job_id, "j1");
    assert_eq!(deck.read_scroll, 0);
    assert!(deck.excluded.is_empty() && deck.notice.is_none());
    assert_eq!(app.input(), "retained investigation draft");
}
