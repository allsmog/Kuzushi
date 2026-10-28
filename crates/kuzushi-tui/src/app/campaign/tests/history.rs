use super::*;

#[test]
fn damaged_history_keeps_the_current_study_draft_and_partial_spend_disclosure() {
    let (root, mut app) = deck_app();
    let broken = campaign_dir(root.path(), "broken");
    std::fs::create_dir_all(&broken).unwrap();
    std::fs::write(broken.join("plan.json"), "{").unwrap();
    app.set_input("retained 東京 draft");
    app.open_campaign_view(Some("camp1".into()));
    let deck = app.router.campaign();
    assert_eq!(deck.selected_campaign().unwrap().campaign_id, "camp1");
    assert_eq!(
        deck.history_coverage.as_ref().unwrap().unreadable_campaigns,
        1
    );
    assert!(deck.trend.unwrap().provider_spend_unresolved);
    assert!(
        deck.notice.is_none(),
        "Unrelated history damage must use the persistent coverage warning"
    );
    assert_eq!(app.input(), "retained 東京 draft");
    app.router.campaign_mut().notice = None;
    assert!(!app
        .router
        .campaign()
        .history_coverage
        .as_ref()
        .unwrap()
        .complete());
}

#[test]
fn history_directory_failure_is_not_presented_as_an_empty_workspace() {
    let (root, mut app) = deck_app();
    let directory = kuzushi_core::capabilities::campaign::campaigns_dir(root.path());
    std::fs::remove_dir_all(&directory).unwrap();
    std::fs::write(
        &directory,
        "Owned regular file blocks the history directory",
    )
    .unwrap();
    app.open_campaign_view(None);
    let deck = app.router.campaign();
    assert!(deck.campaigns.is_empty());
    assert!(deck.history_coverage.as_ref().unwrap().directory_unreadable);
    assert!(deck.trend.unwrap().provider_spend_unresolved);
}

#[test]
fn explicit_old_study_and_refresh_keep_identity_past_the_browse_limit() {
    let (root, mut app) = deck_app();
    for i in 0..105 {
        let path = kuzushi_core::capabilities::campaign::campaign_plan_path(
            root.path(),
            &format!("aaa-{i:03}"),
        );
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, r#"{"jobs":[]}"#).unwrap();
    }
    app.open_campaign_view(Some("camp1".into()));
    app.router.campaign_mut().selected_job = 1;
    app.router.campaign_mut().read_scroll = 4;
    app.refresh_campaign_deck();
    let deck = app.router.campaign();
    assert_eq!(deck.selected_campaign().unwrap().campaign_id, "camp1");
    assert_eq!(deck.selected_job().unwrap().job_id, "j2");
    assert_eq!(deck.read_scroll, 4);
    assert_eq!(deck.campaigns.len(), 100);
    assert!(
        deck.history_coverage
            .as_ref()
            .unwrap()
            .campaign_limit_reached
    );
}
