use super::*;

#[test]
fn a_new_plan_request_does_not_present_the_previous_plans_job_count_as_ready() {
    let (root, mut app) = app();
    let workspace = kuzushi_core::WorkspaceTarget::new(root.path()).unwrap();
    app.set_target(Some(workspace.root().into()));
    let old = kuzushi_core::capabilities::campaign::campaign_plan_path(root.path(), "previous");
    std::fs::create_dir_all(old.parent().unwrap()).unwrap();
    std::fs::write(
        old,
        r#"{"kind":"scan-batch","jobs":[{"jobId":"previous-job","input":{}}]}"#,
    )
    .unwrap();
    let snapshot = kuzushi_core::capabilities::campaign::snapshot::load_campaign_snapshot(
        root.path(),
        "previous",
    )
    .unwrap();
    app.router.campaign_mut().campaigns = vec![snapshot];
    app.router.campaign_mut().detail = true;
    app.router.campaign_mut().job_detail = true;
    let (_, wake) = crate::TerminalLoopInbox::channel_for_test();
    app.set_loop_wake(Some(wake));
    app.open_campaign_view(Some("requested".into()));
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let text = super::super::reader::campaign_view_lines(&app, Rect::new(0, 0, width, height))
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("LOADING INVESTIGATION"),
            "{width}x{height}: {text}"
        );
        assert!(text.contains("requested"), "{text}");
        assert!(
            !text.contains("Jobs:"),
            "Previous workload looked ready: {text}"
        );
        assert!(
            !text.contains("previous-job"),
            "Previous job looked selected: {text}"
        );
        assert!(
            !text.contains("L starts"),
            "Premature launch control: {text}"
        );
        assert!(crate::renderer::campaign_reader_scroll(&app).is_none());
    }
    assert_eq!(
        app.router
            .campaign()
            .selected_campaign()
            .unwrap()
            .campaign_id,
        "previous"
    );
}

fn app() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    app.set_shell_view(crate::ShellView::Campaign);
    (root, app)
}

#[test]
fn partial_history_survives_transient_notice_changes_at_all_six_widths() {
    let (_root, mut app) = app();
    app.router.campaign_mut().history_coverage = Some(
        kuzushi_core::capabilities::campaign::history::CampaignHistoryCoverage {
            unreadable_campaigns: 1,
            ..Default::default()
        },
    );
    app.router.campaign_mut().notice = None;
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        let text = campaign_lines(&app, Rect::new(0, 0, width, height))
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("History partial"), "{width}x{height}: {text}");
        assert!(text.contains("No readable investigations"), "{text}");
        assert!(!text.contains("no campaigns planned"), "{text}");
    }
}

#[test]
fn unreadable_directory_is_not_a_successful_empty_history() {
    let (_root, mut app) = app();
    app.router.campaign_mut().history_coverage = Some(
        kuzushi_core::capabilities::campaign::history::CampaignHistoryCoverage {
            directory_unreadable: true,
            ..Default::default()
        },
    );
    let text = campaign_lines(&app, Rect::new(0, 0, 80, 24))
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("History unavailable"), "{text}");
    assert!(text.contains("Spending is unknown"), "{text}");
    assert!(!text.contains("no campaigns planned"), "{text}");
}
