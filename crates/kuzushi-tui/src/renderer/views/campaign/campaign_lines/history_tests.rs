use super::*;

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
