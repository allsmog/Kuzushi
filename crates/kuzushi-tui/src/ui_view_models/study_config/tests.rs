use super::*;
use kuzushi_core::allowance::{AllowanceLimits, AllowanceSnapshot};
use ratatui::{backend::TestBackend, Terminal};

fn configured_study() -> (tempfile::TempDir, BatchScanConfig) {
    let target = tempfile::tempdir().unwrap();
    let mut config = BatchScanConfig::load(target.path(), None);
    config.study.allowance = Some(AllowanceSnapshot {
        schema_version: 1,
        investigation_id: "labeled-study".into(),
        revision: 1,
        model: "openai-codex:gpt-5.5".into(),
        limits: AllowanceLimits {
            max_provider_calls: 8,
            protected_review_calls: 2,
        },
        committed_calls: 1,
        review_calls: 0,
        unresolved_calls: 0,
        cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
        work_plan: None,
    });
    (target, config)
}

#[test]
fn study_spending_remains_visible_before_budget_selection_at_every_viewport() {
    let (_target, config) = configured_study();
    let mut app = crate::ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_shell_view(crate::app::ShellView::Campaign);
    app.router.campaign_mut().batch_scan_config = Some(config);
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        let expected = if width >= 76 {
            "1 committed / 8 total"
        } else {
            "Calls 1/8"
        };
        assert!(text.contains(expected), "{width}x{height}: {text}");
        assert!(
            text.contains("Review 2") || text.contains("2 Review left"),
            "{width}x{height}"
        );
        assert!(
            text.contains("Enter")
                && text.contains("r re")
                && text.contains("L next")
                && text.contains("Esc back"),
            "{width}x{height}"
        );
    }
    let plain = crate::renderer::render_plain_app(&app, 40);
    let text = plain.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(text.contains("1 committed / 8 total"));
}

#[test]
fn compact_large_allowances_keep_exact_call_counts_and_failed_accounting_never_looks_empty() {
    let (_target, mut config) = configured_study();
    let allowance = config.study.allowance.as_mut().unwrap();
    allowance.committed_calls = 123_456;
    allowance.limits.max_provider_calls = 1_000_000;
    allowance.limits.protected_review_calls = 777_777;
    let label = study_allowance_summary(&config, 36);
    assert_eq!(label, "Calls 123456/1000000");
    config.study.accounting_error = Some("Labeled missing receipt".into());
    assert_eq!(
        study_allowance_summary(&config, 36),
        "Accounting unavailable · work blocked"
    );
    config.study.accounting_error = None;
    config.study.allowance = None;
    assert_eq!(
        study_allowance_summary(&config, 36),
        "Allowance not approved"
    );
}
