use super::*;
use kuzushi_core::allowance::{AllowanceLimits, AllowanceSnapshot};
use ratatui::{backend::TestBackend, Terminal};

#[test]
fn preparation_preview_uses_frozen_limits_and_keeps_legacy_unknowns_honest() {
    let input = serde_json::json!({"tasks":["agentic"],"maxInventoryFiles":1,"maxBytesPerFile":64});
    let summary = agentic_preparation_summary(&input).unwrap();
    assert!(summary.contains("snippet limit 1"));
    assert!(summary.contains("byte limit 64"));
    assert!(summary.contains("later agent reads are separate"));
    assert!(
        agentic_preparation_summary(&serde_json::json!({"tasks":["agentic"]}))
            .unwrap()
            .contains("not recorded")
    );
    assert!(agentic_preparation_summary(&serde_json::json!({"tasks":["secret-scan"]})).is_none());
}

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
        "Last read 123456/1000000 · blocked"
    );
    config.study.accounting_error = None;
    config.study.allowance = None;
    assert_eq!(
        study_allowance_summary(&config, 36),
        "Allowance not approved"
    );
}

#[test]
fn failed_accounting_keeps_last_known_consumption_visible_with_an_honest_label() {
    let (_target, mut config) = configured_study();
    config.study.accounting_error = Some("Labeled missing receipt".into());
    for width in [36, 56, 76, 92, 116, 156] {
        let label = study_allowance_summary(&config, width);
        assert!(
            label.contains("Last read") && label.contains("blocked"),
            "{label}"
        );
        assert!(
            label.contains("1/8") || label.contains("1 committed / 8 total"),
            "{label}"
        );
        assert!(label.chars().count() <= width, "{width}: {label}");
    }
    let lines = allowance_status_lines(&config).join("\n");
    for text in [
        "unverified",
        "1 committed / 8 total",
        "protected review: 2",
        "revision 1",
        "r retries",
    ] {
        assert!(lines.contains(text), "{lines}");
    }
}
#[test]
fn supporting_context_projection_shows_frozen_text_and_omissions() {
    let frozen = serde_json::json!({"scanContextRef":{"schemaVersion":1}});
    let lines =
        super::supporting_context_lines(&frozen, Some("Recorded architecture\nRecorded boundary"));
    assert!(lines[0].contains("exact frozen text"));
    assert_eq!(&lines[1..], &["Recorded architecture", "Recorded boundary"]);
    assert!(super::supporting_context_lines(&frozen, None)[0].contains("no supplemental text"));
    assert!(
        super::supporting_context_lines(&serde_json::json!({}), None)[0].contains("legacy live")
    );
}

#[test]
fn scoped_agentic_summary_distinguishes_discovery_from_context_before_execution() {
    let input = serde_json::json!({"tasks":["agentic"],"scanScopeRef":{"scopeId":"app"}});
    let summary = super::agentic_scope_summary(&input).unwrap();
    assert!(summary.contains("Exact read scope: app"));
    assert!(summary.contains("Shared files provide context only"));
    assert!(summary.contains("MCP tools are unavailable"));
    assert!(super::agentic_scope_summary(&serde_json::json!({"tasks":["secret-scan"]})).is_none());
}
