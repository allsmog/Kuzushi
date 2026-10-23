use super::*;
use kuzushi_core::allowance::{AllowanceLimits, AllowanceSnapshot};
use ratatui::{backend::TestBackend, Terminal};
use serde_json::json;

#[test]
fn evidence_draft_shows_scope_spending_model_and_next_action_without_scrolling() {
    let root = tempfile::tempdir().unwrap();
    let mut config = BatchScanConfig::load(root.path(), None);
    config.study.max_provider_calls = Some(3);
    config.study.protected_review_calls = Some(2);
    config.context_generation = Some(StudyContextGeneration {
        generation_tool: Some("threat-model:build".into()),
        context_input: json!({"sourcePaths":[" app /lib.py", "app/lib.py"]}),
        ..Default::default()
    });
    let mut runtime = kuzushi_core::V2Config::default();
    runtime.model = Some("openai-codex:gpt-5.5".into());
    runtime.runtime.thinking_level = Some("medium".into());
    let mut app = crate::ShellApp::new(runtime, None);
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
        for expected in [
            "2 files · 1 job · 1 attempt",
            "Calls: 3 max · 2 for Review",
            "Dollar estimate unavailable",
            "gpt-5.5",
            "medium",
            "Prepare context draft",
            "M model",
            "Esc back",
        ] {
            assert!(
                text.contains(expected),
                "{width}x{height}: missing {expected}: {text}"
            );
        }
    }
}

#[test]
fn draft_header_matches_explicit_model_input_without_changing_the_session() {
    let root = tempfile::tempdir().unwrap();
    let mut config = BatchScanConfig::load(root.path(), None);
    config.context_generation = Some(StudyContextGeneration {
        generation_tool: Some("threat-model:build".into()),
        context_input: json!({"sourcePaths":["owned.rs"],"model":"openai-codex:gpt-6-luna","thinkingLevel":"low"}),
        ..Default::default()
    });
    let mut runtime = kuzushi_core::V2Config::default();
    runtime.model = Some("openai-codex:gpt-5.5".into());
    let mut app = crate::ShellApp::new(runtime, None);
    app.router.campaign_mut().batch_scan_config = Some(config);
    let text = generation_lines(&app, 120).join("\n");
    assert!(text.contains("openai-oauth:gpt-6-luna · low"));
    assert!(!text.contains("gpt-5.5"));
    assert_eq!(app.config().model.as_deref(), Some("openai-codex:gpt-5.5"));
}

#[test]
fn prepared_evidence_details_use_the_frozen_input_and_model() {
    let root = tempfile::tempdir().unwrap();
    let mut config = BatchScanConfig::load(root.path(), None);
    config.context_generation = Some(StudyContextGeneration {
        context_input: json!({"sourcePaths":["mutable-draft.rs"]}),
        receipt: Some(kuzushi_core::capabilities::campaign::ContextStudyReceipt {
            brief_guidance: None,
            scope_study_origin: None,
            generation_tool: "threat-model:build".into(),
            campaign_id: "owned-frozen-context".into(),
            investigation_id: "owned-investigation".into(),
            plan_sha256: "frozen-plan".into(),
            source_identity: "frozen-source".into(),
            source_inventory: None,
            config_sha256: "frozen-config".into(),
            model: "openai-codex:gpt-5.5".into(),
            input: json!({"sourcePaths":[" app /lib.py","app/lib.py"],"thinkingLevel":"low"}),
            preparation_jobs: Vec::new(),
        }),
        ..Default::default()
    });
    let app = crate::ShellApp::new(kuzushi_core::V2Config::default(), None);
    let text = summary(
        &app,
        &config,
        config.context_generation.as_ref().unwrap(),
        120,
    )
    .join("\n");
    assert!(text.contains("2 files · 1 job · 1 attempt"));
    assert!(text.contains("openai-oauth:gpt-5.5 · low"));
    assert!(text.contains("\" app /lib.py\"") && text.contains("\"app/lib.py\""));
    assert!(!text.contains("mutable-draft.rs") && !text.contains("model unset"));
    assert!(text.contains("inventory extent: not recorded"));
}

#[test]
fn missing_or_malformed_inheritance_never_claims_a_recorded_architecture() {
    let app = crate::ShellApp::new(kuzushi_core::V2Config::default(), None);
    for input in [
        json!({}),
        json!({"inheritedContextRef":{"revisionId":"incomplete"}}),
    ] {
        assert_eq!(
            inherited_label(&app, &input),
            "Inherits: unavailable; inspect exact options"
        );
    }
}

#[test]
fn evidence_plan_keeps_consumption_visible_before_long_source_lists_at_six_sizes() {
    let root = tempfile::tempdir().unwrap();
    let mut config = BatchScanConfig::load(root.path(), None);
    config.context_generation = Some(StudyContextGeneration {
        generation_tool: Some("threat-model:build".into()),
        context_input: json!({"sourcePaths":(0..256).map(|i|format!("component-{i}/owned.rs")).collect::<Vec<_>>() }),
        ..Default::default()
    });
    config.study.allowance = Some(AllowanceSnapshot {
        schema_version: 1,
        investigation_id: "owned-visibility-test".into(),
        revision: 1,
        model: "openai-codex:gpt-5.5".into(),
        limits: AllowanceLimits {
            max_provider_calls: 9,
            protected_review_calls: 2,
        },
        committed_calls: 1,
        review_calls: 0,
        unresolved_calls: 0,
        cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
        work_plan: None,
    });
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
        let calls = if width >= 76 {
            "1 committed / 9 total"
        } else {
            "Calls 1/9"
        };
        assert!(text.contains(calls), "{width}x{height}: {text}");
        assert!(
            text.contains("2 Review left") || text.contains("Review 2"),
            "{width}x{height}: {text}"
        );
    }
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .accounting_error = Some("Missing retained ledger".into());
    let text = summary(
        &app,
        app.router.campaign().batch_scan_config.as_ref().unwrap(),
        app.context_generation().unwrap(),
        36,
    )
    .join("\n");
    assert!(text
        .lines()
        .take(3)
        .any(|line| line.contains("Last read 1/9") && line.contains("blocked")));
}
