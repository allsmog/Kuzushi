use super::*;
use serde_json::json;
use std::path::Path;

fn draft() -> BatchScanConfig {
    let mut config = BatchScanConfig::load(Path::new("/owned-resource-fixture"), None);
    config.study.campaign_id = Some("recorded-draft".into());
    config.study.scan_input = Some(json!({"tasks":["agentic"],"threatModelRef":null}));
    config.study.max_provider_calls = Some(8);
    config.study.protected_review_calls = Some(2);
    config.study.max_job_attempts = 2;
    config.prior_campaign_id = Some("original".into());
    config.resource_picker = Some(StudyResourcePicker {
        cursor: 0,
        scroll: 0,
        history: crate::app::ViewDataState::NotRequested,
        choices: vec![
            StudyResourceChoice {
                campaign_id: Some("original".into()),
                label: "Original".into(),
            },
            StudyResourceChoice {
                campaign_id: Some("selected".into()),
                label: "Selected".into(),
            },
        ],
    });
    config
}

#[test]
fn changed_evidence_invalidates_work_without_changing_options_or_limits() {
    let mut config = draft();
    let input = config.study.scan_input.clone();
    move_choice(&mut config, 1);
    accept_choice(&mut config);
    assert_eq!(config.prior_campaign_id.as_deref(), Some("selected"));
    assert!(config.study.campaign_id.is_none());
    assert_eq!(config.study.scan_input, input);
    assert_eq!(
        (
            config.study.max_provider_calls,
            config.study.protected_review_calls,
            config.study.max_job_attempts
        ),
        (Some(8), Some(2), 2)
    );
}

#[test]
fn unchanged_choice_keeps_the_frozen_draft() {
    let mut config = draft();
    accept_choice(&mut config);
    assert_eq!(config.study.campaign_id.as_deref(), Some("recorded-draft"));
    assert!(config.notice.is_none());
}

#[test]
fn background_history_preserves_hover_selection_and_draft_authority() {
    use crate::app::ViewDataState;
    use kuzushi_core::capabilities::campaign::{StudyUsageCatalogue, StudyUsageChoice};
    let mut config = draft();
    move_choice(&mut config, 1);
    config.resource_picker.as_mut().unwrap().scroll = 4;
    let before = config.study.clone();
    apply_history(
        &mut config,
        ViewDataState::Ready(Ok(StudyUsageCatalogue {
            choices: vec![StudyUsageChoice {
                campaign_id: "newer".into(),
                kind: "scope-study".into(),
                planned_jobs: 6,
                completed_jobs: Some(6),
                created_at_ms: Some(1),
            }],
            ..Default::default()
        })),
    );
    let picker = config.resource_picker.as_ref().unwrap();
    assert_eq!(
        picker.choices[picker.cursor].campaign_id.as_deref(),
        Some("selected")
    );
    assert_eq!(picker.scroll, 4);
    assert_eq!(config.prior_campaign_id.as_deref(), Some("original"));
    assert_eq!(config.study, before);
    let choices = picker.choices.clone();
    apply_history(
        &mut config,
        ViewDataState::Ready(Err("Owned unreadable history".into())),
    );
    assert_eq!(config.resource_picker.as_ref().unwrap().choices, choices);
    assert_eq!(config.study, before);
}

#[test]
fn named_evidence_is_retained_when_outside_the_loaded_history_window() {
    let mut choices = Vec::new();
    append_named_choice(&mut choices, Some("recorded"));
    append_named_choice(&mut choices, Some("recorded"));
    assert_eq!(choices.len(), 1);
    assert_eq!(choices[0].campaign_id.as_deref(), Some("recorded"));
}

#[test]
fn picker_paging_resize_and_cancel_preserve_selection_and_the_composer() {
    use crate::app::V2Config;
    use crate::{ShellView, TerminalViewport};
    use ratatui::{backend::TestBackend, Terminal};
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Campaign);
    app.router.campaign_mut().batch_scan_config = Some(draft());
    app.set_input("held resource draft");
    for (width, height) in [(40, 12), (60, 20), (80, 24), (120, 36), (160, 48), (96, 89)] {
        app.set_viewport(TerminalViewport::new(width, height));
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut seen = String::new();
        let mut tail_visible = false;
        let mut last_frame = String::new();
        for _ in 0..20 {
            terminal
                .draw(|frame| crate::renderer::render_app(frame, &app))
                .unwrap();
            let body = terminal
                .backend()
                .buffer()
                .content
                .chunks(width as usize)
                .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                body.contains("HISTORICAL USAGE") && body.contains("Esc back"),
                "{width}x{height}: {body}"
            );
            let normalized = body
                .replace('│', " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            tail_visible |= normalized.contains("window remains available.");
            seen.push_str(&normalized);
            seen.push('\n');
            last_frame = body;
            app.handle_study_resource_key(KeyCode::PageDown);
        }
        assert_eq!(app.study_resource_picker().unwrap().cursor, 0);
        assert!(
            tail_visible,
            "{width}x{height}: detail tail was unreachable\n{last_frame}"
        );
        assert!(
            seen.contains("prices stay unknown") && seen.contains("starts no jobs"),
            "{width}x{height}: {seen}"
        );
    }
    app.handle_study_resource_key(KeyCode::Esc);
    assert!(app.study_resource_picker().is_none());
    assert_eq!(app.input(), "held resource draft");
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .prior_campaign_id
            .as_deref(),
        Some("original")
    );
}
