use super::*;
use kuzushi_core::V2Config;
use std::borrow::Cow;
use std::time::{Duration, Instant};

fn line_text(line: Line<'static>) -> String {
    line.spans
        .into_iter()
        .map(|span| span.content.into_owned())
        .collect()
}

fn scan_header(
    result_card: Option<crate::ui_view_models::PhaseResultCardModel>,
) -> EngagementHeaderModel {
    EngagementHeaderModel {
        phase: kuzushi_core::WorkflowPhase::Scan,
        reality_phase: Some(kuzushi_core::WorkflowPhase::Scan),
        target: "./target".to_string(),
        context: "context present".to_string(),
        model: "unconfigured".to_string(),
        module: "all modules".to_string(),
        cost_usd: 0.0,
        cost_complete: true,
        cost_invalid: false,
        budget_usd: None,
        live: false,
        finding_filter: None,
        phase_rail: Vec::new(),
        next_action: "acknowledge the partial Scan".to_string(),
        next_tools: String::new(),
        result_card,
    }
}

fn partial_result_card() -> crate::ui_view_models::PhaseResultCardModel {
    crate::ui_view_models::PhaseResultCardModel {
        attempt_id: "attempt-partial".to_string(),
        outcome: "partial".to_string(),
        detail: "partial canonical result retained".to_string(),
        actions: vec![kuzushi_core::workflow_attempts::PhaseResultAction::Select],
        control_hint: "F2 Navigate to resolve this result".to_string(),
        recommended: "acknowledge the partial Scan".to_string(),
    }
}

fn scan_hints() -> Vec<WorkbenchHint> {
    vec![
        WorkbenchHint {
            verb: Cow::Borrowed("run sast:scan {}"),
            label: "scan now",
        },
        WorkbenchHint {
            verb: Cow::Borrowed("next"),
            label: "continue workspace phase",
        },
    ]
}

fn rendered_header_text(header: &EngagementHeaderModel) -> String {
    phase_header_lines(header, &scan_hints(), 80)
        .into_iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn compact_identity_keeps_selected_view_distinct_from_reality() {
    let header = EngagementHeaderModel {
        phase: kuzushi_core::WorkflowPhase::Scan,
        reality_phase: Some(kuzushi_core::WorkflowPhase::Review),
        target: "/a/very/long/target/that/must/not/evict/mode/truth".to_string(),
        context: "context present".to_string(),
        model: "configured".to_string(),
        module: "all modules".to_string(),
        cost_usd: 0.0,
        cost_complete: true,
        cost_invalid: false,
        budget_usd: None,
        live: false,
        finding_filter: None,
        phase_rail: Vec::new(),
        next_action: String::new(),
        next_tools: String::new(),
        result_card: None,
    };

    let text = line_text(identity_line(&header, 40));

    assert!(text.contains("VIEW SCAN"), "{text}");
    assert!(text.contains("REALITY REVIEW"), "{text}");
    assert!(!text.contains("target"), "{text}");
}

#[test]
fn compact_filter_line_names_the_active_filter_and_reset_command() {
    let text = line_text(finding_filter_line("severity:high", 60));

    assert!(text.contains("FILTER"), "{text}");
    assert!(text.contains("severity:high"), "{text}");
    assert!(text.contains("findings filter clear"), "{text}");
}

#[test]
fn compact_result_card_keeps_prompt_draft_navigation_instruction_visible() {
    let card = crate::ui_view_models::PhaseResultCardModel {
        attempt_id: "attempt-1".to_string(),
        outcome: "completed".to_string(),
        detail: "completed without interaction".to_string(),
        actions: vec![kuzushi_core::workflow_attempts::PhaseResultAction::Select],
        control_hint: "F2 Navigate after finishing or clearing prompt draft".to_string(),
        recommended: "use the result".to_string(),
    };

    let text = result_card_lines(Some(&card), 40)
        .into_iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n");

    assert!(text.contains("F2 Navigate after finishing"), "{text}");
    assert!(!text.contains("u Use"), "{text}");
}

#[test]
fn unresolved_partial_result_suppresses_phase_command_hints() {
    let text = rendered_header_text(&scan_header(Some(partial_result_card())));

    assert!(text.contains("NEXT acknowledge the partial Scan"), "{text}");
    assert!(text.contains("F2 Navigate to resolve"), "{text}");
    assert!(
        text.contains("next: acknowledge the partial Scan"),
        "{text}"
    );
    assert!(!text.contains("run sast:scan {} scan now"), "{text}");
    assert!(!text.contains("next continue workspace phase"), "{text}");
}

#[test]
fn normal_scan_retains_phase_command_hints() {
    let text = rendered_header_text(&scan_header(None));

    assert!(text.contains("run sast:scan {} scan now"), "{text}");
    assert!(text.contains("next continue workspace phase"), "{text}");
}

#[test]
fn reduced_motion_freezes_live_pulse_but_keeps_elapsed_redraws_due() {
    let _theme = theme::scoped_theme_for_test(theme::ThemeConfig {
        reduced_motion: true,
        color_depth: theme::ColorDepth::TrueColor,
        ..theme::ThemeConfig::default()
    });
    assert!(!live_pulse_on(), "reduced motion must freeze LIVE styling");

    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_running_tool_for_test("context:build");
    app.ui_mut().set_spinner_phase_for_test(7);
    let started_at = Instant::now();

    assert!(app.tick_at(started_at));
    assert_eq!(app.ui().spinner_phase(), 0);
    assert!(!app.tick_at(started_at + Duration::from_millis(999)));
    assert!(app.tick_at(started_at + Duration::from_secs(1)));
    assert_eq!(
        app.ui().spinner_phase(),
        0,
        "elapsed redraws must not restart animation"
    );
}
