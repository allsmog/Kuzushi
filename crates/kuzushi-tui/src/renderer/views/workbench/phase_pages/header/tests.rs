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
        checkpoint_drift: None,
        target: "./target".to_string(),
        context: "context present".to_string(),
        model: "unconfigured".to_string(),
        threat_model: None,
        module: "all modules".to_string(),
        cost_usd: 0.0,
        cost_complete: true,
        cost_invalid: false,
        budget_usd: None,
        liveness: crate::ui_view_models::WorkLiveness::Idle,
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
        emphasis: crate::PhaseResultEmphasis::DominantDecision,
        compact_summary: "Scan partial".to_string(),
        detail: "partial canonical result retained".to_string(),
        detail_rows: vec![crate::app::PhaseResultDetailRow {
            key: None,
            disclosed_keys: std::collections::BTreeSet::new(),
            text: "partial canonical result retained".to_string(),
        }],
        semantic_keys: std::collections::BTreeSet::new(),
        actions: vec![kuzushi_core::workflow_attempts::PhaseResultAction::Select],
        control_hint: "Esc Navigate to resolve this result".to_string(),
        recommended: "acknowledge the partial Scan".to_string(),
    }
}

fn scan_hints() -> Vec<WorkbenchHint> {
    vec![
        WorkbenchHint {
            verb: Cow::Borrowed("run sast:scan {}"),
            label: std::borrow::Cow::Borrowed("scan now"),
        },
        WorkbenchHint {
            verb: Cow::Borrowed("next"),
            label: std::borrow::Cow::Borrowed("continue workspace phase"),
        },
    ]
}

fn rendered_header_text(header: &EngagementHeaderModel) -> String {
    phase_header_lines(header, &scan_hints(), 80, 40)
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
        checkpoint_drift: None,
        target: "/a/very/long/target/that/must/not/evict/mode/truth".to_string(),
        context: "context present".to_string(),
        model: "configured".to_string(),
        threat_model: None,
        module: "all modules".to_string(),
        cost_usd: 0.0,
        cost_complete: true,
        cost_invalid: false,
        budget_usd: None,
        liveness: crate::ui_view_models::WorkLiveness::Idle,
        finding_filter: None,
        phase_rail: Vec::new(),
        next_action: String::new(),
        next_tools: String::new(),
        result_card: None,
    };

    let text = line_text(identity_line(&header, 40));

    assert!(text.contains("Viewing Scan"), "{text}");
    assert!(
        text.contains("next Review"),
        "reality must survive 40 columns via the compact phrasing: {text}"
    );
    assert!(!text.contains("target"), "{text}");

    let wide = line_text(identity_line(&header, 120));
    assert!(wide.contains("next required Review"), "{wide}");
}

#[test]
fn map_identity_names_the_active_threat_model_separately_from_runtime_model() {
    let mut header = scan_header(None);
    header.phase = kuzushi_core::WorkflowPhase::Map;
    header.reality_phase = Some(kuzushi_core::WorkflowPhase::Map);
    header.model = "configured openai:gpt-test".to_string();
    header.threat_model = Some("model 2/3 · Payments · pasta · verified".to_string());

    let text = line_text(identity_line(&header, 160));

    assert!(text.contains("model configured openai:gpt-test"), "{text}");
    assert!(
        text.contains("model 2/3 · Payments · pasta · verified"),
        "{text}"
    );
}

#[test]
fn stale_checkpoint_names_cause_and_rerun_without_claiming_progress() {
    let mut header = scan_header(None);
    header.checkpoint_drift = Some(crate::ui_view_models::CheckpointDrift {
        phase: kuzushi_core::WorkflowPhase::Scan,
        accepted_revision: Some("abcdef012345".to_string()),
        current_revision: Some("123456789abc".to_string()),
        dirty_changed: false,
        relationship: Some(kuzushi_core::workspace::RevisionRelationship::AheadBy(3)),
    });

    let wide = phase_header_lines(&header, &scan_hints(), 140, 40)
        .into_iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(wide.contains("accepted Scan is stale"), "{wide}");
    assert!(wide.contains("3 commits behind"), "{wide}");
    assert!(wide.contains("rerun Scan"), "{wide}");

    let narrow = phase_header_lines(&header, &[], 40, 20)
        .into_iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(narrow.contains("Scan stale"), "{narrow}");
    assert!(narrow.contains("rerun Scan"), "{narrow}");
}

#[test]
fn liveness_badge_distinguishes_external_sync_from_idle_and_live() {
    // The "86% CPU watcher while the badge says idle" incident: external
    // writers churning workspace state must not render as idle.
    let (idle, _) = live_atom(crate::ui_view_models::WorkLiveness::Idle);
    let (sync, _) = live_atom(crate::ui_view_models::WorkLiveness::ExternalSync);
    let (live, _) = live_atom(crate::ui_view_models::WorkLiveness::Live);

    assert_eq!(idle, "○ idle");
    assert_eq!(sync, "◌ workspace sync");
    assert_eq!(live, "● LIVE");
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
        emphasis: crate::PhaseResultEmphasis::CompactDisposition,
        compact_summary: "Map ready · 1 run(s)".to_string(),
        detail: "completed without interaction".to_string(),
        detail_rows: vec![crate::app::PhaseResultDetailRow {
            key: None,
            disclosed_keys: std::collections::BTreeSet::new(),
            text: "completed without interaction".to_string(),
        }],
        semantic_keys: std::collections::BTreeSet::new(),
        actions: vec![kuzushi_core::workflow_attempts::PhaseResultAction::Select],
        control_hint: "Esc Navigate after finishing or clearing prompt draft".to_string(),
        recommended: "use the result".to_string(),
    };

    let text = result_card_lines(Some(&card), 40, 32)
        .into_iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n");

    assert!(text.contains("Esc Navigate after finishing"), "{text}");
    assert!(!text.contains("u Use"), "{text}");
}

#[test]
fn narrow_result_card_discloses_every_viewport_omission_with_source_keys() {
    let card = keyed_result_card();

    let rows = result_card_render_rows(&card, 34, 10);
    let text = rows
        .iter()
        .map(|row| row.line.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let accounted = accounted_render_keys(&rows);

    assert_eq!(accounted, card.semantic_keys);
    assert!(rows.len() <= 10, "viewport budget exceeded: {}", rows.len());
    assert!(text.contains("omitted"), "{text}");
    assert!(text.contains("replay"), "{text}");
    assert!(rows.iter().all(|row| row.line.width() <= 34));
}

#[test]
fn ultra_compact_result_card_reserves_the_phase_truth_body() {
    let card = keyed_result_card();

    let rows = result_card_render_rows(&card, 40, 3);
    let text = rows
        .iter()
        .map(|row| row.line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    assert_eq!(rows.len(), 1);
    assert_eq!(accounted_render_keys(&rows), card.semantic_keys);
    assert!(text.contains("replay"), "{text}");
    assert!(rows.iter().all(|row| row.line.width() <= 40));
}

fn keyed_result_card() -> crate::ui_view_models::PhaseResultCardModel {
    use kuzushi_core::run_lifecycle::{RunCellKey, RunCellRoleV1, RunCellSourceV1, RunItemId};
    let keys = (0..6)
        .map(|ordinal| RunCellKey {
            source: RunCellSourceV1::Item(RunItemId::new()),
            role: RunCellRoleV1::ResultSummary,
            ordinal,
        })
        .collect::<Vec<_>>();
    crate::ui_view_models::PhaseResultCardModel {
        attempt_id: "attempt-with-a-long-stable-identity".to_string(),
        outcome: "partial".to_string(),
        emphasis: crate::PhaseResultEmphasis::DominantDecision,
        compact_summary: "Scan partial".to_string(),
        detail: "source-backed detail".to_string(),
        detail_rows: keys
            .iter()
            .map(|key| crate::app::PhaseResultDetailRow {
                key: Some(key.clone()),
                disclosed_keys: std::collections::BTreeSet::new(),
                text: "bounded source-backed result detail remains inspectable".to_string(),
            })
            .collect(),
        semantic_keys: keys.into_iter().collect(),
        actions: vec![kuzushi_core::workflow_attempts::PhaseResultAction::Open],
        control_hint: "o Open the canonical result".to_string(),
        recommended: "inspect replay before selecting this partial result".to_string(),
    }
}

#[test]
fn unresolved_partial_result_suppresses_phase_command_hints() {
    let text = rendered_header_text(&scan_header(Some(partial_result_card())));

    assert!(text.contains("NEXT acknowledge the partial Scan"), "{text}");
    assert!(text.contains("Esc Navigate to resolve"), "{text}");
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
