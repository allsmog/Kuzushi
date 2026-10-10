use super::*;

#[test]
fn suppression_label_survives_compact_and_wide_queue_rendering() {
    let mut row = review_row();
    row.proof_confidence = ProofConfidence::Dismissed;
    row.proof_confidence_label = "suppressed".into();
    row.decision = "needs_review".into();
    row.decision_author = "-".into();
    for width in [28, 40, 60, 80, 120, 160] {
        let text = lines_text(populated_review_queue_pane_lines(
            &review_model(vec![row.clone()]),
            Rect::new(0, 0, width, 16),
        ));
        assert!(text.contains("suppressed"), "{width}: {text}");
        let finding_row = text.lines().find(|line| line.contains("F-0001")).unwrap();
        assert!(!finding_row.contains("dismissed"), "{width}: {text}");
        assert!(!finding_row.contains("false-pos"), "{width}: {text}");
    }
}

#[test]
fn compact_reading_shows_both_claims_before_secondary_facets() {
    let mut first = review_row();
    first.title = "Descriptor policy allows inconsistent approval settings".into();
    first.proof_confidence = ProofConfidence::Unverified;
    let mut second = first.clone();
    second.alias = "F-0002".into();
    second.title = "Prompt override path escapes the selected directory".into();
    second.selected = false;
    let mut model = review_model(vec![first, second]);
    model.ordering_indicator = Some("order: proof band, then severity");
    model.facet_groups = vec![
        crate::ui_view_models::ReviewFacetGroup {
            label: "source",
            values: vec![crate::ui_view_models::ReviewFacetCount {
                value: "a-very-long-engine-name".into(),
                count: 2,
            }],
        };
        6
    ]
    .into();
    let lines = populated_review_queue_pane_lines(&model, Rect::new(0, 0, 28, 14));
    assert!(lines.len() <= 14);
    for line in &lines {
        assert!(line.width() <= 28, "{line:?}");
    }
    let text = lines_text(lines);
    for value in [
        "F-0001",
        "F-0002",
        "Descriptor policy",
        "Prompt override path",
        "unverified",
        "sources:2",
    ] {
        assert!(text.contains(value), "missing {value}: {text}");
    }
}

#[test]
fn compact_reading_preserves_learn_order_instead_of_claiming_default_sort() {
    let mut model = review_model(vec![review_row()]);
    model.ordering_indicator = Some(crate::ui_view_models::LEARN_ORDERING_INDICATOR);
    let text = lines_text(populated_review_queue_pane_lines(
        &model,
        Rect::new(0, 0, 28, 14),
    ));
    assert!(text.contains("learn"), "{text}");
    assert!(!text.contains("proof > severity"), "{text}");
}

#[test]
fn compact_reading_keeps_each_selected_identity_within_actual_height() {
    for height in [2, 3, 6, 14] {
        for selected in 0..20 {
            let rows = (0..20)
                .map(|i| {
                    grouped_row(
                        &format!("F-{:04}", i + 1),
                        ReviewWorkflowGroup::NeedsReview,
                        i == selected,
                    )
                })
                .collect();
            let lines =
                populated_review_queue_pane_lines(&review_model(rows), Rect::new(0, 0, 28, height));
            assert!(lines.len() <= usize::from(height), "{height}: {lines:?}");
            let text = lines_text(lines);
            assert!(text.contains(&format!("▸F-{:04}", selected + 1)), "{text}");
        }
    }
}

#[test]
fn compact_reading_keeps_occurrence_separate_from_proof() {
    let mut row = review_row();
    row.proof_confidence = ProofConfidence::Unverified;
    row.occurrence = Some(crate::ui_view_models::ReviewOccurrence {
        seen: 2,
        completed: 3,
        planned: 4,
        failed: 1,
    });
    let text = lines_text(populated_review_queue_pane_lines(
        &review_model(vec![row]),
        Rect::new(0, 0, 28, 14),
    ));
    assert!(text.contains("unverified"), "{text}");
    assert!(text.contains("occ 2/3 · p4 f1"), "{text}");
}

#[test]
fn compact_reading_full_frame_shows_both_titles_at_ordinary_widths() {
    use kuzushi_core::{Finding, Severity, V2Config};
    use ratatui::{backend::TestBackend, Terminal};
    for width in [80, 120] {
        let mut app = crate::ShellApp::new(V2Config::default(), None);
        app.set_shell_view(crate::ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(crate::app::WorkbenchPage::Review));
        app.set_findings(vec![
            Finding::new_semgrep(
                "policy",
                "src/policy.rs",
                2,
                None,
                Severity::High,
                "Descriptor policy allows inconsistent approval settings",
            ),
            Finding::new_semgrep(
                "path",
                "src/paths.rs",
                9,
                None,
                Severity::Medium,
                "Prompt override path escapes the selected directory",
            ),
        ]);
        let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let text = (0..24)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        for label in [
            "F-0001",
            "F-0002",
            "Descriptor policy",
            "Prompt override path",
        ] {
            assert!(text.contains(label), "{width}: missing {label}: {text}");
        }
    }
}

#[test]
fn compact_reading_detail_page_keys_scroll_without_retargeting() {
    use crate::ui_view_models::PhaseSurfaceId;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use kuzushi_core::{Finding, Severity, V2Config};
    let mut app = crate::ShellApp::new(V2Config::default(), None);
    app.set_viewport(crate::app::TerminalViewport {
        columns: 80,
        rows: 24,
    });
    app.set_shell_view(crate::ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Review));
    app.set_input_mode(crate::InputMode::Navigate);
    app.set_findings(vec![Finding::new_semgrep(
        "rule",
        "src/code.rs",
        2,
        None,
        Severity::High,
        "Claim with evidence to inspect",
    )]);
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ReviewDetail);
    let plan =
        crate::renderer::workbench_phase_plan_for_app(&app, Rect::new(0, 0, 80, 24)).unwrap();
    let inner = crate::renderer::shared::cockpit_pane_block("detail", false)
        .inner(plan.surface(PhaseSurfaceId::ReviewDetail).unwrap().rect);
    for (code, expected) in [(KeyCode::PageDown, inner.height), (KeyCode::PageUp, 0)] {
        crate::app::update_and_execute_effects(
            &mut app,
            crate::app::Msg::Term(crate::app::TermEvent::Key(KeyEvent::new(
                code,
                KeyModifiers::NONE,
            ))),
        );
        assert_eq!(
            app.router
                .workbench()
                .scroll()
                .get(PhaseSurfaceId::ReviewDetail),
            expected
        );
        assert_eq!(app.router.findings().cursor(), 0);
        assert!(!app.has_running_work());
    }
}
