use super::*;
use kuzushi_core::workflow_attempts::{
    PhaseAttemptCompleted, PhaseAttemptDisposition, PhaseAttemptDispositionRecorded,
    PhaseAttemptEvent, PhaseAttemptLedger, PhaseAttemptOutcome, PhaseTargetSnapshot,
};

#[test]
fn report_header_prioritizes_the_target_and_review_counts_without_route_diagnostics() {
    let mut app = app_with_current_revision("a");
    app.set_target(Some(std::path::PathBuf::from("/report-source-reading")));
    let lines = report_header_lines(&app, Rect::new(0, 0, 40, 8));
    let text = lines
        .iter()
        .map(Line::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("REPORT"));
    assert!(text.contains("report-source-reading"));
    assert!(!text.contains("module route") && !text.contains("view:report"));
    assert!(lines.len() <= 4);
}

#[test]
fn source_reassessment_header_and_explanation_survive_every_viewport_and_plain_output() {
    let mut app = app_with_current_revision("a");
    app.set_target(Some(std::path::PathBuf::from("/report-source-reading")));
    app.router.report_mut().toggle_scope();
    app.domain_mut()
        .set_review_source_applicabilities(std::collections::BTreeMap::from([(
            "recorded-marker".into(),
            kuzushi_core::workspace::WorkspaceReviewSourceApplicability::LaterSourceUnverified,
        )]));
    hydrate_workspace_review(&app);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let area = Rect::new(0, 0, width, height);
        let header = report_header_lines(&app, area);
        let text = header
            .iter()
            .map(Line::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            text.contains("source review needed: 1"),
            "{width}x{height}: {text}"
        );
        assert!(header.iter().all(|line| line.width() <= width as usize));
        let document = report_document_lines(&app, area)
            .iter()
            .map(Line::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(document.contains("Earlier decisions remain recorded."));
    }
    let plain = crate::renderer::render_plain_app(&app, 40);
    let words = plain.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(words.contains("source review needed: 1"));
    assert!(words.contains("Earlier decisions remain recorded."));
    assert!(!plain.contains('\u{1b}'));
}

fn app_with_current_revision(revision: &str) -> ShellApp {
    let original = PhaseTargetSnapshot {
        target: "/report-source-reading".into(),
        revision: Some("a".repeat(40)),
        dirty: false,
    };
    let attempt = PhaseAttemptCompleted::new(
        kuzushi_core::WorkflowPhase::Scan,
        vec!["recorded-study-trial".into()],
        original.clone(),
        PhaseAttemptOutcome::Completed,
    );
    let selected = PhaseAttemptDispositionRecorded::new(
        &attempt.attempt_id,
        PhaseAttemptDisposition::Selected {
            acknowledged_partial: false,
        },
    );
    let ledger = PhaseAttemptLedger::from_events([
        PhaseAttemptEvent::PhaseAttemptCompleted(attempt),
        PhaseAttemptEvent::PhaseAttemptDispositionRecorded(selected),
    ])
    .unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.engagement.set_phase_attempt_projection_health(
        Some(PhaseTargetSnapshot {
            revision: Some(revision.repeat(40)),
            ..original
        }),
        ledger,
        false,
    );
    app.set_shell_view(crate::ShellView::Report);
    app
}

#[test]
fn earlier_source_notice_stays_visible_while_reading_at_every_width() {
    let mut app = app_with_current_revision("b");
    for (width, height) in [(40, 7), (60, 12), (80, 16), (96, 80), (120, 28), (160, 40)] {
        for offset in [0, 10, u16::MAX] {
            app.router.default_scroll_mut().set(offset);
            let lines = report_lines(&app, Rect::new(0, 0, width, height));
            assert_eq!(lines[2].to_string(), "Earlier source · reassess checkout");
            assert!(lines.iter().all(|line| line.width() <= width as usize));
            assert!(lines.len() <= height as usize);
        }
    }
}

#[test]
fn report_paging_reaches_the_tail_with_a_source_notice() {
    let mut app = app_with_current_revision("b");
    app.set_viewport(crate::TerminalViewport::new(40, 12));
    for _ in 0..30 {
        let offset = report_offset_after_page(&app, 1);
        app.router.default_scroll_mut().set(offset as u16);
    }
    let area = crate::renderer::primary_body_area(&app, Rect::new(0, 0, 40, 12));
    let lines = report_lines(&app, area);
    assert_eq!(lines[2].to_string(), "Earlier source · reassess checkout");
    assert_eq!(lines.last(), report_document_lines(&app, area).last());
    let tail = app.router.default_scroll().offset();
    assert_eq!(report_offset_after_page(&app, 1), tail as usize);
    assert!(report_offset_after_page(&app, -1) < tail as usize);
}

#[test]
fn a_study_on_current_source_has_no_earlier_source_notice() {
    let app = app_with_current_revision("a");
    assert_eq!(crate::ui_view_models::report_source_notice(&app), None);
    assert_eq!(report_reader_height(&app, 7), 5);
}

#[test]
fn plain_report_discloses_earlier_source_without_terminal_styles() {
    let app = app_with_current_revision("b");
    let text = crate::renderer::render_plain_app(&app, 40);
    assert!(text.contains("Earlier source · reassess checkout"));
    assert!(!text.contains('\u{1b}'));
}

#[test]
fn explicitly_selected_history_does_not_claim_current_source_assessment() {
    let mut app = app_with_current_revision("a");
    app.router
        .report_mut()
        .set_study(Some(crate::app::ReportStudyRef {
            campaign_id: "historical-study".into(),
            plan_sha256: "recorded-plan".into(),
        }));
    assert_eq!(
        crate::ui_view_models::report_source_notice(&app),
        Some("Recorded source · current unassessed")
    );
    app.router.report_mut().toggle_scope();
    assert_eq!(
        crate::ui_view_models::report_source_notice(&app),
        Some("History · current source unassessed")
    );
}

#[test]
fn source_notice_reading_preserves_the_draft_and_destination_editor() {
    let mut app = app_with_current_revision("b");
    app.set_input("retained report draft");
    let draft = app.input().to_owned();
    let cursor = app.cursor();
    report_lines(&app, Rect::new(0, 0, 40, 7));
    report_offset_after_page(&app, 1);
    assert_eq!(app.input(), draft);
    assert_eq!(app.cursor(), cursor);
    app.router.report_mut().set_editing_path(true);
    let editing = report_lines(&app, Rect::new(0, 0, 40, 7));
    assert!(editing[0].to_string().contains("EXPORT DESTINATION"));
    assert!(!editing
        .iter()
        .any(|line| line.to_string().contains("Earlier source")));
}

fn hydrate_workspace_review(app: &ShellApp) {
    let key = crate::app::ViewHydrationKey::WorkspaceReportReview {
        findings_watermark: app.findings_read_watermark(),
    };
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(crate::app::ViewHydrationResult {
            target: app.target_owned().unwrap(),
            key,
            value: crate::app::ViewHydrationValue::WorkspaceReportReview(Ok(
                kuzushi_core::workspace::WorkspaceReviewSummary {
                    finding_count: 2,
                    reassessment_required: 1,
                    ..Default::default()
                },
            )),
        });
}
