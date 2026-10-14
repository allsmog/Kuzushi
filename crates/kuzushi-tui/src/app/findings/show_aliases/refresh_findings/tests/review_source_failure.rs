use super::*;

fn confirmed_finding() -> Finding {
    Finding {
        fingerprint: "labeled-source-failure".into(),
        triage: Some(kuzushi_core::TriageOutcome {
            verdict: kuzushi_core::TriageVerdict::TruePositive,
            confidence: 1.0,
            rationale: "Labeled operator verdict".into(),
            ..Default::default()
        }),
        triaged_by: Some(kuzushi_core::findings::TriageAuthor::Human),
        ..Finding::default()
    }
}

#[test]
fn unavailable_review_source_clears_current_confirmed_count() {
    let findings = vec![confirmed_finding()];
    let mut app = ShellApp::new(V2Config::default(), None);
    let counts = crate::ui_view_models::finding_ledger_counts(&findings, &[], 1);
    assert_eq!((counts.reviewed, counts.confirmed), (1, 1));

    app.apply_snapshot_counts(&unavailable_source_snapshot(findings));

    let counts = app.domain().finding_ledger_counts().unwrap();
    assert_eq!((counts.reviewed, counts.confirmed), (0, 0));
}

#[test]
fn unavailable_review_source_keeps_terminal_decisions_open() {
    let findings = vec![confirmed_finding()];
    let mut app = ShellApp::new(V2Config::default(), None);
    app.apply_snapshot_counts(&unavailable_source_snapshot(findings.clone()));
    app.domain_mut().set_findings(findings);

    let queue = crate::ui_view_models::review_queue_model(
        &app,
        crate::ui_view_models::ReviewQueueMode::Open,
    );
    assert_eq!(queue.visible_count, 1);
    assert_eq!(queue.complete_count, 0);
    assert_eq!(app.domain().review_source_reassessment_count(), 1);
}

fn unavailable_source_snapshot(findings: Vec<Finding>) -> FindingsReadSnapshot {
    FindingsReadSnapshot {
        page_recovery_notice: None,
        target: Default::default(),
        watermark: None,
        policy: IdentityFoldPolicy::Legacy,
        report: FindingListReport {
            count: findings.len(),
            findings: findings.clone(),
            aliases: vec![],
            review_decisions: Default::default(),
        },
        corpus: findings,
        review_decisions: vec![],
        completion: Err("Labeled unavailable source".into()),
        legacy_lifecycles: vec![],
        warnings: vec![],
        page: Default::default(),
    }
}
