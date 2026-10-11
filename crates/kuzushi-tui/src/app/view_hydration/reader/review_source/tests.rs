use super::*;
use kuzushi_core::findings::{ReviewDecision, ReviewDecisionVerdict, TriageAuthor};
use kuzushi_core::{Finding, FindingStore, RunSummary, RunTargetGitMetadata, Severity};
use std::fs;

fn seed(target: &Path) -> (Finding, ViewHydrationKey) {
    fs::create_dir_all(target.join("src")).unwrap();
    fs::write(target.join("README.md"), "Labeled synthetic findings and commit metadata for TUI testing. Source is never executed.\n").unwrap();
    fs::write(
        target.join("src/lib.rs"),
        "// Labeled source, never executed.\npub fn record() -> u8 { 1 }\n",
    )
    .unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(target).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("fixture-a", target, "completed")
        .unwrap();
    let finding = Finding::new_tool(
        "fixture",
        "fixture.review-source",
        "src/lib.rs",
        2,
        None,
        Severity::High,
        "Synthetic decision-source finding",
    );
    let id = store.insert_finding("fixture-a", &finding).unwrap();
    store
        .append_user_review_decision(
            id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "Synthetic operator decision on source A".into(),
                dismiss_reason: None,
                actor: Some("fixture-operator".into()),
            },
        )
        .unwrap();
    let decision = store.list_review_decisions(id).unwrap().pop().unwrap();
    let watermark = decision.provenance.unwrap().read_watermark.unwrap();
    fs::write(
        target.join("src/lib.rs"),
        "// Labeled source, never executed.\npub fn record() -> u8 { 2 }\n",
    )
    .unwrap();
    store
        .record_run_started("fixture-b", target, "completed")
        .unwrap();
    let id = store.insert_finding("fixture-b", &finding).unwrap();
    store
        .append_user_review_decision(
            id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::NeedsReview,
                author: TriageAuthor::Imported,
                confidence: 0.5,
                rationale: "Synthetic imported assessment on later source B".into(),
                dismiss_reason: None,
                actor: Some("fixture-import".into()),
            },
        )
        .unwrap();
    for (run, digit) in [("fixture-a", '1'), ("fixture-b", '2')] {
        let mut summary =
            RunSummary::running(run, "fixture:scan", None, target.display().to_string());
        summary.target_git = Some(RunTargetGitMetadata {
            sha: digit.to_string().repeat(40),
            branch: Some("main".into()),
            dirty: false,
        });
        kuzushi_core::write_run_summary(target, &summary.complete()).unwrap();
    }
    let current = store
        .get_finding_by_fingerprint(&finding.fingerprint)
        .unwrap()
        .unwrap();
    let stable_fp = kuzushi_core::findings::finding_observation_identity(&current).to_owned();
    (
        current,
        ViewHydrationKey::FindingReviewSource {
            stable_fp,
            decision_watermark: watermark,
            observation_watermark: None,
        },
    )
}

#[test]
fn review_source_reader_keeps_the_human_basis_and_reads_both_recorded_revisions() {
    let root = tempfile::tempdir().unwrap();
    let (_, key) = seed(root.path());
    let before = fs::read(root.path().join(".kuzushi/v3/runs/fixture-a/run.json")).unwrap();
    let Some(ViewHydrationValue::FindingReviewSource(Ok(Some(source)))) =
        read_review_source(root.path(), &key)
    else {
        panic!("source receipt unavailable");
    };
    assert_eq!(source.basis.run_id, "fixture-a");
    assert!(source.basis.source_changed_since_decision);
    assert!(matches!(
        source.decided_revision,
        RecordedSourceRevision::Known(_)
    ));
    assert!(matches!(
        source.later_revision,
        Some(RecordedSourceRevision::Known(_))
    ));
    assert_eq!(
        before,
        fs::read(root.path().join(".kuzushi/v3/runs/fixture-a/run.json")).unwrap()
    );
}

#[test]
fn damaged_revision_metadata_is_disclosed_without_losing_the_ledger_basis() {
    let root = tempfile::tempdir().unwrap();
    let (_, key) = seed(root.path());
    fs::write(
        root.path().join(".kuzushi/v3/runs/fixture-a/run.json"),
        "broken metadata",
    )
    .unwrap();
    let Some(ViewHydrationValue::FindingReviewSource(Ok(Some(source)))) =
        read_review_source(root.path(), &key)
    else {
        panic!("source receipt unavailable");
    };
    assert_eq!(source.basis.run_id, "fixture-a");
    assert_eq!(source.decided_revision, RecordedSourceRevision::Unreadable);
}

#[test]
fn source_inspection_never_repairs_an_abandoned_running_metadata_file() {
    let root = tempfile::tempdir().unwrap();
    let (_, key) = seed(root.path());
    let path = root.path().join(".kuzushi/v3/runs/fixture-a/run.json");
    let mut summary: RunSummary = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    summary.status = "running".into();
    summary.process_id = Some(u32::MAX);
    summary.completed_at_unix = None;
    let bytes = serde_json::to_vec_pretty(&summary).unwrap();
    fs::write(&path, &bytes).unwrap();
    let Some(ViewHydrationValue::FindingReviewSource(Ok(Some(source)))) =
        read_review_source(root.path(), &key)
    else {
        panic!("source receipt unavailable");
    };
    assert!(matches!(
        source.decided_revision,
        RecordedSourceRevision::Known(_)
    ));
    assert_eq!(
        bytes,
        fs::read(path).unwrap(),
        "source inspection must be read-only"
    );
}

#[test]
fn real_ledger_hydration_reaches_the_selected_review_detail_without_stealing_input() {
    let root = tempfile::tempdir().unwrap();
    let (finding, _) = seed(root.path());
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.refresh_findings(false);
    app.set_workbench_page(crate::WorkbenchPage::Review);
    app.set_input_mode(crate::InputMode::Prompt);
    let key = crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('d'),
        crossterm::event::KeyModifiers::NONE,
    );
    app.reduce_key(key);
    app.hydrate_all_view_data_for_test();
    let detail = crate::ui_view_models::selected_finding_detail_model(&app).unwrap();
    assert_eq!(detail.fingerprint, finding.fingerprint);
    assert_eq!(detail.decision, "confirmed");
    let source = detail.decision_basis.unwrap();
    assert!(source.warning);
    assert!(source
        .rows
        .iter()
        .any(|row| row == "Decision observation: fixture-a"));
    assert!(source
        .rows
        .iter()
        .any(|row| row.contains("Later commit: 222222222222")));
    assert_eq!(app.input(), "d");
    assert_eq!(app.input_mode(), crate::InputMode::Prompt);
}

#[test]
fn narrow_review_open_reveals_the_hidden_detail_instead_of_leaving_the_queue_visible() {
    let root = tempfile::tempdir().unwrap();
    let (finding, _) = seed(root.path());
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.refresh_findings(false);
    app.set_workbench_page(crate::WorkbenchPage::Review);
    app.set_viewport(crate::TerminalViewport::new(60, 20));
    app.open_finding_at_cursor();
    let plan = crate::renderer::workbench_phase_plan_for_app(
        &app,
        ratatui::layout::Rect::new(0, 0, 60, 20),
    )
    .unwrap();
    assert!(plan
        .surface(crate::ui_view_models::PhaseSurfaceId::ReviewDetail)
        .is_some());
    assert_eq!(
        plan.effective_focus,
        crate::ui_view_models::PhaseSurfaceId::ReviewDetail
    );
    assert_eq!(
        app.selected_finding().as_ref().unwrap().fingerprint,
        finding.fingerprint
    );
}

#[test]
fn changed_source_requires_review_and_new_decision_restores_completion() {
    let root = tempfile::tempdir().unwrap();
    let (finding, _) = seed(root.path());
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.refresh_findings(false);
    assert_eq!(app.domain().finding_ledger_counts().unwrap().reviewed, 0);
    assert!(app.domain().review_source_needs_reassessment(&finding));
    let open = crate::ui_view_models::review_queue_model(
        &app,
        crate::ui_view_models::ReviewQueueMode::Open,
    );
    assert_eq!(open.open_count, 1);
    let workspace = kuzushi_core::WorkspaceTarget::new(root.path()).unwrap();
    kuzushi_core::workspace::record_user_review_decision_for_finding(
        &workspace,
        &finding,
        &ReviewDecision {
            verdict: ReviewDecisionVerdict::Deferred,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: "Reviewed source B".into(),
            dismiss_reason: None,
            actor: Some("operator".into()),
        },
    )
    .unwrap();
    app.refresh_findings(false);
    assert_eq!(app.domain().finding_ledger_counts().unwrap().reviewed, 1);
    assert!(!app.domain().review_source_needs_reassessment(&finding));
    let open = crate::ui_view_models::review_queue_model(
        &app,
        crate::ui_view_models::ReviewQueueMode::Open,
    );
    assert_eq!(open.open_count, 0);
}

#[test]
fn prepare_native_review_source_fixture() {
    let Some(path) = std::env::var_os("KUZUSHI_REVIEW_SOURCE_FIXTURE_OUT") else {
        return;
    };
    let root = PathBuf::from(path);
    fs::create_dir_all(&root).unwrap();
    let (finding, key) = seed(&root);
    let document = serde_json::json!({"findingFingerprint":finding.fingerprint,"key":format!("{key:?}"),"findingsAreSynthetic":true,"commitMetadataIsSynthetic":true,"sourceExecuted":false,"providerRequests":0});
    fs::write(
        root.join("fixture-receipt.json"),
        serde_json::to_vec_pretty(&document).unwrap(),
    )
    .unwrap();
}
