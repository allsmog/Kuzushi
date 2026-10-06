use super::*;

struct GapScanner {
    finding: bool,
}
impl ScanEngine for GapScanner {
    fn id(&self) -> &'static str {
        "gap-scanner"
    }
    fn scan(&self, _: &Path, _: &ScanCancellation) -> Result<Vec<Finding>> {
        unreachable!("use artifacts")
    }
    fn scan_artifacts(&self, _: &Path, _: &ScanCancellation) -> Result<ScanEngineOutput> {
        let findings = self
            .finding
            .then(|| {
                Finding::new_tool(
                    "gap-scanner",
                    "demo",
                    "app.rs",
                    1,
                    None,
                    Severity::High,
                    "retained source observation",
                )
            })
            .into_iter()
            .collect();
        Ok(ScanEngineOutput {
            findings,
            scan_errors: vec!["unread file broken.rs".into()],
            ..Default::default()
        })
    }
}

#[test]
fn typed_native_run_retains_findings_and_durable_partial_coverage() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("service")).unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let options = ScanRunOptions {
        run_id: Some("partial-native".into()),
        paths: vec!["service".into()],
        ..Default::default()
    };
    let scanners: Vec<Box<dyn ScanEngine>> = vec![Box::new(GapScanner { finding: true })];
    let report = run_native_scan_with_cancellation(
        &workspace,
        &store,
        &scanners,
        &options,
        &Default::default(),
    )
    .unwrap();
    assert!(report.coverage.has_gaps());
    assert_eq!(report.run.findings_count, 1);
    assert_eq!(report.coverage.engines[0].scope.as_deref(), Some("service"));
    assert_eq!(
        store.run_status("partial-native").unwrap().as_deref(),
        Some("partial")
    );
    assert_eq!(
        store.list_findings_for_scan_id("partial-native").unwrap()[0].file_path,
        "service/app.rs"
    );
}

#[test]
fn legacy_callers_receive_an_error_after_preserving_partial_observations() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let options = ScanRunOptions {
        run_id: Some("legacy-partial".into()),
        ..Default::default()
    };
    let scanners: Vec<Box<dyn ScanEngine>> = vec![Box::new(GapScanner { finding: true })];
    let error = run_scan_engines_with_options(&workspace, &store, &scanners, &options).unwrap_err();
    assert!(error.to_string().contains("unread file broken.rs"));
    assert_eq!(
        store
            .list_findings_for_scan_id("legacy-partial")
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store.run_status("legacy-partial").unwrap().as_deref(),
        Some("partial")
    );
}

#[test]
fn an_empty_typed_result_with_gaps_is_partial_rather_than_clean() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let scanners: Vec<Box<dyn ScanEngine>> = vec![Box::new(GapScanner { finding: false })];
    let report = run_native_scan_with_cancellation(
        &workspace,
        &store,
        &scanners,
        &Default::default(),
        &Default::default(),
    )
    .unwrap();
    assert!(report.coverage.has_gaps());
    assert_eq!(report.run.findings_count, 0);
    assert_eq!(
        store.run_status(&report.run.id).unwrap().as_deref(),
        Some("partial")
    );
}

#[test]
fn partial_absence_preserves_prior_findings_across_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let finding = Finding::new_tool(
        "secret-scan",
        "token",
        "app.rs",
        1,
        None,
        Severity::High,
        "prior observation",
    );
    store
        .record_run_started("prior", workspace.root(), "running")
        .unwrap();
    store.insert_finding("prior", &finding).unwrap();
    store.record_run_finished("prior", "completed", 1).unwrap();
    let scanners: Vec<Box<dyn ScanEngine>> = vec![Box::new(GapScanner { finding: false })];
    let options = ScanRunOptions {
        run_id: Some("incomplete-followup".into()),
        ..Default::default()
    };
    run_native_scan_with_cancellation(&workspace, &store, &scanners, &options, &Default::default())
        .unwrap();
    assert_eq!(store.list_relevant_findings().unwrap().len(), 1);
    drop(store);
    let reopened = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert_eq!(reopened.list_relevant_findings().unwrap().len(), 1);
    assert_eq!(
        reopened
            .run_status("incomplete-followup")
            .unwrap()
            .as_deref(),
        Some("partial")
    );
}
