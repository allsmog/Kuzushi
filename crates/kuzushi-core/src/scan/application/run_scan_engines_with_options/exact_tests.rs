use super::*;

struct UncontainedObservation;
struct CanceledExactDiscovery;

impl ScanEngine for CanceledExactDiscovery {
    fn id(&self) -> &'static str {
        "labeled-canceled-exact-fixture"
    }
    fn supports_exact_files(&self) -> bool {
        true
    }
    fn scan(&self, _: &Path, _: &ScanCancellation) -> Result<Vec<Finding>> {
        unreachable!()
    }
    fn scan_exact_files(
        &self,
        _: &Path,
        _: &[String],
        cancellation: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        cancellation.cancel();
        Ok(ScanEngineOutput {
            findings: vec![Finding::new_tool(
                self.id(),
                "Labeled retained observation",
                "included.py",
                1,
                None,
                Severity::Low,
                "fixture",
            )],
            scan_errors: vec![
                "Operator canceled discovery; selected files remain unsearched".into(),
            ],
            ..Default::default()
        })
    }
}

impl ScanEngine for UncontainedObservation {
    fn id(&self) -> &'static str {
        "labeled-exact-fixture"
    }
    fn supports_exact_files(&self) -> bool {
        true
    }
    fn scan(&self, _target: &Path, _cancel: &ScanCancellation) -> Result<Vec<Finding>> {
        panic!("exact membership must never call directory discovery");
    }
    fn scan_exact_files(
        &self,
        _root: &Path,
        files: &[String],
        _cancel: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        assert_eq!(files, ["included.py"]);
        Ok(ScanEngineOutput::from_findings(vec![Finding::new_tool(
            "labeled-fixture",
            "Labeled outside observation",
            "excluded.py",
            1,
            None,
            Severity::Low,
            "fixture",
        )]))
    }
}

#[test]
fn exact_native_pipeline_refuses_outside_observations_and_preserves_the_failed_receipt() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("included.py"),
        "print('Labeled fixture')\n",
    )
    .unwrap();
    fs::write(
        root.path().join("excluded.py"),
        "print('Excluded fixture')\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    workspace.ensure_state_dir().unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let options = ScanRunOptions {
        run_id: Some("exact-outside-fixture".into()),
        ..Default::default()
    };
    let error = run_native_scan_files_with_cancellation(
        &workspace,
        &store,
        &[Box::new(UncontainedObservation)],
        &options,
        &["included.py".into()],
        &Default::default(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("outside accepted file membership"));
    assert!(store.list_findings(10).unwrap().is_empty());
    assert_eq!(
        store
            .run_status("exact-outside-fixture")
            .unwrap()
            .as_deref(),
        Some("failed")
    );
}

#[test]
fn exact_native_skipped_binary_source_reports_partial_coverage() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("selected.bin"), [0, 1, 2, 3]).unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    workspace.ensure_state_dir().unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let report = run_native_scan_files_with_cancellation(
        &workspace,
        &store,
        &[Box::new(SecretScanScanner)],
        &Default::default(),
        &["selected.bin".into()],
        &Default::default(),
    )
    .unwrap();
    assert_eq!(report.run.findings_count, 0);
    assert!(report.coverage.has_gaps());
    assert!(report.coverage.engines[0].scan_errors[0].contains("skipped 1 selected files"));
}

#[test]
fn canceled_exact_discovery_keeps_partial_observations_and_never_starts_another_engine() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("included.py"), "print('Labeled source')\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    workspace.ensure_state_dir().unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let scanners: Vec<Box<dyn ScanEngine>> = vec![
        Box::new(CanceledExactDiscovery),
        Box::new(UncontainedObservation),
    ];
    let error = run_native_scan_files_with_cancellation(
        &workspace,
        &store,
        &scanners,
        &Default::default(),
        &["included.py".into()],
        &Default::default(),
    )
    .unwrap_err();
    let failure = native_scan_failure(&error).unwrap();
    assert_eq!(failure.report.run.findings_count, 1);
    assert_eq!(
        failure.report.coverage.engines[0].disposition,
        NativeEngineDisposition::Canceled
    );
    assert_eq!(
        failure.report.coverage.engines[1].disposition,
        NativeEngineDisposition::NotStarted
    );
    assert_eq!(store.list_findings(10).unwrap().len(), 1);
}
