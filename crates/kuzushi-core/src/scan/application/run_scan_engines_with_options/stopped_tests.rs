use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct StopScanner {
    id: &'static str,
    action: &'static str,
    calls: Arc<AtomicUsize>,
}
impl ScanEngine for StopScanner {
    fn id(&self) -> &'static str {
        self.id
    }
    fn scan(&self, _: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.action {
            "fail" => anyhow::bail!("labeled engine failure"),
            "cancel" => cancellation.cancel(),
            "interrupt" => cancellation.interrupt(),
            _ => (),
        }
        let path = if self.action == "outside" {
            "../outside.rs"
        } else {
            "app.rs"
        };
        Ok(vec![Finding::new_tool(
            self.id,
            "labeled",
            path,
            1,
            None,
            Severity::High,
            "Retained protocol observation",
        )])
    }
}

fn stopped_run(
    action: &'static str,
) -> (
    tempfile::TempDir,
    WorkspaceTarget,
    FindingStore,
    anyhow::Error,
    Arc<AtomicUsize>,
) {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    seed_prior_observation(&workspace, &store);
    let calls = Arc::new(AtomicUsize::new(0));
    let scanners = stop_scanners(action, &calls);
    let options = ScanRunOptions {
        run_id: Some("stopped-native".into()),
        ..Default::default()
    };
    let error = run_native_scan_with_cancellation(
        &workspace,
        &store,
        &scanners,
        &options,
        &Default::default(),
    )
    .unwrap_err();
    (root, workspace, store, error, calls)
}

fn stop_scanners(action: &'static str, calls: &Arc<AtomicUsize>) -> Vec<Box<dyn ScanEngine>> {
    [
        (
            "first",
            if matches!(action, "cancel" | "interrupt") {
                action
            } else {
                "ok"
            },
        ),
        ("second", action),
        ("third", "ok"),
    ]
    .into_iter()
    .map(|(id, action)| {
        Box::new(StopScanner {
            id,
            action,
            calls: Arc::clone(calls),
        }) as Box<dyn ScanEngine>
    })
    .collect()
}

#[test]
fn a_later_engine_failure_retains_observations_and_stops_the_fixed_plan() {
    let (_root, workspace, store, error, calls) = stopped_run("fail");
    let failure = native_scan_failure(&error).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(failure.status, crate::run_lifecycle::RunItemStatus::Failed);
    assert_eq!(failure.report.run.findings_count, 1);
    assert_eq!(
        failure.report.coverage.engines[1].disposition,
        NativeEngineDisposition::Failed
    );
    assert_eq!(
        failure.report.coverage.engines[2].disposition,
        NativeEngineDisposition::NotStarted
    );
    assert!(error.to_string().contains("1 observation(s) retained"));
    assert!(format!("{error:#}").contains("labeled engine failure"));
    assert_eq!(
        store.run_status("stopped-native").unwrap().as_deref(),
        Some("failed")
    );
    drop(store);
    let reopened = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert_eq!(
        reopened
            .list_findings_for_scan_id("stopped-native")
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        reopened.run_status("stopped-native").unwrap().as_deref(),
        Some("failed")
    );
}

#[test]
fn cancellation_and_interruption_retain_prior_output_without_starting_another_job() {
    for (action, status) in [("cancel", "canceled"), ("interrupt", "interrupted")] {
        let (_root, workspace, store, error, calls) = stopped_run(action);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(store
            .list_relevant_findings()
            .unwrap()
            .iter()
            .any(|finding| finding.file_path == "previous.rs"));
        let failure = native_scan_failure(&error).unwrap();
        assert_eq!(failure.status.label(), status);
        assert_eq!(
            failure.report.coverage.engines[0].disposition,
            NativeEngineDisposition::Complete
        );
        assert_eq!(
            failure.report.coverage.engines[1].disposition,
            NativeEngineDisposition::NotStarted
        );
        assert_eq!(
            store
                .list_findings_for_scan_id("stopped-native")
                .unwrap()
                .len(),
            1
        );
        drop(store);
        assert_eq!(
            FindingStore::open(workspace.findings_db_path())
                .unwrap()
                .run_status("stopped-native")
                .unwrap()
                .as_deref(),
            Some(status)
        );
    }
}

#[test]
fn rejecting_a_later_outside_path_does_not_import_it_or_discard_prior_evidence() {
    let (_root, _, store, error, calls) = stopped_run("outside");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        native_scan_failure(&error)
            .unwrap()
            .report
            .run
            .findings_count,
        1
    );
    let findings = store.list_findings_for_scan_id("stopped-native").unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].file_path, "app.rs");
}

#[test]
fn later_indexing_failure_retains_completed_discovery_and_a_failed_run() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let scanners = indexing_failure_fixture(&workspace);
    let options = ScanRunOptions {
        run_id: Some("indexing-stopped".into()),
        index_static_evidence: true,
        ..Default::default()
    };
    let error = run_native_scan_with_cancellation(
        &workspace,
        &store,
        &scanners,
        &options,
        &Default::default(),
    )
    .unwrap_err();
    let failure = native_scan_failure(&error).unwrap();
    assert_eq!(failure.report.run.findings_count, 1);
    assert_eq!(
        failure.report.coverage.engines[0].disposition,
        NativeEngineDisposition::Complete
    );
    assert!(error.to_string().contains("0 planned job(s) not started"));
    assert_eq!(
        store.run_status("indexing-stopped").unwrap().as_deref(),
        Some("failed")
    );
    assert_eq!(
        store
            .list_findings_for_scan_id("indexing-stopped")
            .unwrap()
            .len(),
        1
    );
}

fn indexing_failure_fixture(workspace: &WorkspaceTarget) -> Vec<Box<dyn ScanEngine>> {
    let evidence_path = crate::static_evidence::static_evidence_path(workspace);
    fs::create_dir_all(evidence_path.parent().unwrap()).unwrap();
    fs::create_dir(evidence_path).unwrap();
    vec![Box::new(StopScanner {
        id: "semgrep",
        action: "ok",
        calls: Arc::new(AtomicUsize::new(0)),
    })]
}

fn seed_prior_observation(workspace: &WorkspaceTarget, store: &FindingStore) {
    let finding = Finding::new_tool(
        "prior",
        "labeled",
        "previous.rs",
        1,
        None,
        Severity::High,
        "Prior observation",
    );
    store
        .record_run_started("prior", workspace.root(), "running")
        .unwrap();
    store.insert_finding("prior", &finding).unwrap();
    store.record_run_finished("prior", "completed", 1).unwrap();
}
