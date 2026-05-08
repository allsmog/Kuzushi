use super::*;

pub(crate) fn run_scan_worker_scanners(
    session: ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    options: &ScanRunOptions,
    scanners: Vec<Box<dyn ScanEngine>>,
) -> Result<()> {
    let Some(findings) = collect_scan_worker_findings(&session, tx, cancel, scanners)? else {
        return Ok(());
    };
    finish_scan_worker_findings(session, tx, options, findings)
}

pub(crate) fn finish_scan_worker_findings(
    session: ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    options: &ScanRunOptions,
    mut findings: Vec<Finding>,
) -> Result<()> {
    apply_scan_worker_severity_filter(&mut findings, options);
    persist_scan_worker_findings(&session, tx, &findings)?;
    finish_scan_worker_session(session, tx, findings.len())
}

pub(crate) struct ScanWorkerSession {
    pub(crate) workspace: WorkspaceTarget,
    pub(crate) store: FindingStore,
    pub(crate) run_id: String,
}

pub(crate) fn start_scan_worker_session(
    target: PathBuf,
    db_path: PathBuf,
    tx: &Sender<ScanEvent>,
) -> Result<ScanWorkerSession> {
    let (workspace, store) = start_scan_worker_resources(target, db_path)?;
    let run_id = create_scan_worker_run(&store, workspace.root())?;
    announce_scan_worker_started(tx, &run_id, workspace.root());

    Ok(ScanWorkerSession {
        workspace,
        store,
        run_id,
    })
}

pub(crate) fn start_scan_worker_resources(
    target: PathBuf,
    db_path: PathBuf,
) -> Result<(WorkspaceTarget, FindingStore)> {
    let workspace = prepare_scan_worker_workspace(target)?;
    let store = FindingStore::open(db_path)?;
    Ok((workspace, store))
}

pub(crate) fn prepare_scan_worker_workspace(target: PathBuf) -> Result<WorkspaceTarget> {
    let workspace = WorkspaceTarget::new(&target)?;
    workspace.ensure_state_dir()?;
    Ok(workspace)
}

pub(crate) fn create_scan_worker_run(
    store: &FindingStore,
    target: &std::path::Path,
) -> Result<String> {
    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, target, "running")?;
    Ok(run_id)
}

pub(crate) fn announce_scan_worker_started(
    tx: &Sender<ScanEvent>,
    run_id: &str,
    target: &std::path::Path,
) {
    let _ = tx.send(ScanEvent::Started {
        run_id: run_id.to_string(),
        target: target.to_path_buf(),
    });
    let _ = tx.send(ScanEvent::Stage("running scan".to_string()));
}

pub(crate) fn scan_worker_engines(options: &ScanRunOptions) -> Result<Vec<Box<dyn ScanEngine>>> {
    if let Some(tasks) = options.tasks.as_ref() {
        return kuzushi_core::scan_engines_for_tasks(tasks);
    }
    Ok(default_scan_engines())
}

pub(crate) fn collect_scan_worker_findings(
    session: &ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    scanners: Vec<Box<dyn ScanEngine>>,
) -> Result<Option<Vec<Finding>>> {
    let mut findings = Vec::new();
    let cancelled = scanners.into_iter().try_fold(false, |cancelled, scanner| {
        scan_worker_fold_step(cancelled, session, tx, cancel, scanner, &mut findings)
    })?;
    Ok(scan_worker_findings_result(cancelled, findings))
}

fn scan_worker_fold_step(
    cancelled: bool,
    session: &ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    scanner: Box<dyn ScanEngine>,
    findings: &mut Vec<Finding>,
) -> Result<bool> {
    if cancelled {
        return Ok(true);
    }
    scan_worker_step(session, tx, cancel, scanner, findings)
}

fn scan_worker_findings_result(cancelled: bool, findings: Vec<Finding>) -> Option<Vec<Finding>> {
    (!cancelled).then_some(findings)
}

pub(crate) fn scan_worker_step(
    session: &ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    scanner: Box<dyn ScanEngine>,
    findings: &mut Vec<Finding>,
) -> Result<bool> {
    cancel.wait_if_paused();
    if cancel_scan_worker_if_requested(session, tx, cancel, findings.len())? {
        return Ok(true);
    }
    run_scan_worker_engine(session, tx, cancel, scanner, findings)
}
