use super::*;

pub(crate) fn cancel_scan_worker_if_requested(
    session: &ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    findings_count: usize,
) -> Result<bool> {
    if !cancel.is_cancelled() {
        return Ok(false);
    }
    session
        .store
        .complete_scan_run(&session.run_id, "cancelled", findings_count)?;
    let _ = tx.send(ScanEvent::Cancelled {
        run_id: session.run_id.clone(),
    });
    Ok(true)
}

pub(crate) fn run_scan_worker_engine(
    session: &ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    scanner: Box<dyn ScanEngine>,
    findings: &mut Vec<Finding>,
) -> Result<bool> {
    let _ = tx.send(ScanEvent::Stage(format!("running {}", scanner.id())));
    match scanner.scan(session.workspace.root(), cancel) {
        Ok(mut scanner_findings) => {
            findings.append(&mut scanner_findings);
            Ok(false)
        }
        Err(error) => handle_scan_worker_engine_error(session, tx, cancel, findings.len(), error),
    }
}

pub(crate) fn handle_scan_worker_engine_error(
    session: &ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    findings_count: usize,
    error: anyhow::Error,
) -> Result<bool> {
    if cancel.is_cancelled() {
        return cancel_scan_worker_if_requested(session, tx, cancel, findings_count);
    }
    Err(error)
}

pub(crate) fn apply_scan_worker_severity_filter(
    findings: &mut Vec<Finding>,
    options: &ScanRunOptions,
) {
    if let Some(allowed) = &options.severity {
        findings.retain(|finding| allowed.contains(&finding.severity));
    }
}

pub(crate) fn persist_scan_worker_findings(
    session: &ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    findings: &[Finding],
) -> Result<()> {
    let _ = tx.send(ScanEvent::Stage(format!(
        "persisting {} finding(s)",
        findings.len()
    )));

    for finding in findings {
        session.store.insert_finding(&session.run_id, finding)?;
        let _ = tx.send(ScanEvent::FindingStored {
            fingerprint: finding.fingerprint.clone(),
            severity: finding.severity,
            title: finding.title.clone(),
        });
    }
    Ok(())
}

pub(crate) fn finish_scan_worker_session(
    session: ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    findings_count: usize,
) -> Result<()> {
    session
        .store
        .complete_scan_run(&session.run_id, "completed", findings_count)?;
    let _ = tx.send(ScanEvent::Finished {
        run_id: session.run_id,
        findings_count,
    });
    Ok(())
}
