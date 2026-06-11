use anyhow::Result;
use kuzushi_core::{
    export_workspace_findings, FindingStore, Severity, WorkspaceExportFormat, WorkspaceTarget,
};
use std::path::PathBuf;

/// Post-scan CI policy: SARIF export and severity gating. Applied after scan
/// output and run artifacts are emitted, so reports are complete before any
/// gate exit fires.
#[derive(Debug, Default)]
pub(crate) struct ScanGatePolicy {
    pub(crate) fail_on: Option<Severity>,
    pub(crate) sarif: Option<PathBuf>,
}

/// Exit code when `--fail-on` trips. Distinct from 1 (operational failure) so
/// CI can tell "the scanner broke" from "the scan worked and found blocking
/// issues". Documented in README and the reference workflow.
pub(crate) const FAIL_ON_EXIT_CODE: i32 = 3;

pub(crate) fn apply_scan_gate_policy(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    scan_id: &str,
    policy: &ScanGatePolicy,
) -> Result<()> {
    if let Some(path) = &policy.sarif {
        let export =
            export_workspace_findings(workspace, path, Some(WorkspaceExportFormat::Sarif))?;
        eprintln!(
            "sarif: wrote {} finding(s) to {}",
            export.count,
            export.output_path.display()
        );
    }
    if let Some(threshold) = policy.fail_on {
        enforce_fail_on(store, scan_id, threshold)?;
    }
    Ok(())
}

fn enforce_fail_on(store: &FindingStore, scan_id: &str, threshold: Severity) -> Result<()> {
    let blocking = count_blocking_findings(store, scan_id, threshold)?;
    if blocking == 0 {
        return Ok(());
    }
    eprintln!(
        "fail-on: {blocking} finding(s) at or above {} for scan {scan_id} (exit {FAIL_ON_EXIT_CODE})",
        severity_gate_label(threshold),
    );
    std::process::exit(FAIL_ON_EXIT_CODE);
}

pub(crate) fn count_blocking_findings(
    store: &FindingStore,
    scan_id: &str,
    threshold: Severity,
) -> Result<usize> {
    let Some(threshold_rank) = severity_gate_rank(threshold) else {
        return Ok(0);
    };
    Ok(store
        .list_findings_for_scan_id(scan_id)?
        .iter()
        .filter(|finding| {
            severity_gate_rank(finding.severity).is_some_and(|rank| rank >= threshold_rank)
        })
        .count())
}

/// Severity rank for gating. `Unknown` is deliberately excluded (`None`): the
/// enum's derived `Ord` sorts `Unknown` above `Critical`, and an unparsed
/// severity must never trip a CI gate — it stays visible in reports instead.
fn severity_gate_rank(severity: Severity) -> Option<u8> {
    match severity {
        Severity::Info => Some(0),
        Severity::Low => Some(1),
        Severity::Medium => Some(2),
        Severity::High => Some(3),
        Severity::Critical => Some(4),
        Severity::Unknown => None,
    }
}

fn severity_gate_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
        Severity::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::Finding;

    fn store_with(severities: &[Severity]) -> FindingStore {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("scan-1", std::path::Path::new("/tmp"), "running")
            .unwrap();
        for (index, severity) in severities.iter().enumerate() {
            let finding = Finding::new_tool(
                "semgrep",
                &format!("rule-{index}"),
                "src/app.rs",
                10 + index as u32,
                None,
                *severity,
                "finding for gate test",
            );
            store.insert_finding("scan-1", &finding).unwrap();
        }
        store
    }

    #[test]
    fn counts_findings_at_or_above_threshold() {
        let store = store_with(&[Severity::Low, Severity::High, Severity::Critical]);
        assert_eq!(
            count_blocking_findings(&store, "scan-1", Severity::High).unwrap(),
            2
        );
        assert_eq!(
            count_blocking_findings(&store, "scan-1", Severity::Low).unwrap(),
            3
        );
        assert_eq!(
            count_blocking_findings(&store, "scan-1", Severity::Critical).unwrap(),
            1
        );
    }

    #[test]
    fn unknown_severity_never_trips_the_gate() {
        let store = store_with(&[Severity::Unknown, Severity::Unknown]);
        assert_eq!(
            count_blocking_findings(&store, "scan-1", Severity::Low).unwrap(),
            0
        );
    }

    #[test]
    fn other_scans_do_not_leak_into_the_gate() {
        let store = store_with(&[Severity::Critical]);
        assert_eq!(
            count_blocking_findings(&store, "scan-2", Severity::Low).unwrap(),
            0
        );
    }
}
