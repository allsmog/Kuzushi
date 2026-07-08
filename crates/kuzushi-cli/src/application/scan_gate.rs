use anyhow::{Context, Result};
use kuzushi_core::{
    export_workspace_findings, suppressions::run_suppression_sweep, FindingStore, Severity,
    WorkspaceExportFormat, WorkspaceTarget,
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
        reconcile_suppressions_before_gate(workspace, store)?;
        enforce_fail_on(store, scan_id, threshold)?;
    }
    Ok(())
}

/// Re-run the suppression sweep immediately before `--fail-on` decides
/// pass/fail. The scan-start sweep is not enough by itself: a finding the
/// scan re-observes gets its `stable_findings.current_status` reset to
/// `open` by the observation projection, which hydrates `suppressed=false`
/// regardless of an unexpired rule. Gating on that stale hydration used to
/// only self-correct when `--sarif` also ran (SARIF export carries its own
/// sweep). Idempotent; a sweep failure is a hard error so the gate never
/// passes on state it could not re-evaluate.
fn reconcile_suppressions_before_gate(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
) -> Result<()> {
    run_suppression_sweep(store, workspace, "system:scan-gate")
        .context("suppression sweep failed before fail-on gate; refusing to gate on stale state")?;
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
        .filter(|finding| !finding.suppressed)
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
            .record_run_started("scan-1", std::path::Path::new("/tmp"), "running")
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
    fn suppressed_findings_do_not_trip_the_gate() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("scan-1", std::path::Path::new("/tmp"), "running")
            .unwrap();
        let mut finding = Finding::new_tool(
            "semgrep",
            "rule-suppressed",
            "src/app.rs",
            10,
            None,
            Severity::Critical,
            "suppressed critical",
        );
        finding.suppressed = true;
        store.insert_finding("scan-1", &finding).unwrap();
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

    /// Regression test for the bug where `--fail-on` only honored a
    /// suppression for a re-observed finding when `--sarif` was also passed
    /// (SARIF export carries its own sweep; the gate previously did not).
    /// A finding the scan re-observes gets `stable_findings.current_status`
    /// reset to `open` by the observation projection, which re-hydrates
    /// `suppressed=false` even though an unexpired rule still matches it.
    /// `apply_scan_gate_policy` must now re-sweep right before the gate
    /// decides, so this passes with no `--sarif` option set.
    #[test]
    fn gate_honors_suppression_for_a_re_observed_finding_without_sarif() {
        use kuzushi_core::suppressions::{
            save_suppression_rules, FindingRef, SuppressionOrigin, SuppressionPredicate,
            SuppressionReason, SuppressionRule,
        };

        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("src")).unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("scan-1", workspace.root(), "running")
            .unwrap();

        let finding = Finding::new_tool(
            "semgrep",
            "rust.sqli.tainted-query",
            "src/app.rs",
            10,
            Some(10),
            Severity::High,
            "tainted query, CWE-89",
        );
        store.insert_finding("scan-1", &finding).unwrap();
        let fingerprint = store.list_findings_for_scan_id("scan-1").unwrap()[0]
            .fingerprint
            .clone();

        let rule = SuppressionRule {
            id: "sup-reobserve".to_string(),
            predicate: SuppressionPredicate {
                finding_id: Some(FindingRef(fingerprint)),
                ..SuppressionPredicate::empty()
            },
            reason: SuppressionReason::FalsePositive,
            statement: "sanitized upstream".to_string(),
            actor: "tester".to_string(),
            created_at_unix: 1,
            expires_at_unix: None,
            origin: SuppressionOrigin::File,
        };
        save_suppression_rules(&workspace, &[rule]).unwrap();

        // Scan-start sweep suppresses the finding for this run.
        run_suppression_sweep(&store, &workspace, "system:scan-start").unwrap();
        assert!(store.list_findings_for_scan_id("scan-1").unwrap()[0].suppressed);

        // The scan re-observes the same finding later in the same run,
        // resetting current_status to 'open' and re-hydrating
        // suppressed=false, without any change to the (still unexpired) rule.
        store.insert_finding("scan-1", &finding).unwrap();
        assert!(
            !store.list_findings_for_scan_id("scan-1").unwrap()[0].suppressed,
            "re-observation must reproduce the stale-open hydration bug"
        );

        // The gate must re-sweep before enforcing --fail-on, without needing
        // --sarif, so the unexpired rule still suppresses the finding here.
        let policy = ScanGatePolicy {
            fail_on: Some(Severity::High),
            sarif: None,
        };
        apply_scan_gate_policy(&workspace, &store, "scan-1", &policy)
            .expect("gate must not fail when an unexpired rule covers the re-observed finding");
        assert!(
            store.list_findings_for_scan_id("scan-1").unwrap()[0].suppressed,
            "gate-time sweep must leave the finding suppressed"
        );
    }
}
