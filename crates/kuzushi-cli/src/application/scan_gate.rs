use anyhow::{Context, Result};
use kuzushi_core::{
    export_scan_findings_sarif_with_run_summary, suppressions::run_suppression_sweep, FindingStore,
    Severity, WorkspaceTarget,
};
use std::collections::BTreeSet;
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
    run_ids: &[String],
    aggregate_run_id: &str,
    policy: &ScanGatePolicy,
) -> Result<()> {
    if let Some(path) = &policy.sarif {
        let export = export_scan_findings_sarif_with_run_summary(
            workspace,
            path,
            run_ids,
            aggregate_run_id,
        )?;
        eprintln!(
            "sarif: wrote {} finding(s) to {}",
            export.count,
            export.output_path.display()
        );
    }
    if let Some(threshold) = policy.fail_on {
        reconcile_suppressions_before_gate(workspace, store)?;
        enforce_fail_on(store, run_ids, threshold)?;
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

fn enforce_fail_on(store: &FindingStore, run_ids: &[String], threshold: Severity) -> Result<()> {
    let blocking = count_blocking_findings_for_run_ids(store, run_ids, threshold)?;
    if blocking == 0 {
        return Ok(());
    }
    eprintln!(
        "fail-on: {blocking} finding(s) at or above {} for scan runs {} (exit {FAIL_ON_EXIT_CODE})",
        severity_gate_label(threshold),
        run_ids.join(","),
    );
    super::config_diagnostics::exit_after_runtime_diagnostics(FAIL_ON_EXIT_CODE);
}

#[cfg(test)]
pub(crate) fn count_blocking_findings(
    store: &FindingStore,
    scan_id: &str,
    threshold: Severity,
) -> Result<usize> {
    count_blocking_findings_for_run_ids(store, &[scan_id.to_string()], threshold)
}

pub(crate) fn count_blocking_findings_for_run_ids(
    store: &FindingStore,
    run_ids: &[String],
    threshold: Severity,
) -> Result<usize> {
    let Some(threshold_rank) = severity_gate_rank(threshold) else {
        return Ok(0);
    };
    let mut blocking = BTreeSet::new();
    for run_id in run_ids {
        for finding in store.list_findings_for_scan_id(run_id)? {
            if !finding.suppressed
                && severity_gate_rank(finding.severity).is_some_and(|rank| rank >= threshold_rank)
            {
                blocking.insert(finding_dedupe_key(&finding));
            }
        }
    }
    Ok(blocking.len())
}

fn finding_dedupe_key(finding: &kuzushi_core::Finding) -> String {
    finding
        .identity_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&finding.fingerprint)
        .to_string()
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
    use kuzushi_core::suppressions::{
        save_suppression_rules, FindingRef, SuppressionOrigin, SuppressionPredicate,
        SuppressionReason, SuppressionRule,
    };
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

    #[test]
    fn union_gate_counts_each_durable_identity_once_across_child_runs() {
        let store = FindingStore::open_in_memory().unwrap();
        record_running_scans(&store, &["child-a", "child-b"]);
        let (first, second) = cross_engine_duplicate_findings();
        assert_ne!(first.fingerprint, second.fingerprint);
        store.insert_finding("child-a", &first).unwrap();
        store.insert_finding("child-b", &second).unwrap();
        let first_identity = stored_identity(&store, "child-a");
        let second_identity = stored_identity(&store, "child-b");
        assert_eq!(first_identity, second_identity);
        let count = count_blocking_findings_for_run_ids(
            &store,
            &["child-a".to_string(), "child-b".to_string()],
            Severity::High,
        )
        .unwrap();
        assert_eq!(count, 1, "cross-engine identity must gate once");
    }

    fn record_running_scans(store: &FindingStore, run_ids: &[&str]) {
        for run_id in run_ids {
            store
                .record_run_started(run_id, std::path::Path::new("/tmp"), "running")
                .unwrap();
        }
    }

    fn cross_engine_duplicate_findings() -> (Finding, Finding) {
        let evidence = shared_locus_evidence();
        let first = Finding::new_tool(
            "semgrep",
            "java.injection.tainted-system-call",
            "src/foo.c",
            42,
            Some(42),
            Severity::High,
            "user-controlled exec, CWE-78",
        )
        .with_evidence(vec![evidence.clone()]);
        let second = Finding::new_tool(
            "systems-hunt",
            "systems/cwe-78",
            "src/foo.c",
            42,
            Some(42),
            Severity::Critical,
            "exec reaches shell with attacker input, CWE-78",
        )
        .with_evidence(vec![evidence]);
        (first, second)
    }

    fn shared_locus_evidence() -> kuzushi_core::FindingEvidence {
        kuzushi_core::FindingEvidence {
            kind: "code".to_string(),
            file_path: "src/foo.c".to_string(),
            line: 42,
            snippet: "execl(user_controlled_command);".to_string(),
            rationale: "same source-to-sink locus".to_string(),
            confidence: 90,
            request_blob: None,
            response_blob: None,
        }
    }

    fn stored_identity(store: &FindingStore, run_id: &str) -> Option<String> {
        store.list_findings_for_scan_id(run_id).unwrap()[0]
            .identity_id
            .clone()
    }

    #[test]
    fn dedupe_key_prefers_identity_over_observation_fingerprint() {
        let mut first = Finding::new_tool(
            "one",
            "rule-one",
            "src/a.rs",
            1,
            None,
            Severity::High,
            "one",
        );
        let mut second = Finding::new_tool(
            "two",
            "rule-two",
            "src/b.rs",
            2,
            None,
            Severity::High,
            "two",
        );
        first.identity_id = Some("fi_shared".to_string());
        second.identity_id = Some("fi_shared".to_string());
        assert_ne!(first.fingerprint, second.fingerprint);
        assert_eq!(finding_dedupe_key(&first), finding_dedupe_key(&second));
    }

    #[test]
    fn scan_sarif_excludes_findings_from_prior_runs() {
        let (temp, workspace, store) = scan_sarif_fixture();
        let output = temp.path().join("current.sarif");
        let policy = ScanGatePolicy {
            fail_on: None,
            sarif: Some(output.clone()),
        };
        write_current_scan_summary(&workspace);

        apply_scan_gate_policy(
            &workspace,
            &store,
            &["current-run".to_string()],
            "current-run",
            &policy,
        )
        .unwrap();

        let body = std::fs::read_to_string(output).unwrap();
        assert!(body.contains("current-rule"), "{body}");
        assert!(!body.contains("old-rule"), "{body}");
    }

    fn scan_sarif_fixture() -> (tempfile::TempDir, WorkspaceTarget, FindingStore) {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        for run_id in ["old-run", "current-run"] {
            store
                .record_run_started(run_id, workspace.root(), "running")
                .unwrap();
        }
        let old = Finding::new_tool(
            "semgrep",
            "old-rule",
            "src/old.rs",
            1,
            None,
            Severity::High,
            "old finding",
        );
        let current = Finding::new_tool(
            "semgrep",
            "current-rule",
            "src/current.rs",
            2,
            None,
            Severity::High,
            "current finding",
        );
        store.insert_finding("old-run", &old).unwrap();
        store.insert_finding("current-run", &current).unwrap();
        (temp, workspace, store)
    }

    fn write_current_scan_summary(workspace: &WorkspaceTarget) {
        let summary = kuzushi_core::RunSummary::running(
            "current-run",
            "scan",
            Some("sast:scan".to_string()),
            workspace.root().display().to_string(),
        )
        .complete()
        .with_cost(Some(0.0));
        kuzushi_core::write_run_summary(workspace.root(), &summary).unwrap();
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
        let (_tmp, workspace, store, finding) = reobserved_finding_fixture();
        save_test_suppression(&workspace, &finding_fingerprint(&store));
        // Scan-start sweep suppresses the finding for this run.
        run_suppression_sweep(&store, &workspace, "system:scan-start").unwrap();
        assert!(finding_is_suppressed(&store));
        // The scan re-observes the same finding later in the same run,
        // resetting current_status to 'open' and re-hydrating
        // suppressed=false, without any change to the (still unexpired) rule.
        store.insert_finding("scan-1", &finding).unwrap();
        assert!(
            !finding_is_suppressed(&store),
            "re-observation must reproduce the stale-open hydration bug"
        );
        // The gate must re-sweep before enforcing --fail-on, without needing
        // --sarif, so the unexpired rule still suppresses the finding here.
        let policy = ScanGatePolicy {
            fail_on: Some(Severity::High),
            sarif: None,
        };
        apply_scan_gate_policy(
            &workspace,
            &store,
            &["scan-1".to_string()],
            "scan-1",
            &policy,
        )
        .expect("gate must not fail when an unexpired rule covers the re-observed finding");
        assert!(
            finding_is_suppressed(&store),
            "gate-time sweep must leave the finding suppressed"
        );
    }

    fn reobserved_finding_fixture() -> (tempfile::TempDir, WorkspaceTarget, FindingStore, Finding) {
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
        (tmp, workspace, store, finding)
    }

    fn finding_fingerprint(store: &FindingStore) -> String {
        store.list_findings_for_scan_id("scan-1").unwrap()[0]
            .fingerprint
            .clone()
    }

    fn finding_is_suppressed(store: &FindingStore) -> bool {
        store.list_findings_for_scan_id("scan-1").unwrap()[0].suppressed
    }

    fn save_test_suppression(workspace: &WorkspaceTarget, fingerprint: &str) {
        let rule = SuppressionRule {
            id: "sup-reobserve".to_string(),
            predicate: SuppressionPredicate {
                finding_id: Some(FindingRef(fingerprint.to_string())),
                ..SuppressionPredicate::empty()
            },
            reason: SuppressionReason::FalsePositive,
            statement: "sanitized upstream".to_string(),
            actor: "tester".to_string(),
            created_at_unix: 1,
            expires_at_unix: None,
            origin: SuppressionOrigin::File,
        };
        save_suppression_rules(workspace, &[rule]).unwrap();
    }
}
