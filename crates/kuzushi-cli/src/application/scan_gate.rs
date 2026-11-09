use anyhow::{Context, Result};
use kuzushi_core::capabilities::campaign::{
    persist_batch_gate_outcome, persist_batch_sarif_document, ScanBatchGateBinding,
    ScanBatchGateCounts, ScanBatchGateOutcome, ScanBatchGatePolicy,
};
use kuzushi_core::findings::{derive_batch_gate_binding, BatchOccurrenceReport};
use kuzushi_core::{
    export_scan_findings_sarif, export_scan_findings_sarif_with_run_summary,
    suppressions::run_suppression_sweep, FindingStore, Severity, WorkspaceTarget,
};
use std::collections::{BTreeMap, BTreeSet};
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

pub(crate) struct AppliedBatchGate {
    outcome: ScanBatchGateOutcome,
}

impl AppliedBatchGate {
    pub(crate) fn outcome(&self) -> &ScanBatchGateOutcome {
        &self.outcome
    }

    pub(crate) fn operationally_incomplete(&self) -> bool {
        self.outcome.operational_status
            == kuzushi_core::capabilities::campaign::BatchOperationalStatus::Incomplete
    }

    pub(crate) fn failed(&self) -> bool {
        self.outcome.security_status
            == kuzushi_core::capabilities::campaign::BatchSecurityGateStatus::Failed
    }

    pub(crate) fn enforce(self) {
        exit_on_blocking_findings(
            self.outcome.threshold,
            self.outcome.blocking_safe_fold_count,
            &self.outcome.completed_run_ids,
        );
    }
}

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

pub(crate) fn apply_batch_scan_gate_policy(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    report: &BatchOccurrenceReport,
    policy: &ScanGatePolicy,
) -> Result<AppliedBatchGate> {
    let frozen_policy = batch_gate_policy(policy);
    let run_ids = report.completed_run_ids();
    let sarif_path = export_batch_sarif(workspace, report, policy, &run_ids)?;
    if policy.fail_on.is_some() {
        reconcile_suppressions_before_gate(workspace, store)?;
    }
    let (binding, blocking) =
        derive_batch_gate_binding(store, report, policy.fail_on, sarif_path.as_deref())?;
    let outcome = batch_gate_outcome(
        report,
        &frozen_policy,
        run_ids,
        blocking,
        sarif_path.is_some(),
        binding,
    );
    let path = persist_batch_gate_outcome(workspace.root(), &outcome)?;
    eprintln!(
        "batch gate: {} ({})",
        outcome.status.as_str(),
        path.display()
    );
    Ok(AppliedBatchGate { outcome })
}

fn export_batch_sarif(
    workspace: &WorkspaceTarget,
    report: &BatchOccurrenceReport,
    policy: &ScanGatePolicy,
    run_ids: &[String],
) -> Result<Option<PathBuf>> {
    let Some(path) = &policy.sarif else {
        return Ok(None);
    };
    let export = export_scan_findings_sarif(workspace, path, run_ids)?;
    let folded_count = annotate_batch_sarif(&export.output_path, report)?;
    eprintln!(
        "sarif: wrote {} identity-folded batch finding(s) to {}",
        folded_count,
        export.output_path.display()
    );
    Ok(Some(export.output_path))
}

fn batch_gate_outcome(
    report: &BatchOccurrenceReport,
    gate_policy: &ScanBatchGatePolicy,
    completed_run_ids: Vec<String>,
    blocking_safe_fold_count: usize,
    sarif_written: bool,
    binding: ScanBatchGateBinding,
) -> ScanBatchGateOutcome {
    ScanBatchGateOutcome::new(
        &report.batch_id,
        &report.equivalence_key,
        gate_policy,
        ScanBatchGateCounts {
            planned_trials: report.planned,
            completed_trials: report.completed,
            failed_trials: report.failed,
            pending_trials: report.pending,
            completed_run_ids,
            blocking_safe_fold_count,
            sarif_written,
        },
        binding,
    )
}

fn batch_gate_policy(policy: &ScanGatePolicy) -> ScanBatchGatePolicy {
    ScanBatchGatePolicy {
        fail_on: policy.fail_on,
        sarif: policy.sarif.clone(),
    }
}

fn exit_on_blocking_findings(threshold: Option<Severity>, blocking: usize, run_ids: &[String]) {
    let Some(threshold) = threshold.filter(|_| blocking > 0) else {
        return;
    };
    eprintln!(
        "fail-on: {blocking} finding(s) at or above {} for scan runs {} (exit {FAIL_ON_EXIT_CODE})",
        severity_gate_label(threshold),
        run_ids.join(","),
    );
    super::config_diagnostics::exit_after_runtime_diagnostics(FAIL_ON_EXIT_CODE);
}

fn annotate_batch_sarif(path: &std::path::Path, report: &BatchOccurrenceReport) -> Result<usize> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("could not read batch SARIF {}", path.display()))?;
    let mut document: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is malformed SARIF", path.display()))?;
    document["properties"]["kuzushiBatch"] = batch_sarif_metadata(report);
    let folded_count = annotate_sarif_results(&mut document, report)?;
    persist_batch_sarif_document(path, &document)?;
    Ok(folded_count)
}

fn batch_sarif_metadata(report: &BatchOccurrenceReport) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": report.schema_version,
        "batchId": report.batch_id,
        "equivalenceKey": report.equivalence_key,
        "identityFold": report.identity_fold,
        "trialsPlanned": report.planned,
        "trialsCompleted": report.completed,
        "trialsFailed": report.failed,
        "trialsPending": report.pending,
        "rawAttemptRunIds": report.all_attempt_run_ids(),
    })
}

/// One surviving result and the index of the run it was emitted in.
///
/// `export_scan_findings_sarif` emits one `runs[]` entry per `Finding.tool`,
/// and SARIF 2.1.0 resolves a result's detector (`tool.driver.name`), its rule
/// metadata (`tool.driver.rules[]`, looked up by `result.ruleId`) and its path
/// bases (`originalUriBaseIds`) against the run that contains it. Identity
/// folding therefore has to keep each representative where its own engine
/// reported it.
struct FoldedResult {
    run_index: usize,
    result: serde_json::Value,
}

fn annotate_sarif_results(
    document: &mut serde_json::Value,
    report: &BatchOccurrenceReport,
) -> Result<usize> {
    let runs = document
        .get_mut("runs")
        .and_then(serde_json::Value::as_array_mut)
        .context("batch SARIF has no runs array")?;
    anyhow::ensure!(!runs.is_empty(), "batch SARIF has no run");
    let folded = fold_sarif_results(take_sarif_results(runs), report)?;
    restore_folded_results(runs, folded)
}

/// Drain every run's results, tagging each with the run it came from. `drain`
/// leaves each visited run with an empty `results` array, so a run whose only
/// observation folded away reports no result rather than keeping a stale one.
fn take_sarif_results(runs: &mut [serde_json::Value]) -> Vec<FoldedResult> {
    let mut results = Vec::new();
    for (run_index, run) in runs.iter_mut().enumerate() {
        let Some(run_results) = run
            .get_mut("results")
            .and_then(serde_json::Value::as_array_mut)
        else {
            continue;
        };
        results.extend(
            run_results
                .drain(..)
                .map(|result| FoldedResult { run_index, result }),
        );
    }
    results
}

fn fold_sarif_results(
    results: Vec<FoldedResult>,
    report: &BatchOccurrenceReport,
) -> Result<Vec<FoldedResult>> {
    let mut selected = BTreeMap::<usize, (bool, FoldedResult)>::new();
    for mut folded in results {
        let fingerprint = sarif_result_fingerprint(&folded.result)?.to_string();
        let (index, row) = occurrence_row_for_fingerprint(report, &fingerprint)?;
        annotate_sarif_result(&mut folded.result, row);
        let representative = fingerprint == row.representative_fingerprint;
        match selected.entry(index) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((representative, folded));
            }
            std::collections::btree_map::Entry::Occupied(mut entry)
                if representative && !entry.get().0 =>
            {
                entry.insert((true, folded));
            }
            _ => {}
        }
    }
    Ok(selected.into_values().map(|(_, folded)| folded).collect())
}

/// Return each surviving result to its own run and report how many survived.
fn restore_folded_results(
    runs: &mut [serde_json::Value],
    folded: Vec<FoldedResult>,
) -> Result<usize> {
    let count = folded.len();
    for folded in folded {
        run_results_array(runs, folded.run_index)?.push(folded.result);
    }
    Ok(count)
}

fn run_results_array(
    runs: &mut [serde_json::Value],
    run_index: usize,
) -> Result<&mut Vec<serde_json::Value>> {
    runs.get_mut(run_index)
        .and_then(|run| run.get_mut("results"))
        .and_then(serde_json::Value::as_array_mut)
        .with_context(|| format!("batch SARIF run {run_index} lost its results array"))
}

fn sarif_result_fingerprint(result: &serde_json::Value) -> Result<&str> {
    result
        .pointer("/fingerprints/kuzushi~1v1")
        .and_then(serde_json::Value::as_str)
        .context("batch SARIF result has no Kuzushi fingerprint")
}

fn occurrence_row_for_fingerprint<'a>(
    report: &'a BatchOccurrenceReport,
    fingerprint: &str,
) -> Result<(usize, &'a kuzushi_core::findings::BatchOccurrenceRow)> {
    report
        .rows
        .iter()
        .enumerate()
        .find(|(_, row)| row.fingerprints.iter().any(|value| value == fingerprint))
        .with_context(|| format!("SARIF finding {fingerprint} has no batch occurrence group"))
}

fn annotate_sarif_result(
    result: &mut serde_json::Value,
    row: &kuzushi_core::findings::BatchOccurrenceRow,
) {
    result["properties"]["kuzushiBatchOccurrence"] = serde_json::json!({
        "seen": row.seen,
        "completed": row.completed,
        "planned": row.planned,
        "failed": row.failed,
        "runIds": row.run_ids,
        "severityVariants": row.severities,
        "locationVariants": row.locations,
        "titleVariants": row.titles,
    });
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
    kuzushi_core::findings::finding_projection_key(
        finding,
        kuzushi_core::findings::IdentityFoldPolicy::Safe,
    )
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
    use kuzushi_core::findings::{
        BatchOccurrenceRow, BatchTrialReport, FindingIdentityBasis, IdentityFoldPolicy,
    };
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
        record_running_scans(&store, &["seed", "child-a", "child-b"]);
        let (mut first, mut second) = cross_engine_duplicate_findings();
        first.dedup_key = Some("shared-source-locus".to_string());
        second.dedup_key = first.dedup_key.clone();
        assert_ne!(first.fingerprint, second.fingerprint);
        store.insert_finding("seed", &first).unwrap();
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

    #[test]
    fn batch_sarif_safe_fold_keeps_distinct_fallback_signatures() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        record_running_scans(&store, &["trial-a", "trial-b"]);
        let mut first = fallback_finding("first", "sig:first", 10);
        let mut second = fallback_finding("second", "sig:second", 80);
        first.identity_id = Some("fi_shared_fallback".to_string());
        second.identity_id = Some("fi_shared_fallback".to_string());
        store.insert_finding("trial-a", &first).unwrap();
        store.insert_finding("trial-b", &second).unwrap();
        let output = temp.path().join("batch.sarif");

        let exported = export_scan_findings_sarif(
            &workspace,
            &output,
            &["trial-a".to_string(), "trial-b".to_string()],
        )
        .unwrap();

        assert_eq!(exported.count, 2);
    }

    #[test]
    fn batch_sarif_emits_one_annotated_result_per_safe_occurrence_group() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        record_running_scans(&store, &["trial-a", "trial-b"]);
        let (first, second) = cross_engine_duplicate_findings();
        store.insert_finding("trial-a", &first).unwrap();
        store.insert_finding("trial-b", &second).unwrap();
        let stored_first = store.list_findings_for_scan_id("trial-a").unwrap()[0].clone();
        let stored_second = store.list_findings_for_scan_id("trial-b").unwrap()[0].clone();
        let report = occurrence_report_for_duplicate(&stored_first, &stored_second);
        let output = temp.path().join("batch.sarif");

        apply_batch_scan_gate_policy(
            &workspace,
            &store,
            &report,
            &ScanGatePolicy {
                fail_on: None,
                sarif: Some(output.clone()),
            },
        )
        .unwrap();

        let sarif: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        let published = published_results(&sarif);
        assert_eq!(published.len(), 1, "one result per safe occurrence group");
        let (driver, result) = published[0];
        assert_eq!(
            driver, "systems-hunt",
            "the representative stays under the driver that reported it"
        );
        assert_eq!(result["ruleId"], "systems/cwe-78");
        assert_eq!(
            result.pointer("/properties/kuzushiBatchOccurrence/seen"),
            Some(&serde_json::json!(2))
        );
        assert_eq!(
            sarif.pointer("/properties/kuzushiBatch/trialsCompleted"),
            Some(&serde_json::json!(2))
        );
        let gate_path =
            kuzushi_core::capabilities::campaign::campaign_dir(workspace.root(), "batch-test")
                .join("gate.json");
        let gate: serde_json::Value =
            serde_json::from_slice(&std::fs::read(gate_path).unwrap()).unwrap();
        assert_eq!(gate["status"], "disabled");
        assert_eq!(gate["completedTrials"], 2);
        assert_eq!(gate["blockingSafeFoldCount"], 0);
        assert_eq!(gate["sarifWritten"], true);
        assert!(gate["binding"]["logicalTerminalStateSha256"].is_string());
        assert!(gate["binding"]["blockingFindingsSha256"].is_string());
        assert!(gate["binding"]["sarifSha256"].is_string());
    }

    /// A batch scan whose engines each report a finding of their own exports
    /// one `runs[]` entry per tool, and every result must stay in the run whose
    /// driver reported it. Pooling them into `runs[0]` republished one engine's
    /// finding under another engine's name and left the other run claiming it
    /// found nothing.
    #[test]
    fn each_engines_result_stays_in_its_own_run() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        record_running_scans(&store, &["trial-a", "trial-b"]);
        let (semgrep, systems) = distinct_findings_from_two_engines();
        store.insert_finding("trial-a", &semgrep).unwrap();
        store.insert_finding("trial-b", &systems).unwrap();
        let stored_semgrep = store.list_findings_for_scan_id("trial-a").unwrap()[0].clone();
        let stored_systems = store.list_findings_for_scan_id("trial-b").unwrap()[0].clone();
        let report = occurrence_report_for_distinct(&stored_semgrep, &stored_systems);
        let output = temp.path().join("batch.sarif");

        apply_batch_scan_gate_policy(
            &workspace,
            &store,
            &report,
            &ScanGatePolicy {
                fail_on: None,
                sarif: Some(output.clone()),
            },
        )
        .unwrap();

        let sarif: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        let mut published: Vec<(&str, &str)> = published_results(&sarif)
            .into_iter()
            .map(|(driver, result)| (driver, result["ruleId"].as_str().unwrap()))
            .collect();
        published.sort_unstable();
        assert_eq!(
            published,
            vec![
                ("semgrep", "java.injection.tainted-system-call"),
                ("systems-hunt", "systems/cwe-78"),
            ],
            "each result must be published under the driver that reported it"
        );
        for (driver, result) in published_results(&sarif) {
            let rule_id = result["ruleId"].as_str().unwrap();
            assert!(
                declared_rule_ids(&sarif, driver).contains(&rule_id),
                "{driver} carries a result for {rule_id}, which it does not declare"
            );
            assert_eq!(
                result.pointer("/properties/kuzushiBatchOccurrence/seen"),
                Some(&serde_json::json!(1))
            );
        }
    }

    /// The rule ids a run declares in its own `tool.driver.rules[]`, which is
    /// where a SARIF consumer resolves `result.ruleId`.
    fn declared_rule_ids<'a>(sarif: &'a serde_json::Value, driver: &str) -> Vec<&'a str> {
        sarif["runs"]
            .as_array()
            .expect("runs[] present")
            .iter()
            .filter(|run| run.pointer("/tool/driver/name") == Some(&serde_json::json!(driver)))
            .flat_map(|run| {
                run["tool"]["driver"]["rules"]
                    .as_array()
                    .expect("every run declares its rules")
                    .iter()
                    .map(|rule| rule["id"].as_str().expect("every rule has an id"))
            })
            .collect()
    }

    /// Every published result paired with the driver of the run carrying it.
    fn published_results(sarif: &serde_json::Value) -> Vec<(&str, &serde_json::Value)> {
        sarif["runs"]
            .as_array()
            .expect("runs[] present")
            .iter()
            .flat_map(|run| {
                let driver = run
                    .pointer("/tool/driver/name")
                    .and_then(serde_json::Value::as_str)
                    .expect("every run names its driver");
                run["results"]
                    .as_array()
                    .expect("every run publishes a results array")
                    .iter()
                    .map(move |result| (driver, result))
            })
            .collect()
    }

    #[test]
    fn batch_controller_recomputes_gate_after_trial_finding_and_sarif_drift() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        record_running_scans(&store, &["trial-a", "trial-b"]);
        let (mut finding, second) = cross_engine_duplicate_findings();
        finding.identity_basis = Some(FindingIdentityBasis::ExactProducerFingerprint);
        store.insert_finding("trial-a", &finding).unwrap();
        let mut report = occurrence_report_for_duplicate(&finding, &second);
        mark_second_trial_failed(&mut report, &finding);
        let output = temp.path().join("batch.sarif");
        std::fs::write(&output, b"stale sarif").unwrap();
        let policy = ScanGatePolicy {
            fail_on: Some(Severity::High),
            sarif: Some(output.clone()),
        };
        report.gate = Some(stale_gate_receipt(&report, &policy));

        let applied = apply_batch_scan_gate_policy(&workspace, &store, &report, &policy).unwrap();

        let outcome = applied.outcome();
        assert_eq!((outcome.completed_trials, outcome.failed_trials), (1, 1));
        assert_eq!(outcome.completed_run_ids, vec!["trial-a"]);
        assert_eq!(outcome.blocking_safe_fold_count, 1);
        assert!(outcome.sarif_written);
        assert_ne!(std::fs::read(&output).unwrap(), b"stale sarif");
        let sarif_digest =
            kuzushi_core::run_lifecycle::sha256_content_digest(&std::fs::read(&output).unwrap());
        assert_eq!(
            outcome.binding.sarif_sha256.as_deref(),
            Some(sarif_digest.as_str())
        );
        let gate_path =
            kuzushi_core::capabilities::campaign::campaign_dir(workspace.root(), "batch-test")
                .join("gate.json");
        let persisted: ScanBatchGateOutcome =
            serde_json::from_slice(&std::fs::read(gate_path).unwrap()).unwrap();
        assert_eq!(&persisted, outcome);
    }

    fn mark_second_trial_failed(report: &mut BatchOccurrenceReport, finding: &Finding) {
        report.completed = 1;
        report.failed = 1;
        report.trials[1].state = "failed".to_string();
        report.trials[1].finding_run_ids.clear();
        let row = &mut report.rows[0];
        row.seen = 1;
        row.completed = 1;
        row.failed = 1;
        row.run_ids = vec!["trial-a".to_string()];
        row.fingerprints = vec![finding.fingerprint.clone()];
        row.severities = vec![finding.severity.as_str().to_string()];
        row.locations = vec![finding_location(finding)];
        row.titles = vec![finding.title.clone()];
    }

    fn stale_gate_receipt(
        report: &BatchOccurrenceReport,
        policy: &ScanGatePolicy,
    ) -> ScanBatchGateOutcome {
        ScanBatchGateOutcome::new(
            &report.batch_id,
            &report.equivalence_key,
            &batch_gate_policy(policy),
            ScanBatchGateCounts {
                planned_trials: 2,
                completed_trials: 2,
                failed_trials: 0,
                pending_trials: 0,
                completed_run_ids: vec!["trial-a".to_string(), "trial-b".to_string()],
                blocking_safe_fold_count: 0,
                sarif_written: true,
            },
            ScanBatchGateBinding {
                logical_terminal_state_sha256: "sha256:stale-state".to_string(),
                blocking_findings_sha256: "sha256:stale-findings".to_string(),
                sarif_path: Some(policy.sarif.clone().unwrap()),
                sarif_sha256: Some("sha256:stale-sarif".to_string()),
            },
        )
    }

    fn occurrence_report_for_duplicate(first: &Finding, second: &Finding) -> BatchOccurrenceReport {
        BatchOccurrenceReport {
            schema_version: 1,
            batch_id: "batch-test".to_string(),
            equivalence_key: "sha256:equivalent".to_string(),
            identity_fold: IdentityFoldPolicy::Safe,
            planned: 2,
            completed: 2,
            failed: 0,
            pending: 0,
            gate: None,
            trials: vec![completed_trial(1, "trial-a"), completed_trial(2, "trial-b")],
            rows: vec![BatchOccurrenceRow {
                fold_key: finding_dedupe_key(first),
                identity_id: first.identity_id.clone(),
                identity_basis: first.identity_basis,
                seen: 2,
                completed: 2,
                planned: 2,
                failed: 0,
                severities: vec!["high".to_string(), "critical".to_string()],
                locations: vec![finding_location(first), finding_location(second)],
                titles: vec![first.title.clone(), second.title.clone()],
                fingerprints: vec![first.fingerprint.clone(), second.fingerprint.clone()],
                run_ids: vec!["trial-a".to_string(), "trial-b".to_string()],
                representative_observation_ref: None,
                representative_fingerprint: second.fingerprint.clone(),
                representative_title: second.title.clone(),
                representative_severity: "critical".to_string(),
                representative_location: finding_location(second),
            }],
        }
    }

    fn finding_location(finding: &Finding) -> String {
        format!("{}:{}", finding.file_path, finding.start_line)
    }

    fn completed_trial(trial: usize, run_id: &str) -> BatchTrialReport {
        BatchTrialReport {
            trial,
            job_id: format!("trial-{trial:03}"),
            state: "completed".to_string(),
            attempts: 1,
            run_id: Some(run_id.to_string()),
            attempt_run_ids: vec![run_id.to_string()],
            finding_run_ids: vec![run_id.to_string()],
            failure_reason: None,
        }
    }

    fn fallback_finding(title: &str, signature: &str, line: u32) -> Finding {
        let mut finding = Finding::new_tool(
            "semgrep",
            "rule/cwe-78",
            "src/shell.rs",
            line,
            Some(line),
            Severity::High,
            title,
        );
        finding.identity_basis = Some(FindingIdentityBasis::FileFallback);
        finding.source_signature = Some(signature.to_string());
        finding
    }

    /// Two findings from two engines that do not fold together: different
    /// files, rules and source signatures, so the export emits one `runs[]`
    /// entry per tool and the occurrence report carries one row per finding.
    fn distinct_findings_from_two_engines() -> (Finding, Finding) {
        let mut semgrep = Finding::new_tool(
            "semgrep",
            "java.injection.tainted-system-call",
            "src/exec.c",
            42,
            Some(42),
            Severity::High,
            "user-controlled exec, CWE-78",
        );
        let mut systems = Finding::new_tool(
            "systems-hunt",
            "systems/cwe-78",
            "src/spawn.c",
            108,
            Some(108),
            Severity::Critical,
            "spawn reaches shell with attacker input, CWE-78",
        );
        semgrep.identity_basis = Some(FindingIdentityBasis::SourceLocator);
        systems.identity_basis = Some(FindingIdentityBasis::SourceLocator);
        semgrep.source_signature = Some("src/exec.c:exec:user".to_string());
        systems.source_signature = Some("src/spawn.c:spawn:user".to_string());
        (semgrep, systems)
    }

    /// One trial per finding, one occurrence row per finding — the shape a
    /// batch scan produces when its engines report different findings.
    fn occurrence_report_for_distinct(first: &Finding, second: &Finding) -> BatchOccurrenceReport {
        let row = |finding: &Finding, run_id: &str| BatchOccurrenceRow {
            fold_key: finding_dedupe_key(finding),
            identity_id: finding.identity_id.clone(),
            identity_basis: finding.identity_basis,
            seen: 1,
            completed: 1,
            planned: 1,
            failed: 0,
            severities: vec![finding.severity.as_str().to_string()],
            locations: vec![finding_location(finding)],
            titles: vec![finding.title.clone()],
            fingerprints: vec![finding.fingerprint.clone()],
            run_ids: vec![run_id.to_string()],
            representative_observation_ref: None,
            representative_fingerprint: finding.fingerprint.clone(),
            representative_title: finding.title.clone(),
            representative_severity: finding.severity.as_str().to_string(),
            representative_location: finding_location(finding),
        };
        BatchOccurrenceReport {
            schema_version: 1,
            batch_id: "batch-test".to_string(),
            equivalence_key: "sha256:equivalent".to_string(),
            identity_fold: IdentityFoldPolicy::Safe,
            planned: 2,
            completed: 2,
            failed: 0,
            pending: 0,
            gate: None,
            trials: vec![completed_trial(1, "trial-a"), completed_trial(2, "trial-b")],
            rows: vec![row(first, "trial-a"), row(second, "trial-b")],
        }
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
        let mut first = Finding::new_tool(
            "semgrep",
            "java.injection.tainted-system-call",
            "src/foo.c",
            42,
            Some(42),
            Severity::High,
            "user-controlled exec, CWE-78",
        )
        .with_evidence(vec![evidence.clone()]);
        let mut second = Finding::new_tool(
            "systems-hunt",
            "systems/cwe-78",
            "src/foo.c",
            42,
            Some(42),
            Severity::Critical,
            "exec reaches shell with attacker input, CWE-78",
        )
        .with_evidence(vec![evidence]);
        first.identity_basis = Some(FindingIdentityBasis::SourceLocator);
        second.identity_basis = Some(FindingIdentityBasis::SourceLocator);
        first.source_signature = Some("src/foo.c:exec:user".to_string());
        second.source_signature = first.source_signature.clone();
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
        first.identity_basis = Some(FindingIdentityBasis::SourceLocator);
        second.identity_basis = Some(FindingIdentityBasis::SourceLocator);
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
