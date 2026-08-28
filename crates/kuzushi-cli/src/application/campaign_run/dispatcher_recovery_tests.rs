use super::*;
use kuzushi_core::capabilities::campaign::{
    compile_scan_batch_plan, ScanBatchGatePolicy, ScanBatchPlanSpec,
};
use kuzushi_core::findings::{
    derive_batch_occurrence_report, Finding, FindingIdentityBasis, FindingStore, Severity,
};
use kuzushi_core::run_artifacts::{
    load_run_summary, try_record_tool_run_complete,
    try_record_tool_run_started_with_reproducibility, write_run_summary, ToolRunRecord,
};
use kuzushi_core::{ModuleRegistry, WorkspaceTarget};
use serde_json::json;
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;

const CHILD_TEST: &str =
    "application::campaign_run::dispatcher_recovery_tests::dispatcher_fixture_child";

#[tokio::test]
async fn dispatcher_recovery_preserves_attempts_findings_identities_and_cost() {
    let target = tempfile::tempdir().unwrap();
    seed_source(target.path());
    let binary = fixture_child_script(target.path());
    let (batch_id, workers) = compile_fixture_batch(target.path());

    leave_terminal_child_unsettled(target.path(), &batch_id, &binary).await;
    resume_dispatcher(target.path(), &batch_id, workers, &binary).await;

    assert_recovered_queue(target.path(), &batch_id);
    assert_recovered_findings(target.path(), &batch_id);
}

async fn leave_terminal_child_unsettled(target: &Path, batch_id: &str, binary: &Path) {
    let loaded = load_plan_jobs(target, batch_id, &[]).unwrap();
    let settings = fixture_settings(false);
    let mut dispatcher =
        Dispatcher::open(target.to_path_buf(), batch_id.to_string(), loaded, settings).unwrap();
    dispatcher.binary = binary.to_path_buf();
    let job = dispatcher.plan_jobs[0].clone();
    let (attempt, dispatch) = dispatcher.next_attempt_numbers(&job.job_id);
    let run_id = format!("{batch_id}-{}-a{dispatch}", job.job_id);
    dispatcher
        .mark_job_running(&job.job_id, &run_id, attempt, dispatch)
        .unwrap();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let report = run_child(&dispatcher.child_spec(&job, &run_id), shutdown_rx)
        .await
        .unwrap();
    assert_eq!(report.outcome, JobOutcome::OperationalError);
    drop(dispatcher);
}

async fn resume_dispatcher(target: &Path, batch_id: &str, workers: usize, binary: &Path) {
    let loaded = load_plan_jobs(target, batch_id, &[]).unwrap();
    let mut dispatcher = Dispatcher::open(
        target.to_path_buf(),
        batch_id.to_string(),
        loaded,
        fixture_settings(true),
    )
    .unwrap();
    dispatcher.binary = binary.to_path_buf();
    dispatcher.settings.workers = workers;
    dispatcher.run().await.unwrap();
}

fn compile_fixture_batch(target: &Path) -> (String, usize) {
    let registry = ModuleRegistry::with_v2_builtins();
    let config = crate::application::config_diagnostics::load_cli_config(Some(target)).unwrap();
    let handle = compile_scan_batch_plan(ScanBatchPlanSpec {
        root: target,
        batch_id: Some("batch-dispatch-recovery".to_string()),
        trials: 2,
        requested_workers: 2,
        gate_policy: fixture_gate_policy(target),
        prepared_input: json!({
            "triage": false,
            "identityFold": "safe",
            "taskMode": "manual",
            "tasks": ["secret-scan"]
        }),
        config: &config,
        registry: &registry,
    })
    .unwrap();
    (handle.campaign_id, handle.effective_workers)
}

fn fixture_gate_policy(target: &Path) -> ScanBatchGatePolicy {
    let canonical_target = std::fs::canonicalize(target).unwrap();
    ScanBatchGatePolicy {
        fail_on: Some(Severity::High),
        sarif: Some(canonical_target.join("batch-dispatch-recovery.sarif")),
    }
}

fn fixture_settings(resume: bool) -> DispatchSettings {
    DispatchSettings {
        workers: 1,
        max_attempts: 2,
        job_timeout: Duration::from_secs(20),
        quota_wall_threshold: 3,
        quota_wall_pause: Duration::from_secs(1),
        retry_backoff_secs: 0,
        budget_usd: None,
        job_budget_usd: None,
        resume,
    }
}

fn assert_recovered_queue(target: &Path, batch_id: &str) {
    let path = campaign_dir(target, batch_id).join("queue.json");
    let queue: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let jobs = queue["jobs"].as_object().unwrap();
    assert_eq!(jobs.len(), 2);
    for job in jobs.values() {
        assert_eq!(job["state"], "completed");
        assert_eq!(job["dispatches"], 2);
        assert_eq!(job["attemptRuns"].as_array().unwrap().len(), 2);
    }
    let total = jobs
        .values()
        .map(|job| job["costUsd"].as_f64().unwrap())
        .sum::<f64>();
    assert!((total - 2.0).abs() < 1e-9, "retry cost must sum once");
    let events =
        std::fs::read_to_string(campaign_dir(target, batch_id).join("events.jsonl")).unwrap();
    assert!(events.contains("recovered-stale-running"));
    assert!(events.contains("\"workers\":2"), "{events}");
}

fn assert_recovered_findings(target: &Path, batch_id: &str) {
    let workspace = WorkspaceTarget::new(target).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let report = derive_batch_occurrence_report(target, batch_id, &store).unwrap();
    assert_eq!((report.planned, report.completed, report.failed), (2, 2, 0));
    assert_eq!(report.all_attempt_run_ids().len(), 4);
    assert_eq!(report.rows.len(), 1);
    assert_eq!(report.rows[0].seen, 2);
    let identities = report
        .trials
        .iter()
        .flat_map(|trial| &trial.finding_run_ids)
        .flat_map(|run_id| store.list_findings_for_scan_id(run_id).unwrap())
        .filter_map(|finding| finding.identity_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        identities.len(),
        1,
        "all retry observations keep one identity"
    );
    assert_recovered_batch_gate(&workspace, &store, &report);
}

fn assert_recovered_batch_gate(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    report: &kuzushi_core::findings::BatchOccurrenceReport,
) {
    let policy = crate::application::scan_gate::ScanGatePolicy {
        fail_on: Some(Severity::High),
        sarif: Some(workspace.root().join("batch-dispatch-recovery.sarif")),
    };
    let applied = crate::application::scan_gate::apply_batch_scan_gate_policy(
        workspace, store, report, &policy,
    )
    .unwrap();
    assert_eq!(applied.outcome().completed_trials, 2);
    assert_eq!(applied.outcome().blocking_safe_fold_count, 1);
    assert!(applied.outcome().binding.sarif_sha256.is_some());
    let hydrated =
        derive_batch_occurrence_report(workspace.root(), "batch-dispatch-recovery", store).unwrap();
    assert!(hydrated.gate.is_some());
}

fn seed_source(target: &Path) {
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::write(target.join("src/app.rs"), "fn vulnerable() {}\n").unwrap();
}

fn fixture_child_script(target: &Path) -> PathBuf {
    let test_binary = std::env::current_exe().unwrap();
    let path = target.join("fixture-child.sh");
    let body = format!(
        "#!/bin/sh\n\
         target=''\nrun_id=''\n\
         while [ \"$#\" -gt 0 ]; do\n\
           case \"$1\" in\n\
             --target) target=\"$2\"; shift 2 ;;\n\
             --run-id) run_id=\"$2\"; shift 2 ;;\n\
             *) shift ;;\n\
           esac\n\
         done\n\
         KUZUSHI_DISPATCH_FIXTURE_TARGET=\"$target\" \\\n         KUZUSHI_DISPATCH_FIXTURE_RUN_ID=\"$run_id\" \\\n         exec \"{}\" --exact \"{}\" --nocapture\n",
        escape_double_quoted(&test_binary.to_string_lossy()),
        CHILD_TEST,
    );
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn escape_double_quoted(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`")
}

#[test]
fn dispatcher_fixture_child() {
    let Ok(target) = std::env::var("KUZUSHI_DISPATCH_FIXTURE_TARGET") else {
        return;
    };
    let run_id = std::env::var("KUZUSHI_DISPATCH_FIXTURE_RUN_ID").unwrap();
    let target = PathBuf::from(target);
    write_child_findings(&target, &run_id);
    let exit_code = write_child_run(&target, &run_id);
    std::process::exit(exit_code);
}

fn write_child_findings(target: &Path, run_id: &str) {
    let workspace = WorkspaceTarget::new(target).unwrap();
    workspace.ensure_state_dir().unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store.record_run_started(run_id, target, "running").unwrap();
    let mut finding = Finding::new_tool(
        "secret-scan",
        "fixture/cwe-798",
        "src/app.rs",
        1,
        Some(1),
        Severity::High,
        "fixture hard-coded credential, CWE-798",
    );
    finding.identity_id = Some("fi_dispatch_recovery".to_string());
    finding.identity_basis = Some(FindingIdentityBasis::ExactProducerFingerprint);
    store.insert_finding(run_id, &finding).unwrap();
}

fn write_child_run(target: &Path, run_id: &str) -> i32 {
    write_child_equivalence_receipt(target, run_id);
    let config_sha = planned_config_sha(target);
    let record = ToolRunRecord::new(target, run_id, "run", "sast:scan");
    try_record_tool_run_started_with_reproducibility(
        record,
        &json!({}),
        None,
        Some(config_sha),
        Vec::new(),
    )
    .unwrap();
    let first_attempt = run_id.ends_with("-a1");
    if first_attempt {
        publish_running_cost_then_sigkill(target, run_id);
    } else {
        try_record_tool_run_complete(
            record,
            &json!({"status": "completed", "data": {"engines": ["secret-scan"]}}),
        )
        .unwrap();
    }
    let mut summary = load_run_summary(target, run_id).unwrap();
    summary.cost_usd = Some(0.6);
    write_run_summary(target, &summary).unwrap();
    0
}

fn write_child_equivalence_receipt(target: &Path, run_id: &str) {
    let path = campaign_dir(target, "batch-dispatch-recovery").join("plan.json");
    let plan: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let input = plan["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|job| {
            job["jobId"]
                .as_str()
                .is_some_and(|job_id| run_id.contains(job_id))
        })
        .unwrap()["input"]
        .clone();
    let config = crate::application::config_diagnostics::load_cli_config(Some(target)).unwrap();
    kuzushi_core::capabilities::campaign::verify_scan_batch_child_equivalence(
        target,
        run_id,
        &input,
        &config,
        &ModuleRegistry::with_v2_builtins(),
    )
    .unwrap();
}

fn publish_running_cost_then_sigkill(target: &Path, run_id: &str) -> ! {
    let mut summary = load_run_summary(target, run_id).unwrap();
    summary.cost_usd = Some(0.4);
    write_run_summary(target, &summary).unwrap();
    let status = std::process::Command::new("/bin/kill")
        .args(["-9", &std::process::id().to_string()])
        .status();
    panic!("SIGKILL fixture unexpectedly survived: {status:?}")
}

fn planned_config_sha(target: &Path) -> String {
    let path = campaign_dir(target, "batch-dispatch-recovery").join("plan.json");
    let plan: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    plan.pointer("/equivalence/configSha256")
        .and_then(Value::as_str)
        .unwrap()
        .to_string()
}
