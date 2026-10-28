use super::*;
use crate::capabilities::campaign::{
    load_context_matrix_receipt, read_campaign_plan_document, verify_scan_batch_child_equivalence,
};
use crate::modules::ToolExecutionContext;

struct Fixture {
    root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    config: crate::V2Config,
    registry: ModuleRegistry,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("main.rs"),
            "// Owned report fixture, never executed.\nfn main() {}\n",
        )
        .unwrap();
        Self {
            workspace: WorkspaceTarget::new(root.path()).unwrap(),
            root,
            config: crate::V2Config {
                model: Some("openai-codex:gpt-5.5".into()),
                ..Default::default()
            },
            registry: ModuleRegistry::with_v2_builtins(),
        }
    }

    fn ctx(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }

    fn plan(&self, approve: bool) {
        let cases = ["Alpha", "Beta", "Gamma"].into_iter().map(|label| {
            let reference = self.registry.execute_tool("threat-model:import", json!({"activate":true,"label":label,
                "document":{"version":"1","methodology":"stride","title":label,"systemContext":"Owned labeled report fixture",
                "dfd":{"nodes":[{"id":"app","name":"Greeting","type":"process","trustZone":"internal"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{}}}), &self.ctx()).unwrap();
            json!({"id":label.to_lowercase(),"label":label,"threatModelRef":reference["data"]["modelRef"]})
        }).collect::<Vec<_>>();
        self.registry.execute_tool("campaign:study", json!({"campaignId":"matrix-report","investigationId":"matrix-accounting",
            "baselineCaseId":"alpha","scanInput":{"taskMode":"manual","tasks":["secret-scan"]},"contextCases":cases}), &self.ctx()).unwrap();
        if approve {
            self.approve();
        }
    }

    fn approve(&self) {
        let receipt = load_context_matrix_receipt(self.root.path(), "matrix-report").unwrap();
        let input = json!({"investigationId":"matrix-accounting","expectedRevision":0,"model":"openai-codex:gpt-5.5",
            "maxProviderCalls":11,"protectedReviewCalls":2,"reason":"Owned report fixture; no model requests",
            "campaignId":"matrix-report","campaignPlanSha256":receipt.plan_sha256,"campaignJobs":9,"maxJobAttempts":1});
        let prepared = self
            .registry
            .prepare_dispatch_input("campaign:approve-allowance", input, &self.ctx(), None)
            .unwrap()
            .authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &self.ctx(), None)
            .unwrap();
    }

    fn observations(&self) -> Vec<String> {
        let plan = read_campaign_plan_document(self.root.path(), "matrix-report").unwrap();
        let store = FindingStore::open(self.workspace.findings_db_path()).unwrap();
        let snapshot =
            crate::incremental_index::register_workspace_tree_identity(&self.workspace).unwrap();
        let mut queue = serde_json::Map::new();
        let mut runs = Vec::new();
        for (index, job) in plan["jobs"].as_array().unwrap().iter().enumerate() {
            let id = job["jobId"].as_str().unwrap();
            let run = format!("matrix-pass-{}", index + 1);
            self.run_receipt(&run, &job["input"], &snapshot);
            store
                .record_run_started(&run, self.workspace.root(), "completed")
                .unwrap();
            if [0, 1, 2, 3, 4, 6].contains(&index) {
                store.insert_finding(&run, &labeled_observation()).unwrap();
            }
            queue.insert(
                id.into(),
                json!({"state":"completed","attempts":1,"runId":run,"attemptRuns":[{"runId":run}]}),
            );
            runs.push(run);
        }
        let path = crate::capabilities::campaign::campaign_dir(self.root.path(), "matrix-report")
            .join("queue.json");
        fs::write(path, json!({"jobs":queue}).to_string()).unwrap();
        runs
    }

    fn run_receipt(
        &self,
        run: &str,
        input: &serde_json::Value,
        snapshot: &crate::incremental_index::IndexedWorkspaceSnapshot,
    ) {
        let consumed = verify_scan_batch_child_equivalence(
            self.root.path(),
            run,
            input,
            &self.config,
            &self.registry,
        )
        .unwrap()
        .unwrap();
        let record = crate::run_artifacts::ToolRunRecord::new(
            self.workspace.root(),
            run,
            "run",
            "sast:scan",
        );
        crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
            record,
            input,
            None,
            Some(consumed.consumed.components.config_sha256),
            Vec::new(),
        )
        .unwrap();
        self.complete_labeled_receipt(record, input, snapshot);
    }

    fn complete_labeled_receipt(
        &self,
        record: crate::run_artifacts::ToolRunRecord<'_>,
        input: &serde_json::Value,
        snapshot: &crate::incremental_index::IndexedWorkspaceSnapshot,
    ) {
        use crate::run_lifecycle::{RunItemStatus, RunObservationHandle, SafeText};
        let observation =
            RunObservationHandle::jsonl(self.workspace.root().to_path_buf(), record.run_id)
                .unwrap();
        // Synthetic application call; no scanner executor or provider runs.
        let call = crate::modules::ApplicationToolCall::start(
            observation.clone(),
            "sast:scan",
            input,
            None,
            None,
        )
        .unwrap();
        let completion = call.completion(
            RunItemStatus::Completed,
            crate::runtime::RuntimeCostReport::UNAVAILABLE,
            vec![SafeText::operator_visible(
                "Labeled synthetic receipt; no executor invoked",
            )],
            0,
            0,
        );
        let output = json!({"status":"completed","data":{"engines":["secret-scan"],
            "snapshotHash":snapshot.snapshot_hash,"treeHash":snapshot.tree_hash}});
        crate::run_artifacts::try_record_tool_run_complete_settled(
            record,
            &output,
            &observation,
            completion,
        )
        .unwrap();
    }
}

fn labeled_observation() -> Finding {
    Finding::new_tool(
        "secret-scan",
        "labeled-report-fixture",
        "main.rs",
        1,
        None,
        crate::Severity::Info,
        "Labeled synthetic report observation, no security defect claimed",
    )
}

#[test]
#[ignore = "Produces owned native TUI receipts only when explicitly requested"]
fn native_matrix_handoff_fixture() {
    let output = std::env::var_os("KUZUSHI_DEVEX_MATRIX_TARGET_FILE")
        .expect("fixture output path is required");
    let fixture = Fixture::new();
    fixture.plan(true);
    fixture.observations();
    write_native_fixture_queue(fixture.root.path());
    let target = fixture.root.keep();
    fs::write(output, target.to_string_lossy().as_bytes()).unwrap();
}

fn write_native_fixture_queue(root: &Path) {
    let path =
        crate::capabilities::campaign::campaign_dir(root, "matrix-report").join("queue.json");
    let mut queue: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    queue["campaignId"] = json!("matrix-report");
    queue["updatedAtMs"] = json!(1);
    for job in queue["jobs"].as_object_mut().unwrap().values_mut() {
        job["dispatches"] = json!(1);
        job["providerSpendUnresolved"] = json!(false);
        let attempt = &mut job["attemptRuns"][0];
        attempt["attempt"] = json!(1);
        attempt["dispatch"] = json!(1);
        attempt["startedAtMs"] = json!(1);
        attempt["state"] = json!("completed");
    }
    fs::write(path, queue.to_string()).unwrap();
}

#[test]
fn matrix_report_retains_per_case_denominators_and_authenticates_selected_runs() {
    let fixture = Fixture::new();
    fixture.plan(true);
    let runs = fixture.observations();
    let document = load_investigation_report_document_for_runs(&fixture.workspace, &runs)
        .unwrap()
        .unwrap();
    assert_eq!(
        document.work_counts(),
        InvestigationWorkCounts {
            planned: 9,
            completed: 9,
            failed: 0,
            pending: 0
        }
    );
    assert_eq!(
        (
            document.summary().observation_count,
            document.summary().finding_count
        ),
        (6, 1)
    );
    let value = serde_json::to_value(&document).unwrap();
    assert_eq!(value["kind"], "context-matrix");
    assert!(value.get("equivalence").is_none());
    assert!(value["occurrence"].get("completed").is_none());
    for (index, seen) in [3, 2, 1].into_iter().enumerate() {
        assert_eq!(
            value["occurrence"]["cases"][index]["occurrence"]["rows"][0]["seen"],
            seen
        );
        assert_eq!(
            value["occurrence"]["cases"][index]["occurrence"]["completed"],
            3
        );
    }
    assert!(load_investigation_report_document_for_runs(&fixture.workspace, &runs[..8]).is_err());
    assert!(load_investigation_report(&fixture.workspace, "matrix-report").is_err());
}

#[test]
fn unapproved_matrix_and_changed_approved_plan_cannot_claim_approved_work() {
    let fixture = Fixture::new();
    fixture.plan(false);
    assert!(load_investigation_report_document(&fixture.workspace, "matrix-report").is_err());
    fixture.approve();
    let mut plan = read_campaign_plan_document(fixture.root.path(), "matrix-report").unwrap();
    plan["contextMatrix"]["cases"][1]["label"] = json!("Changed label");
    let path = crate::capabilities::campaign::campaign_dir(fixture.root.path(), "matrix-report")
        .join("plan.json");
    fs::write(path, plan.to_string()).unwrap();
    assert!(load_investigation_report_document(&fixture.workspace, "matrix-report").is_err());
}

#[test]
fn matrix_preview_filters_unrelated_history_and_preserves_historical_source() {
    let fixture = Fixture::new();
    fixture.plan(true);
    fixture.observations();
    let store = FindingStore::open(fixture.workspace.findings_db_path()).unwrap();
    store
        .record_run_started("unrelated", fixture.workspace.root(), "completed")
        .unwrap();
    let mut unrelated = labeled_observation();
    unrelated.rule_id = "unrelated".into();
    unrelated.fingerprint = "unrelated".into();
    store.insert_finding("unrelated", &unrelated).unwrap();
    drop(store);
    let options = WorkspaceExportOptions::default().with_campaign(Some("matrix-report".into()));
    let preview = preview_workspace_findings_export(
        &fixture.workspace,
        WorkspaceExportFormat::Json,
        &options,
    )
    .unwrap();
    assert_eq!((preview.count, preview.total_count), (1, 1));
    assert_eq!(
        preview.investigation.as_ref().unwrap()["observationCount"],
        6
    );
    fs::write(
        fixture.root.path().join("main.rs"),
        "// Later source, never executed.\n",
    )
    .unwrap();
    let later = load_investigation_report_document(&fixture.workspace, "matrix-report").unwrap();
    assert_eq!(later.summary().observation_count, 6);
    assert_eq!(
        serde_json::to_value(&later).unwrap()["cases"],
        preview.investigation.unwrap()["cases"]
    );
}

#[test]
fn matrix_exports_and_confirmed_sarif_keep_cases_raw_observations_and_human_decisions() {
    use crate::findings::{ReviewDecision, ReviewDecisionVerdict, TriageAuthor};
    let fixture = Fixture::new();
    fixture.plan(true);
    fixture.observations();
    let store = FindingStore::open(fixture.workspace.findings_db_path()).unwrap();
    let finding = store.list_all_findings().unwrap().pop().unwrap();
    store
        .append_user_review_decision(
            finding.id.unwrap(),
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "Labeled synthetic report decision, no real security defect claimed"
                    .into(),
                dismiss_reason: None,
                actor: Some("operator".into()),
            },
        )
        .unwrap();
    for (format, path) in [
        (WorkspaceExportFormat::Json, "matrix.json"),
        (WorkspaceExportFormat::Jsonl, "matrix.jsonl"),
        (WorkspaceExportFormat::Sarif, "matrix.sarif"),
        (WorkspaceExportFormat::Csv, "matrix.csv"),
        (WorkspaceExportFormat::VulnFindings, "matrix-vuln.json"),
        (WorkspaceExportFormat::MarkdownBundle, "matrix-bundle"),
    ] {
        let options =
            WorkspaceExportOptions::new(Some(format)).with_campaign(Some("matrix-report".into()));
        let result = export_workspace_findings_with_options(
            &fixture.workspace,
            fixture.root.path().join(path),
            &options,
        )
        .unwrap();
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(result.investigation_receipt_path.unwrap()).unwrap())
                .unwrap();
        assert_eq!(receipt["observationCount"], 6);
        assert_eq!(receipt["reviewedCount"], 1);
        assert_eq!(receipt["confirmedCount"], 1);
        assert_eq!(receipt["cases"].as_array().unwrap().len(), 3);
        assert!(receipt.get("equivalence").is_none());
    }
    let mut ctx = fixture.ctx();
    ctx.findings_store = Some(&store);
    let prepared = fixture
        .registry
        .prepare_dispatch_input(
            "report:sarif",
            json!({"campaignId":"matrix-report","output":"matrix-confirmed.sarif"}),
            &ctx,
            None,
        )
        .unwrap()
        .authorize_explicit_headless();
    fixture
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    let sarif: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture.root.path().join("matrix-confirmed.sarif")).unwrap(),
    )
    .unwrap();
    assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 1);
    assert_eq!(
        sarif["runs"][0]["properties"]["kuzushiExport"]["investigation"]["kind"],
        "context-matrix"
    );
    assert!(
        fs::read_to_string(fixture.root.path().join("matrix-bundle/README.md"))
            .unwrap()
            .contains("Recurrence is separate for each context.")
    );
}

#[test]
fn matrix_handoff_is_unselected_idempotent_and_keeps_the_complete_attempt_set() {
    let fixture = Fixture::new();
    fixture.plan(true);
    let runs = fixture.observations();
    let store = FindingStore::open_read_only(fixture.workspace.findings_db_path()).unwrap();
    let record = || {
        crate::capabilities::campaign::record_scan_batch_phase_result(
            fixture.root.path(),
            "matrix-report",
            &store,
        )
        .unwrap()
        .unwrap()
    };
    let id = record();
    let path = crate::workflow_attempts::phase_attempt_ledger_path(fixture.root.path());
    let before = fs::read(&path).unwrap();
    assert_eq!(record(), id);
    assert_eq!(fs::read(path).unwrap(), before);
    let ledger = crate::workflow_attempts::load_phase_attempt_ledger(fixture.root.path()).unwrap();
    let result = ledger.attempt(&id).unwrap();
    assert!(!ledger.content_reuse_is_blocked(&id));
    assert!(result.disposition.is_none());
    assert_eq!(
        result.completed.outcome,
        crate::workflow_attempts::PhaseAttemptOutcome::Completed
    );
    assert_eq!(result.completed.run_refs, runs);
    fs::write(
        fixture.root.path().join("main.rs"),
        "// Later owned source.\n",
    )
    .unwrap();
    let changed = crate::workflow_attempts::load_phase_attempt_ledger(fixture.root.path()).unwrap();
    assert!(changed.content_reuse_is_blocked(&id));
    assert_eq!(changed.attempt(&id).unwrap().completed.run_refs, runs);
}

#[test]
fn matrix_handoff_preserves_partial_work_and_blocks_changed_source_selection() {
    let fixture = Fixture::new();
    fixture.plan(true);
    fixture.observations();
    let path = crate::capabilities::campaign::campaign_dir(fixture.root.path(), "matrix-report")
        .join("queue.json");
    let mut queue: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for id in ["gamma-trial-002", "gamma-trial-003"] {
        queue["jobs"][id] =
            json!({"state":"parked","attempts":0,"reason":"operator stopped remaining work"});
    }
    fs::write(path, queue.to_string()).unwrap();
    fs::write(
        fixture.root.path().join("main.rs"),
        "// Later owned source, never executed.\n",
    )
    .unwrap();
    let store = FindingStore::open_read_only(fixture.workspace.findings_db_path()).unwrap();
    let id = crate::capabilities::campaign::record_scan_batch_phase_result(
        fixture.root.path(),
        "matrix-report",
        &store,
    )
    .unwrap()
    .unwrap();
    let ledger = crate::workflow_attempts::load_phase_attempt_ledger(fixture.root.path()).unwrap();
    let result = ledger.attempt(&id).unwrap();
    assert_eq!(
        result.completed.outcome,
        crate::workflow_attempts::PhaseAttemptOutcome::Partial
    );
    assert!(result.disposition.is_none());
    assert_eq!(result.completed.run_refs.len(), 7);
    assert!(result
        .completed
        .selection_blocked_reason
        .as_ref()
        .unwrap()
        .contains("earlier source content"));
    assert_eq!(
        store
            .count_finding_observations_for_scan_ids(&result.completed.run_refs)
            .unwrap(),
        6
    );
}

#[test]
fn unstarted_matrix_creates_no_scan_attempt() {
    let fixture = Fixture::new();
    fixture.plan(true);
    let store = FindingStore::open_read_only(fixture.workspace.findings_db_path()).unwrap();
    assert!(
        crate::capabilities::campaign::record_scan_batch_phase_result(
            fixture.root.path(),
            "matrix-report",
            &store
        )
        .unwrap()
        .is_none()
    );
    assert!(
        crate::workflow_attempts::load_phase_attempt_events(fixture.root.path())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn completed_retry_selection_keeps_canceled_history_and_observations_in_reports() {
    let fixture = Fixture::new();
    fixture.plan(true);
    let selected = fixture.observations();
    let plan = read_campaign_plan_document(fixture.root.path(), "matrix-report").unwrap();
    let job = &plan["jobs"][0];
    let run = "matrix-prior-canceled";
    let consumed = verify_scan_batch_child_equivalence(
        fixture.root.path(),
        run,
        &job["input"],
        &fixture.config,
        &fixture.registry,
    )
    .unwrap()
    .unwrap();
    let record =
        crate::run_artifacts::ToolRunRecord::new(fixture.root.path(), run, "run", "sast:scan");
    crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        &job["input"],
        None,
        Some(consumed.consumed.components.config_sha256),
        vec![],
    )
    .unwrap();
    crate::run_artifacts::try_record_tool_run_canceled(record, "owned fixture cancellation")
        .unwrap();
    let path = crate::capabilities::campaign::campaign_dir(fixture.root.path(), "matrix-report")
        .join("queue.json");
    let mut queue: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    queue["jobs"][job["jobId"].as_str().unwrap()]["attemptRuns"]
        .as_array_mut()
        .unwrap()
        .insert(0, json!({"runId":run,"outcome":"canceled"}));
    fs::write(path, queue.to_string()).unwrap();
    let store = FindingStore::open(fixture.workspace.findings_db_path()).unwrap();
    store
        .record_run_started(run, fixture.root.path(), "canceled")
        .unwrap();
    let mut finding = labeled_observation();
    finding.rule_id = "canceled-observation".into();
    finding.fingerprint = "canceled-observation".into();
    store.insert_finding(run, &finding).unwrap();
    let document = load_investigation_report_document_for_runs(&fixture.workspace, &selected)
        .unwrap()
        .unwrap();
    assert_eq!(document.summary().attempts.len(), 10);
    assert_eq!(document.summary().observation_count, 7);
    assert_eq!(
        document.phase_result_run_ids().unwrap(),
        selected
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    );
    let mut legacy = selected.clone();
    legacy.push(run.into());
    assert!(
        load_investigation_report_document_for_runs(&fixture.workspace, &legacy)
            .unwrap()
            .is_some()
    );
    assert!(
        load_investigation_report_document_for_runs(&fixture.workspace, &selected[..8]).is_err()
    );
    let id = crate::capabilities::campaign::record_scan_batch_phase_result(
        fixture.root.path(),
        "matrix-report",
        &store,
    )
    .unwrap()
    .unwrap();
    let ledger = crate::workflow_attempts::load_phase_attempt_ledger(fixture.root.path()).unwrap();
    let result = ledger.attempt(&id).unwrap();
    assert_eq!(
        result.completed.outcome,
        crate::workflow_attempts::PhaseAttemptOutcome::Completed
    );
    assert_eq!(result.completed.run_refs.len(), 9);
    assert!(!result.completed.run_refs.iter().any(|id| id == run));
}

#[test]
fn every_authenticated_matrix_case_reaches_report_scan_selection() {
    let fixture = Fixture::new();
    fixture.plan(true);
    let report = load_investigation_report_document(&fixture.workspace, "matrix-report").unwrap();
    let selections = report.summary().scan_selection;
    assert_eq!(selections.len(), 3);
    assert_eq!(
        selections
            .iter()
            .map(|row| row.case_id.as_deref().unwrap())
            .collect::<Vec<_>>(),
        vec!["alpha", "beta", "gamma"]
    );
    for selection in selections {
        assert_eq!(selection.parameters["tasks"], json!(["secret-scan"]));
        assert_eq!(selection.parameters["taskMode"], "manual");
        assert!(!selection.parameters.contains_key("threatModelRef"));
    }
    assert!(report.summary().attempts.is_empty());
    let encoded = serde_json::to_value(&report).unwrap();
    assert_eq!(encoded["scanSelection"].as_array().unwrap().len(), 3);
}
