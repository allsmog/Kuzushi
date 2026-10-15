use super::*;
use crate::findings::ReviewCapturedFileState;
use crate::run_artifacts::ToolRunRecord;
use crate::run_lifecycle::{RunItemStatus, RunObservationHandle};
use crate::ApplicationToolCall;
mod supporting_files;

fn recorded_fixture() -> Fixture {
    let fixture = Fixture::new();
    record_source(&fixture);
    fixture
}

fn record_source(fixture: &Fixture) {
    record_source_at(&fixture.workspace);
}

fn record_source_at(workspace: &WorkspaceTarget) {
    let indexed = crate::incremental_index::index_workspace_snapshot(workspace).unwrap();
    let root = workspace.root();
    let input = json!({"target":root});
    let record = ToolRunRecord::new(root, "observed", "tool", "fixture:source");
    crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        &input,
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    let observation = RunObservationHandle::jsonl(root, "observed")
        .unwrap()
        .start_root_task("Owned source fixture")
        .unwrap();
    observation
        .task_handle()
        .unwrap()
        .update_and_flush(RunItemStatus::Running, None)
        .unwrap();
    let call =
        ApplicationToolCall::start(observation.clone(), "fixture:source", &input, None, None)
            .unwrap();
    let output = json!({"status":"completed","summary":"Owned source fixture, never executed",
        "data":{"snapshotHash":indexed.snapshot_hash,"treeHash":indexed.tree_hash}});
    let completion = call.completion_from_result(&Ok(output.clone()));
    crate::run_artifacts::try_record_tool_run_complete_settled(
        record,
        &output,
        &observation,
        completion,
    )
    .unwrap();
}

fn cited_input() -> Value {
    json!({"strategy":"standard","sourceEvidence":"cited"})
}

#[test]
fn review_source_evidence_freezes_exact_code_without_approval_or_jobs() {
    let fixture = recorded_fixture();
    let receipt = fixture.draft(cited_input());
    let evidence = receipt.source_evidence.as_ref().unwrap();
    assert_eq!(evidence.observations.len(), 1);
    assert_eq!(
        evidence.observations[0].binding,
        ReviewSourceBinding::MatchingRecordedSnapshot
    );
    assert_eq!(
        evidence.observations[0].text.as_deref(),
        Some("Owned review fixture. Never executed.\n")
    );
    assert_eq!(evidence.included_bytes, 38);
    assert!(receipt.input["sourceEvidenceRef"]
        .as_str()
        .unwrap()
        .starts_with("review-evidence:"));
    assert!(!campaign_dir(fixture.root.path(), "review")
        .join("queue.json")
        .exists());
    assert!(fixture
        .ledger()
        .allowance_snapshot("investigation")
        .is_err());
    let reread = load_review_study(fixture.root.path(), "review").unwrap();
    assert_eq!(reread.plan_sha256, receipt.plan_sha256);
    assert_eq!(reread.source_evidence, receipt.source_evidence);
}

#[test]
fn review_source_evidence_discloses_missing_recorded_source_and_refuses_approval() {
    let fixture = Fixture::new();
    let receipt = fixture.draft(cited_input());
    let evidence = receipt.source_evidence.as_ref().unwrap();
    assert_eq!(
        evidence.observations[0].binding,
        ReviewSourceBinding::RecordedSourceUnavailable
    );
    assert_eq!(evidence.included_bytes, 0);
    assert!(fixture
        .approve(fixture.approval(&receipt, 1))
        .unwrap_err()
        .to_string()
        .contains("No cited source text"));
    assert!(fixture
        .ledger()
        .allowance_snapshot("investigation")
        .is_err());
}

#[test]
fn review_source_evidence_does_not_substitute_a_changed_checkout() {
    let fixture = recorded_fixture();
    std::fs::write(
        fixture.root.path().join("note.md"),
        "Changed source, not the recorded observation.\n",
    )
    .unwrap();
    let receipt = fixture.draft(cited_input());
    let source = &receipt.source_evidence.as_ref().unwrap().observations[0];
    assert_eq!(source.binding, ReviewSourceBinding::RecordedSourceChanged);
    assert!(source.text.is_none());
    assert!(source.model_input().contains("No primary source text"));
    assert!(fixture.approve(fixture.approval(&receipt, 1)).is_err());
}

#[test]
fn review_source_evidence_refuses_source_drift_after_preparation() {
    let fixture = recorded_fixture();
    let receipt = fixture.draft(cited_input());
    std::fs::write(fixture.root.path().join("note.md"), "Later source.\n").unwrap();
    let error = fixture.approve(fixture.approval(&receipt, 1)).unwrap_err();
    assert!(error.to_string().contains("source changed"), "{error:#}");
    let historical = load_review_study(fixture.root.path(), "review").unwrap();
    assert!(historical.source_evidence.unwrap().observations[0]
        .text
        .as_deref()
        .unwrap()
        .contains("Owned review fixture"));
}

#[test]
fn review_source_evidence_bounds_complete_files_and_reports_binary_omissions() {
    let fixture = recorded_fixture();
    let receipt = fixture
        .draft(json!({"strategy":"standard","sourceEvidence":"cited","maxSourceEvidenceBytes":1}));
    let evidence = receipt.source_evidence.as_ref().unwrap();
    assert_eq!(evidence.included_bytes, 0);
    assert_eq!(
        evidence.observations[0].file.as_ref().unwrap().state,
        ReviewCapturedFileState::TooLarge
    );
    assert!(fixture.approve(fixture.approval(&receipt, 1)).is_err());

    let fixture = Fixture::new();
    std::fs::write(fixture.root.path().join("note.md"), b"Owned\0binary").unwrap();
    record_source(&fixture);
    let receipt = fixture.draft(cited_input());
    let file = receipt.source_evidence.unwrap().observations[0]
        .file
        .clone()
        .unwrap();
    assert_eq!(file.state, ReviewCapturedFileState::BinaryOrInvalidText);
}

#[test]
fn review_source_evidence_uses_one_total_byte_allowance_across_observations() {
    let fixture = recorded_fixture();
    fixture
        .store
        .insert_finding(
            "observed",
            &Finding::new_tool(
                "audit",
                "second",
                "note.md",
                2,
                None,
                Severity::Low,
                "Second labeled observation",
            ),
        )
        .unwrap();
    let receipt = fixture
        .draft(json!({"strategy":"standard","sourceEvidence":"cited","maxSourceEvidenceBytes":38}));
    let evidence = receipt.source_evidence.unwrap();
    assert_eq!(evidence.included_bytes, 38);
    assert_eq!(
        evidence
            .observations
            .iter()
            .filter(|source| source.text.is_some())
            .count(),
        1
    );
    assert_eq!(
        evidence
            .observations
            .iter()
            .filter(|source| source.binding == ReviewSourceBinding::ByteLimitReached)
            .count(),
        1
    );
}

fn replace_evidence(
    fixture: &Fixture,
    receipt: &ReviewStudyReceipt,
    document: &ReviewSourceEvidence,
) -> Value {
    let store = crate::content_store::ContentStore::open(fixture.workspace.objects_dir()).unwrap();
    let object = store
        .put_json(crate::content_store::ObjectKind::Blob, document)
        .unwrap();
    let mut input = receipt.input.clone();
    input["sourceEvidenceRef"] = json!(format!("review-evidence:{}", object.hash));
    input
}

#[test]
fn review_source_evidence_authenticates_bytes_generation_and_target() {
    let fixture = recorded_fixture();
    let receipt = fixture.draft(cited_input());
    for mutation in ["text", "generation", "target", "hash"] {
        let mut document = receipt.source_evidence.clone().unwrap();
        match mutation {
            "text" => document.observations[0].text = Some("Forged source".into()),
            "generation" => document.observations[0].generation_id += 1,
            "target" => document.target.push_str("-other"),
            _ => document.snapshot_hash = "a".repeat(64),
        }
        let input = replace_evidence(&fixture, &receipt, &document);
        assert!(
            crate::modules::source_evidence::inspect(
                fixture.root.path(),
                &input,
                &receipt.findings
            )
            .is_err(),
            "accepted {mutation}"
        );
    }
}

#[test]
fn review_source_evidence_cannot_replace_the_primary_file_with_another_valid_file() {
    let fixture = Fixture::new();
    std::fs::write(
        fixture.root.path().join("other.md"),
        "Owned review fixture. Never executed.\n",
    )
    .unwrap();
    record_source(&fixture);
    let receipt = fixture.draft(cited_input());
    let mut document = receipt.source_evidence.clone().unwrap();
    document.observations[0].path = "other.md".into();
    document.observations[0].file.as_mut().unwrap().path = "other.md".into();
    let input = replace_evidence(&fixture, &receipt, &document);
    assert!(crate::modules::source_evidence::inspect(
        fixture.root.path(),
        &input,
        &receipt.findings
    )
    .unwrap_err()
    .to_string()
    .contains("primary source"));
}

#[test]
fn review_source_evidence_keeps_legacy_inputs_unchanged_and_rejects_implicit_strategy_changes() {
    let fixture = Fixture::new();
    let receipt = fixture.draft(json!({"strategy":"standard"}));
    assert!(receipt.source_evidence.is_none());
    assert!(receipt.input.get("sourceEvidence").is_none());
    assert!(receipt.input.get("maxSourceEvidenceBytes").is_none());
    assert!(receipt.input.get("sourceEvidenceRef").is_none());
    let result = fixture.registry.execute_tool("campaign:review-study", json!({"campaignId":"deep-cited","investigationId":"investigation", "reviewInput":{"strategy":"deep","sourceEvidence":"cited","threatModelRef":null}}), &fixture.ctx());
    assert!(result.unwrap_err().to_string().contains("standard Review"));
}

#[derive(Clone, Default)]
struct RecordingReview {
    binding: Option<AllowanceBinding>,
    requests: Arc<std::sync::Mutex<Vec<TriageRequest>>>,
}

impl AgentRuntime for RecordingReview {
    fn with_allowance_binding(
        &self,
        binding: AllowanceBinding,
    ) -> Result<Box<dyn AgentRuntime + '_>> {
        Ok(Box::new(Self {
            binding: Some(binding),
            ..self.clone()
        }))
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        let binding = self
            .binding
            .as_ref()
            .context("Synthetic Review requires its approved allowance")?;
        let reservation = binding.reserve(&request.model)?;
        binding.settle(reservation, crate::runtime::RuntimeCostReport::UNAVAILABLE)?;
        self.requests.lock().unwrap().push(request);
        Ok(TriageOutcome {
            verdict: TriageVerdict::NeedsReview,
            confidence: 0.2,
            rationale: "Synthetic bounded Review; no provider request or vulnerability claim"
                .into(),
            ..Default::default()
        })
    }
}

#[test]
fn review_source_evidence_reaches_each_vote_without_rewriting_the_observation() {
    let fixture = recorded_fixture();
    let receipt = fixture.draft(json!({"strategy":"standard","sourceEvidence":"cited","votes":2}));
    let evidence = &receipt.source_evidence.as_ref().unwrap().observations[0];
    let original = receipt.findings[0].clone();
    let approval = fixture.approve(fixture.approval(&receipt, 2)).unwrap();
    let allowance = serde_json::from_value(approval["data"]["allowance"].clone()).unwrap();
    let input = receipt.bound_input(&allowance).unwrap();
    let runtime = RecordingReview::default();
    let result = fixture.run(input, &runtime, "review-with-source").unwrap();
    assert_eq!(result["data"]["successful"], 1);
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests.iter() {
        assert_eq!(request.finding.fingerprint, original.fingerprint);
        assert_eq!(request.finding.message, original.message);
        assert!(request
            .prompt_template
            .as_deref()
            .unwrap()
            .ends_with(&evidence.model_input()));
        assert_eq!(request.model, MODEL);
    }
    let recorded = fixture
        .store
        .get_finding_by_fingerprint(&original.fingerprint)
        .unwrap()
        .unwrap();
    assert_eq!(recorded.message, original.message);
    let accounting = fixture
        .ledger()
        .allowance_snapshot("investigation")
        .unwrap();
    assert_eq!(accounting.committed_calls, 2);
    assert_eq!(accounting.review_calls, 2);
    assert_eq!(accounting.unresolved_calls, 0);
}

#[test]
fn review_source_evidence_cancellation_starts_no_work() {
    let fixture = recorded_fixture();
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    let mut ctx = fixture.ctx();
    ctx.cancellation = Some(&cancellation);
    let result = fixture.registry.execute_tool("campaign:review-study", json!({"campaignId":"cancelled-review", "investigationId":"investigation", "reviewInput":{"strategy":"standard","sourceEvidence":"cited","threatModelRef":null}}), &ctx);
    assert!(result.is_err());
    assert!(!campaign_dir(fixture.root.path(), "cancelled-review").exists());
    assert!(fixture
        .ledger()
        .allowance_snapshot("investigation")
        .is_err());
}

#[test]
#[ignore = "Explicit native source-reader fixture preparation only"]
fn prepare_native_review_source_evidence_fixture() {
    let root = std::path::PathBuf::from(
        std::env::var("KUZUSHI_REVIEW_SOURCE_FIXTURE_OUT").expect("owned native fixture output"),
    );
    prepare_native_source_fixture(&root, false);
}

#[test]
#[ignore = "Explicit native supporting-file fixture preparation only"]
fn prepare_native_review_supporting_files_fixture() {
    let root = std::path::PathBuf::from(
        std::env::var("KUZUSHI_REVIEW_SOURCE_FIXTURE_OUT").expect("owned native fixture output"),
    );
    prepare_native_source_fixture(&root, true);
}

fn prepare_native_source_fixture(root: &std::path::Path, supporting: bool) {
    std::fs::create_dir_all(root).unwrap();
    assert!(
        !root.join("note.md").exists(),
        "Do not overwrite an existing source fixture"
    );
    let mut text = "Owned synthetic source-reader fixture. Never execute.\n".to_string();
    for index in 0..80 {
        text.push_str(&format!("SOURCE_LINE_{index:02} · owned inert text\n"));
    }
    std::fs::write(root.join("note.md"), text).unwrap();
    if supporting {
        for (path, text) in [
            (
                "service.txt",
                "SERVICE_INPUT · owned inert supporting text\n",
            ),
            ("store.txt", "STORE_INPUT · owned inert supporting text\n"),
            ("policy.txt", "POLICY_INPUT · owned inert supporting text\n"),
        ] {
            std::fs::write(root.join(path), text).unwrap();
        }
    }
    let workspace = WorkspaceTarget::new(&root).unwrap();
    assert!(
        !workspace.findings_db_path().exists(),
        "Do not replace an existing findings ledger"
    );
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("observed", &root, "running")
        .unwrap();
    store
        .insert_finding(
            "observed",
            &Finding::new_tool(
                "fixture-source",
                "owned-source",
                "note.md",
                2,
                None,
                Severity::Low,
                "Owned synthetic source observation; no vulnerability claim",
            ),
        )
        .unwrap();
    store
        .record_run_finished("observed", "completed", 1)
        .unwrap();
    record_source_at(&workspace);
}

#[test]
fn review_source_evidence_rejects_invalid_declared_resource_inputs() {
    let fixture = recorded_fixture();
    for review in [
        json!({"sourceEvidence":"cited","maxSourceEvidenceBytes":0}),
        json!({"sourceEvidence":"cited","maxSourceEvidenceBytes":262145}),
        json!({"sourceEvidence":"unknown"}),
        json!({"sourceEvidence":"none","sourceEvidenceRef":"review-evidence:invalid"}),
    ] {
        let mut review = review;
        review["strategy"] = json!("standard");
        review["threatModelRef"] = Value::Null;
        assert!(fixture.registry.execute_tool("campaign:review-study", json!({"campaignId":"invalid-review", "investigationId":"investigation", "reviewInput":review}), &fixture.ctx()).is_err());
    }
    assert!(!campaign_dir(fixture.root.path(), "invalid-review").exists());
    assert!(fixture
        .ledger()
        .allowance_snapshot("investigation")
        .is_err());
}
