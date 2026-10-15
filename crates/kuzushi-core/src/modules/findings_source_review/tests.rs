use super::*;
use crate::workspace::capture_review_source;
use crate::{Finding, FindingStore, ModuleRegistry, Severity, V2Config, WorkspaceTarget};

struct Fixture {
    _root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    store: FindingStore,
    config: V2Config,
    finding: Finding,
}

#[test]
fn code_reader_retains_captured_bytes_after_the_checkout_changes() {
    let fixture = Fixture::new();
    let captured = fixture.capture();
    assert_eq!(captured["citedSourceCode"], "Owned inert source A.\n");
    std::fs::write(
        fixture.workspace.root().join("note.txt"),
        "Changed source after capture.\n",
    )
    .unwrap();
    let read = fixture
        .execute(json!({"op":"read","finding":fixture.finding.fingerprint,
        "sourceRef":captured["sourceRef"]}))
        .unwrap();
    assert_eq!(read["data"]["citedSourceCode"], "Owned inert source A.\n");
    assert!(fixture.decide(&captured).is_err());
}

#[test]
fn oversized_cited_files_are_disclosed_without_a_truncated_code_claim() {
    let fixture = Fixture::new();
    let output = fixture
        .execute(json!({"finding":fixture.finding.fingerprint,"maxCitedSourceBytes":4}))
        .unwrap();
    assert_eq!(
        output["data"]["reviewedSource"]["citedFile"]["state"],
        "too_large"
    );
    assert!(output["data"]["citedSourceCode"].is_null());
}

#[test]
fn damaged_code_object_cannot_be_read_or_used_to_save_a_decision() {
    let fixture = Fixture::new();
    let capture = fixture.capture();
    let hash = crate::identity::Blake3Hash::new(
        capture["reviewedSource"]["citedFile"]["blobHash"]
            .as_str()
            .unwrap()
            .into(),
    )
    .unwrap();
    let store = crate::content_store::ContentStore::open(fixture.workspace.objects_dir()).unwrap();
    std::fs::write(store.object_path(&hash), "Invalid replacement").unwrap();
    assert!(fixture.decide(&capture).is_err());
    assert!(fixture
        .store
        .list_review_decisions(fixture.finding.id.unwrap())
        .unwrap()
        .is_empty());
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("note.txt"), "Owned inert source A.\n").unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("labeled-synthetic-observation", workspace.root(), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "fixture",
            "owned",
            "note.txt",
            1,
            None,
            Severity::Low,
            "Labeled synthetic observation",
        );
        store
            .insert_finding("labeled-synthetic-observation", &finding)
            .unwrap();
        let finding = store
            .get_finding_by_fingerprint(&finding.fingerprint)
            .unwrap()
            .unwrap();
        Self {
            _root: root,
            workspace,
            store,
            config: V2Config::default(),
            finding,
        }
    }

    fn ctx(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: Some(&self.store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }

    fn execute(&self, input: Value) -> Result<Value> {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = self.ctx();
        let prepared = registry
            .prepare_dispatch_input("findings:review-source", input, &ctx, None)?
            .authorize_explicit_headless();
        registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
    }

    fn capture(&self) -> Value {
        self.execute(json!({"finding":self.finding.fingerprint}))
            .unwrap()["data"]
            .clone()
    }

    fn decide(&self, capture: &Value) -> Result<Value> {
        self.execute(json!({"op":"decide","finding":self.finding.fingerprint,
            "sourceRef":capture["sourceRef"],"verdict":"deferred",
            "reason":"Owned source explicitly reviewed; further review is deferred"}))
    }
}

#[test]
fn capture_read_and_decide_preserve_current_source_without_new_observations() {
    let fixture = Fixture::new();
    let capture = fixture.capture();
    assert_eq!(capture["createsObservation"], false);
    assert_eq!(capture["providerRequests"], 0);
    let read = fixture
        .execute(json!({"op":"read","finding":fixture.finding.fingerprint,
        "sourceRef":capture["sourceRef"]}))
        .unwrap();
    assert_eq!(read["data"]["reviewedSource"], capture["reviewedSource"]);
    let saved = fixture.decide(&capture).unwrap();
    let id = saved["data"]["decisionId"].as_i64().unwrap();
    let recorded = crate::workspace::read_decision_reviewed_source(&fixture.workspace, id)
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(recorded).unwrap(),
        capture["reviewedSource"]
    );
    assert_eq!(
        fixture
            .store
            .list_review_decisions(fixture.finding.id.unwrap())
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        saved["data"]["currentCheckoutApplicability"],
        "matched_before_save"
    );
    assert_eq!(saved["data"]["fixStatus"], "not_assessed");
}

#[test]
fn changed_source_rejects_decision_and_preserves_the_original_capture() {
    let fixture = Fixture::new();
    let capture = fixture.capture();
    std::fs::write(
        fixture.workspace.root().join("note.txt"),
        "Owned source B.\n",
    )
    .unwrap();
    assert!(fixture
        .decide(&capture)
        .unwrap_err()
        .to_string()
        .contains("Source content changed"));
    assert!(fixture
        .store
        .list_review_decisions(fixture.finding.id.unwrap())
        .unwrap()
        .is_empty());
    let next = fixture.capture();
    assert_ne!(next["sourceRef"], capture["sourceRef"]);
    assert_ne!(
        next["reviewedSource"]["treeHash"],
        capture["reviewedSource"]["treeHash"]
    );
    fixture.decide(&next).unwrap();
}

#[test]
fn intervening_human_decision_rejects_the_old_source_review_cutoff() {
    let fixture = Fixture::new();
    let capture = fixture.capture();
    let decision = ReviewDecision {
        verdict: ReviewDecisionVerdict::NeedsReview,
        author: TriageAuthor::Human,
        confidence: 1.0,
        rationale: "Later explicit decision".into(),
        dismiss_reason: None,
        actor: Some("operator".into()),
    };
    crate::workspace::record_user_review_decision_for_finding(
        &fixture.workspace,
        &fixture.finding,
        &decision,
    )
    .unwrap();
    assert!(fixture
        .decide(&capture)
        .unwrap_err()
        .to_string()
        .contains("changed after read watermark"));
    assert_eq!(
        fixture
            .store
            .list_review_decisions(fixture.finding.id.unwrap())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn malformed_unknown_and_cross_target_references_never_write_decisions() {
    let fixture = Fixture::new();
    for reference in ["../outside", "review-source:bad"] {
        assert!(fixture.decide(&json!({"sourceRef":reference})).is_err());
    }
    let other = Fixture::new();
    assert!(other.decide(&fixture.capture()).is_err());
    assert!(fixture
        .execute(json!({"finding":fixture.finding.fingerprint,"unknownOption":true}))
        .is_err());
    assert!(fixture
        .store
        .list_review_decisions(fixture.finding.id.unwrap())
        .unwrap()
        .is_empty());
}

#[test]
fn decision_requires_an_explicit_verdict_and_nonempty_reason() {
    let fixture = Fixture::new();
    let capture = fixture.capture();
    for additions in [json!({}), json!({"verdict":"deferred","reason":"   "})] {
        let mut input = json!({"op":"decide","finding":fixture.finding.fingerprint,
            "sourceRef":capture["sourceRef"]});
        input
            .as_object_mut()
            .unwrap()
            .extend(additions.as_object().unwrap().clone());
        assert!(fixture.execute(input).is_err());
    }
    assert!(fixture
        .store
        .list_review_decisions(fixture.finding.id.unwrap())
        .unwrap()
        .is_empty());
}

#[test]
fn source_review_requires_explicit_operator_authorization() {
    let fixture = Fixture::new();
    let registry = ModuleRegistry::with_v2_builtins();
    let ctx = fixture.ctx();
    let prepared = registry
        .prepare_dispatch_input(
            "findings:review-source",
            json!({"finding":fixture.finding.fingerprint}),
            &ctx,
            None,
        )
        .unwrap();
    assert!(registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap_err()
        .to_string()
        .contains("explicit operator authorization"));
    assert!(fixture
        .store
        .list_review_decisions(fixture.finding.id.unwrap())
        .unwrap()
        .is_empty());
}

#[test]
fn a_future_cutoff_is_rejected_before_appending_a_decision_event() {
    let fixture = Fixture::new();
    let capture = fixture.capture();
    let mut source = capture["reviewedSource"].clone();
    source["readWatermark"] = json!(u64::MAX);
    let object = crate::content_store::ContentStore::open(fixture.workspace.objects_dir())
        .unwrap()
        .put_json(crate::content_store::ObjectKind::Blob, &source)
        .unwrap();
    let before = fixture.store.projection_meta().unwrap().applied_seq;
    let error = fixture
        .decide(&json!({"sourceRef":format!("review-source:{}",object.hash)}))
        .unwrap_err();
    assert!(error.to_string().contains("newer than this ledger"));
    assert_eq!(fixture.store.projection_meta().unwrap().applied_seq, before);
    assert!(fixture
        .store
        .list_review_decisions(fixture.finding.id.unwrap())
        .unwrap()
        .is_empty());
}

#[test]
fn source_review_respects_cancellation_without_saving_a_decision() {
    let fixture = Fixture::new();
    let capture = fixture.capture();
    let cancel = crate::scan::ScanCancellation::default();
    cancel.cancel();
    let mut ctx = fixture.ctx();
    ctx.cancellation = Some(&cancel);
    let decision =
        human_decision(&json!({"verdict":"deferred","reason":"Owned reviewed source"})).unwrap();
    assert!(decide_on_review_source(
        &ctx,
        &fixture.finding,
        &decision,
        capture["sourceRef"].as_str().unwrap()
    )
    .is_err());
    assert!(capture_review_source(&ctx, &fixture.finding).is_err());
    assert!(fixture
        .store
        .list_review_decisions(fixture.finding.id.unwrap())
        .unwrap()
        .is_empty());
}

#[test]
fn source_metadata_survives_projection_rebuild_and_export() {
    let fixture = Fixture::new();
    let capture = fixture.capture();
    let result = fixture.decide(&capture).unwrap();
    let before = fixture
        .store
        .latest_review_decision(fixture.finding.id.unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(result["data"]["decisionId"], before.id);
    crate::storage_v3::writer_actor::StorageWriterActor::commit_blocking(
        fixture.workspace.event_log_dir(),
        fixture.workspace.findings_db_path(),
        crate::storage_v3::writer_actor::WriterCommand::Control(
            crate::storage_v3::writer_actor::ControlCommand::RebuildProjection,
        ),
    )
    .unwrap();
    let reopened = FindingStore::open_read_only(fixture.workspace.findings_db_path()).unwrap();
    let after = reopened
        .latest_review_decision(fixture.finding.id.unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        before.provenance.as_ref().unwrap().event_hash,
        after.provenance.as_ref().unwrap().event_hash
    );
    assert_eq!(
        serde_json::to_value(
            reopened
                .reviewed_source_for_decision(
                    reopened
                        .latest_review_decision(fixture.finding.id.unwrap())
                        .unwrap()
                        .unwrap()
                        .id
                )
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        capture["reviewedSource"]
    );
    let output = fixture.workspace.root().join(".kuzushi/reviewed.json");
    crate::workspace::export_workspace_findings(
        &fixture.workspace,
        &output,
        Some(crate::workspace::WorkspaceExportFormat::Json),
    )
    .unwrap();
    let exported: Value = serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
    assert_eq!(
        exported["findings"][0]["reviewedSource"],
        capture["reviewedSource"]
    );
}
