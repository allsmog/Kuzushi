use super::super::*;
use super::tests::{sample_document, MockThreatRuntime};
use crate::modules::{phase_result_phase, ModuleMaturity, ModuleRegistry};
use crate::scan::ScanCancellation;
use crate::{V2Config, WorkspaceTarget};
use kuzushi_descriptor::AllowanceCategory;

fn context<'a>(workspace: &'a WorkspaceTarget, config: &'a V2Config) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

fn normalized(root: &Path, directory: &str) -> PathBuf {
    let path = root.join(directory).join("normalized-threat-model.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        serde_json::to_vec_pretty(&sample_document()).unwrap(),
    )
    .unwrap();
    path
}

fn read(root: &Path, directory: &str, extra: Value) -> Result<Value> {
    let workspace = WorkspaceTarget::new(root)?;
    let config = V2Config::default();
    let mut input = json!({"outputDir":directory});
    input
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    ModuleRegistry::with_v2_builtins_without_optional_adapters().execute_tool(
        "randori:threat-model",
        input,
        &context(&workspace, &config),
    )
}

fn build(root: &Path, input: Value, runtime: &dyn AgentRuntime) -> Result<Value> {
    fs::write(
        root.join("package.json"),
        "{\"dependencies\":{\"express\":\"4\"}}",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root)?;
    let config = V2Config {
        model: Some("openai:gpt-4.1".into()),
        ..Default::default()
    };
    let ctx = context(&workspace, &config);
    let accounted = super::accounting::account_runtime(&ctx, runtime, 1);
    ModuleRegistry::with_v2_builtins_without_optional_adapters().execute_tool_with_runtime(
        "randori:pasta",
        input,
        &ctx,
        Some(&accounted),
    )
}

#[test]
fn randori_actions_are_auxiliary_with_truthful_maturity_and_allowance() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let producer = registry.resolve_tool("randori:pasta").unwrap();
    let reader = registry.resolve_tool("randori:threat-model").unwrap();
    assert_eq!(phase_result_phase(producer), None);
    assert_eq!(phase_result_phase(reader), None);
    assert!(!producer.phase_result && !reader.phase_result);
    assert_eq!(producer.discovery_maturity, Some(ModuleMaturity::Labs));
    assert_eq!(
        producer.allowance_category,
        Some(AllowanceCategory::Context)
    );
    assert_eq!(
        reader.discovery_maturity,
        Some(ModuleMaturity::Compatibility)
    );
}

#[test]
fn malformed_optional_stage_stays_partial_and_preserves_all_input_bytes() {
    let root = tempfile::tempdir().unwrap();
    let path = normalized(root.path(), "artifacts");
    let before = fs::read(&path).unwrap();
    let stage = path.with_file_name("pasta-s2.json");
    fs::write(&stage, "not JSON").unwrap();
    let result = read(root.path(), "artifacts", json!({})).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(
        result["data"]["document"]["dfd"]["nodes"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        result["data"]["artifactRead"]["sourceIdentity"],
        "unverified"
    );
    assert_eq!(result["data"]["artifactRead"]["complete"], false);
    assert!(result["warnings"].to_string().contains("pasta-s2.json"));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::read_to_string(&stage).unwrap(), "not JSON");
}

#[test]
fn empty_stage_is_incomplete_context_instead_of_completed_model() {
    let root = tempfile::tempdir().unwrap();
    let folder = root.path().join("stages");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("pasta-s2.json"), "{}").unwrap();
    let result = read(root.path(), "stages", json!({})).unwrap();
    assert_eq!(result["status"], "partial");
    assert!(result["warnings"].to_string().contains("No DFD nodes"));
    assert!(result["data"]["modelRef"].is_null());
}

#[test]
fn malformed_primary_does_not_silently_fall_back_to_stage_fragments() {
    let root = tempfile::tempdir().unwrap();
    let path = normalized(root.path(), "artifacts");
    fs::write(&path, "not JSON").unwrap();
    fs::write(path.with_file_name("pasta-s2.json"), "{}").unwrap();
    let result = read(root.path(), "artifacts", json!({})).unwrap();
    assert_eq!(result["status"], "failed");
    assert_eq!(result["data"]["reason"], "unusable-artifacts");
    assert_eq!(result["data"]["artifactRead"]["filesUninspected"], 6);
    assert_eq!(fs::read_to_string(path).unwrap(), "not JSON");
}

#[test]
fn literal_paths_and_the_canonical_reader_consume_identical_documents() {
    let root = tempfile::tempdir().unwrap();
    normalized(root.path(), "literal directory ");
    let legacy = read(
        root.path(),
        "literal directory ",
        json!({"model":"unused-legacy-model"}),
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let canonical = ModuleRegistry::with_v2_builtins_without_optional_adapters()
        .execute_tool(
            "threat-model:read",
            json!({"outputDir":"literal directory ","methodology":"pasta"}),
            &context(&workspace, &config),
        )
        .unwrap();
    assert_eq!(legacy["status"], "completed");
    assert_eq!(legacy["data"]["document"], canonical["data"]["document"]);
    assert_eq!(legacy["data"]["ignoredModelOption"], true);
    assert!(legacy["output"]
        .as_str()
        .unwrap()
        .contains("no model request"));
}

#[test]
fn oversized_stage_is_omitted_without_reading_its_sparse_contents() {
    let root = tempfile::tempdir().unwrap();
    let path = normalized(root.path(), "artifacts");
    let stage = path.with_file_name("pasta-s2.json");
    fs::File::create(&stage)
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    let result = read(root.path(), "artifacts", json!({})).unwrap();
    let row = result["data"]["artifactRead"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["file"] == "pasta-s2.json")
        .unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(row["status"], "oversized");
    assert_eq!(row["bytesReserved"], 0);
    assert!(row["sha256"].is_null());
}

#[test]
fn artifact_set_read_reservations_do_not_exceed_the_aggregate_limit() {
    let root = tempfile::tempdir().unwrap();
    let path = normalized(root.path(), "artifacts");
    for name in ["pasta-s1.json", "pasta-s2.json"] {
        fs::File::create(path.with_file_name(name))
            .unwrap()
            .set_len(16 * 1024 * 1024)
            .unwrap();
    }
    let result = read(root.path(), "artifacts", json!({})).unwrap();
    let receipt = &result["data"]["artifactRead"];
    assert_eq!(result["status"], "partial");
    assert!(receipt["bytesReserved"].as_u64().unwrap() <= 32 * 1024 * 1024);
    assert!(receipt["files"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["status"] == "omitted"));
}

#[test]
#[cfg(unix)]
fn linked_optional_stage_is_disclosed_without_reading_the_target() {
    let root = tempfile::tempdir().unwrap();
    let path = normalized(root.path(), "artifacts");
    let outside = tempfile::tempdir().unwrap();
    let other = outside.path().join("operator.json");
    fs::write(&other, "{\"privateMarker\":\"must-not-be-read\"}").unwrap();
    std::os::unix::fs::symlink(&other, path.with_file_name("pasta-s2.json")).unwrap();
    let result = read(root.path(), "artifacts", json!({})).unwrap();
    assert_eq!(result["status"], "partial");
    assert!(!result.to_string().contains("must-not-be-read"));
    assert!(result["data"]["artifacts"]["s2Scope"].is_null());
}

#[test]
fn cancelled_artifact_reads_do_not_return_a_completed_model() {
    let root = tempfile::tempdir().unwrap();
    normalized(root.path(), "artifacts");
    let cancellation = ScanCancellation::default();
    cancellation.cancel();
    let inspection =
        inspect_randori_artifacts(root.path(), "artifacts", Some(&cancellation)).unwrap();
    assert!(inspection.receipt.cancelled);
    assert_eq!(inspection.receipt.bytes_reserved, 0);
    assert!(inspection.normalized.is_none());
}

#[test]
fn existing_draft_files_refuse_before_model_work_and_preserve_operator_edits() {
    let root = tempfile::tempdir().unwrap();
    let path = normalized(root.path(), ".kuzushi/draft");
    fs::write(&path, "{\"operatorNote\":\"keep these bytes\"}").unwrap();
    let runtime = MockThreatRuntime::new(sample_document());
    let error = build(root.path(), json!({"outputDir":".kuzushi/draft"}), &runtime).unwrap_err();
    assert!(error.to_string().contains("Draft preserved"));
    assert!(runtime.requests().is_empty());
    assert_eq!(
        fs::read_to_string(path).unwrap(),
        "{\"operatorNote\":\"keep these bytes\"}"
    );
}

#[test]
fn explicit_replacement_and_reader_roundtrip_leave_active_context_unchanged() {
    let root = tempfile::tempdir().unwrap();
    let path = normalized(root.path(), ".kuzushi/draft ");
    let runtime = MockThreatRuntime::new(sample_document());
    let result = build(
        root.path(),
        json!({"outputDir":".kuzushi/draft ","preserveUserEdits":false}),
        &runtime,
    )
    .unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["persisted"], false);
    assert!(result["data"]["modelRef"].is_null());
    assert!(path.is_file());
    let loaded = read(root.path(), ".kuzushi/draft ", json!({})).unwrap();
    assert_eq!(loaded["data"]["document"], result["data"]["document"]);
    assert!(!root.path().join(".kuzushi/threat-model.json").exists());
    let requests = runtime.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].tool_policy.tools.is_empty());
    assert!(!requests[0].tool_policy.mcps);
    assert_eq!(
        requests[0]
            .runtime_options
            .as_ref()
            .unwrap()
            .max_model_turns,
        Some(1)
    );
}

#[test]
fn produced_draft_imports_as_an_inactive_immutable_revision_for_the_next_reader() {
    let root = tempfile::tempdir().unwrap();
    let runtime = MockThreatRuntime::new(sample_document());
    let draft = build(root.path(), json!({"outputDir":".kuzushi/draft"}), &runtime).unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let imported = registry
        .execute_tool(
            "threat-model:import",
            json!({
                "path":draft["data"]["normalizedArtifact"], "methodology":"pasta", "activate":false,
            }),
            &context(&workspace, &config),
        )
        .unwrap();
    let loaded = registry
        .execute_tool(
            "threat-model:read",
            json!({
                "threatModelRef":imported["data"]["modelRef"],
            }),
            &context(&workspace, &config),
        )
        .unwrap();
    assert_eq!(loaded["data"]["resolvedFrom"], "exact-context");
    assert_eq!(
        loaded["data"]["document"]["dfd"],
        draft["data"]["document"]["dfd"]
    );
    assert_eq!(loaded["data"]["modelRef"], imported["data"]["modelRef"]);
    assert!(!root.path().join(".kuzushi/threat-model.json").exists());
    assert_eq!(runtime.requests().len(), 1);
}

#[test]
fn unsolicited_bridge_findings_are_not_emitted_by_default() {
    let root = tempfile::tempdir().unwrap();
    let runtime = MockThreatRuntime::new(json!({
        "document":sample_document(),
        "findings":[{"title":"Unrequested bridge observation","severity":"high"}],
    }));
    let draft = build(root.path(), json!({"outputDir":".kuzushi/draft"}), &runtime).unwrap();
    assert_eq!(draft["data"]["findings"], json!([]));
    assert!(draft["findings"].as_array().is_none_or(Vec::is_empty));
}

#[test]
fn invalid_declared_limits_refuse_before_querying() {
    let root = tempfile::tempdir().unwrap();
    let runtime = MockThreatRuntime::new(sample_document());
    for input in [
        json!({"maxElements":4}),
        json!({"maxElements":501}),
        json!({"maxThreats":0}),
        json!({"maxThreats":501}),
    ] {
        assert!(build(root.path(), input, &runtime).is_err());
    }
    assert!(runtime.requests().is_empty());
}

#[test]
#[cfg(unix)]
fn linked_producer_output_refuses_before_querying() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join(".kuzushi")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join(".kuzushi/draft")).unwrap();
    let runtime = MockThreatRuntime::new(sample_document());
    assert!(build(
        root.path(),
        json!({"outputDir":".kuzushi/draft","preserveUserEdits":false}),
        &runtime
    )
    .is_err());
    assert!(runtime.requests().is_empty());
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
}

struct ConcurrentDraftWriter {
    path: PathBuf,
    inner: MockThreatRuntime,
}

impl AgentRuntime for ConcurrentDraftWriter {
    fn query_blocking(
        &self,
        request: AgentQueryRequest,
    ) -> Result<crate::runtime::AgentQueryResponse> {
        fs::create_dir_all(self.path.parent().unwrap())?;
        fs::write(&self.path, "Operator edits created during model work")?;
        self.inner.query_blocking(request)
    }

    fn triage_finding_blocking(
        &self,
        _: crate::runtime::TriageRequest,
    ) -> Result<crate::TriageOutcome> {
        anyhow::bail!("The draft fixture cannot triage")
    }
}

#[test]
fn operator_file_created_during_query_is_not_replaced() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join(".kuzushi/draft/THREAT_MODEL.md");
    let runtime = ConcurrentDraftWriter {
        path: path.clone(),
        inner: MockThreatRuntime::new(sample_document()),
    };
    let error = build(root.path(), json!({"outputDir":".kuzushi/draft"}), &runtime).unwrap_err();
    assert!(error.to_string().contains("Draft preserved"), "{error:#}");
    assert_eq!(runtime.inner.requests().len(), 1);
    assert_eq!(
        fs::read_to_string(path).unwrap(),
        "Operator edits created during model work"
    );
    assert!(!root
        .path()
        .join(".kuzushi/draft/normalized-threat-model.json")
        .exists());
}
