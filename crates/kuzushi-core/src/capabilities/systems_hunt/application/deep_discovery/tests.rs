use super::*;
use crate::allowance::AllowanceBinding;
use crate::runtime::{AgentQueryResponse, TriageRequest};
use crate::{ModuleRegistry, V2Config, WorkspaceTarget};
use std::sync::{Arc, Mutex};

const MODEL: &str = "openai-codex:gpt-5.5";
const ANSWER: &str = r#"{"findings":[{"title":"Owned metadata observation","cwe":["CWE-20"],"severity":"info","filePath":"owned.c","startLine":1,"message":"Owned source fixture metadata; no vulnerability is asserted","evidence":["owned.c:1 - supplied inert metadata"]}]}"#;

struct Fixture {
    root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    config: V2Config,
    registry: ModuleRegistry,
    store: crate::FindingStore,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("owned.c"),
            "// owned_input owned_sink; inert text, never executed.\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let store = crate::FindingStore::open(workspace.findings_db_path()).unwrap();
        Self {
            store,
            workspace: WorkspaceTarget::new(root.path()).unwrap(),
            root,
            config: V2Config {
                model: Some(MODEL.into()),
                ..Default::default()
            },
            registry: ModuleRegistry::with_v2_builtins_without_optional_adapters(),
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
    fn dispatch(&self, input: Value, runtime: &OfflineRuntime) -> Result<Value> {
        let ctx = self.ctx();
        let prepared = self
            .registry
            .prepare_dispatch_input(TOOL, input, &ctx, None)?
            .authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(runtime))
    }
    fn approve(&self, calls: u64) {
        let ctx = self.ctx();
        let prepared = self.registry.prepare_dispatch_input("campaign:approve-allowance",
            json!({"investigationId":"owned-deep-discovery","expectedRevision":0,"model":MODEL,"maxProviderCalls":calls,
                "protectedReviewCalls":1,"reason":"Owned inert metadata discovery; intercepted only"}), &ctx, None)
            .unwrap().authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
            .unwrap();
    }
    fn input(&self) -> Value {
        json!({"cwes":["CWE-20"],"allowanceRef":{"schemaVersion":1,"investigationId":"owned-deep-discovery","revision":1,"workId":"one-discovery"}})
    }
    fn snapshot(&self) -> crate::allowance::AllowanceSnapshot {
        crate::SpendLimiter::open(self.workspace.findings_db_path())
            .unwrap()
            .allowance_snapshot("owned-deep-discovery")
            .unwrap()
    }
}

#[derive(Clone)]
struct OfflineRuntime {
    binding: Option<AllowanceBinding>,
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    text: String,
    cancel_after: Option<Arc<crate::scan::ScanCancellation>>,
    mutate_after: Option<PathBuf>,
    retained_input: Option<PathBuf>,
}

impl OfflineRuntime {
    fn new(text: &str) -> Self {
        Self {
            binding: None,
            requests: Default::default(),
            text: text.into(),
            cancel_after: None,
            mutate_after: None,
            retained_input: None,
        }
    }
}

impl AgentRuntime for OfflineRuntime {
    fn allowance_binding(&self) -> Option<&AllowanceBinding> {
        self.binding.as_ref()
    }
    fn with_allowance_binding(
        &self,
        binding: AllowanceBinding,
    ) -> Result<Box<dyn AgentRuntime + '_>> {
        Ok(Box::new(Self {
            binding: Some(binding),
            ..self.clone()
        }))
    }
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        if let Some(path) = &self.retained_input {
            let retained: Value = serde_json::from_slice(&fs::read(path)?)?;
            anyhow::ensure!(
                retained["data"]["frozenInput"] == serde_json::from_str::<Value>(&request.prompt)?
            );
            anyhow::ensure!(retained["data"]["systemPrompt"] == request.system_prompt);
            anyhow::ensure!(retained["data"]["model"] == request.model);
            anyhow::ensure!(retained["data"]["runtimeRequest"] == serde_json::to_value(&request)?);
        }
        let binding = self
            .binding
            .as_ref()
            .context("An unbudgeted discovery reached the transport")?;
        let reserved = binding.reserve(&request.model)?;
        self.requests.lock().unwrap().push(request);
        if self.text == "owned transport failure" {
            anyhow::bail!("owned transport failure");
        }
        let response = AgentQueryResponse {
            text: self.text.clone(),
            ..Default::default()
        };
        binding.settle(reserved, response.checked_cost_report()?)?;
        if let Some(path) = &self.mutate_after {
            fs::write(path, "// owned source changed; still inert text\n")?;
        }
        if let Some(canceled) = &self.cancel_after {
            canceled.cancel();
        }
        Ok(response)
    }
    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<crate::TriageOutcome> {
        anyhow::bail!("No triage belongs to these discovery fixtures")
    }
}

#[test]
fn shared_discovery_is_labs_scan_with_required_ledger_and_discovery_allowance() {
    let f = Fixture::new();
    let tool = f.registry.resolve_tool(TOOL).unwrap();
    assert_eq!(
        tool.discovery_maturity,
        Some(crate::modules::ModuleMaturity::Labs)
    );
    assert_eq!(tool.phase, crate::modules::ToolPhase::Scan);
    assert!(tool.phase_result);
    assert!(
        !tool
            .options
            .iter()
            .find(|option| option.name == "maxSourceBytes")
            .unwrap()
            .advanced
    );
    assert!(
        tool.options
            .iter()
            .find(|option| option.name == "cwes")
            .unwrap()
            .required
    );
    assert_eq!(
        tool.allowance_category,
        Some(kuzushi_descriptor::AllowanceCategory::Discovery)
    );
    assert_eq!(
        tool.finding_store_requirement,
        crate::modules::FindingStoreRequirement::Required
    );
    let runtime = OfflineRuntime::new(ANSWER);
    assert!(f
        .dispatch(json!({"cwes":["CWE-20"]}), &runtime)
        .unwrap_err()
        .to_string()
        .contains("allowance"));
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn discovery_consumes_explicit_classes_once_and_publishes_to_the_ledger() {
    let f = Fixture::new();
    f.approve(2);
    let runtime = OfflineRuntime::new(ANSWER);
    let result = f.dispatch(f.input(), &runtime).unwrap();
    assert_eq!(result["data"]["count"], 1);
    assert_eq!(result["status"], "completed");
    assert_eq!(f.store.list_findings(10).unwrap().len(), 1);
    assert_eq!(result["data"]["findings"][0]["tool"], "deep-semantic-hunt");
    let artifact = result["data"]["artifacts"][0].as_str().unwrap();
    let saved: Value =
        serde_json::from_slice(&fs::read(f.root.path().join(artifact)).unwrap()).unwrap();
    assert_eq!(saved["title"], "Owned metadata observation");
    assert_eq!(result["data"]["frozenInput"]["cwes"][0]["id"], "CWE-20");
    assert!(result["data"].get("costUsd").is_none());
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("Unverified model observations"));
    assert_eq!(f.snapshot().committed_calls, 1);
    assert_eq!(f.snapshot().protected_review_remaining(), 1);
}

#[test]
fn one_fresh_tool_free_request_preserves_model_reasoning_aliases_and_exact_input() {
    let f = Fixture::new();
    f.approve(2);
    let runtime = OfflineRuntime::new(ANSWER);
    let mut input = f.input();
    input["max_files"] = json!(1);
    input["head_bytes"] = json!(24);
    input["max_source_bytes"] = json!(24);
    input["reasoningEffort"] = json!("medium");
    input["threatModelRef"] = Value::Null;
    input["scanContextRef"] = Value::Null;
    let result = f.dispatch(input, &runtime).unwrap();
    assert_eq!(result["status"], "partial");
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let q = &requests[0];
    assert_eq!(q.model, MODEL);
    assert_eq!(q.thinking_level.as_deref(), Some("medium"));
    assert!(q.structured_output.is_none());
    assert!(q.tool_policy.tools.is_empty() && !q.tool_policy.mcps);
    assert!(q.tool_policy.mcp_read_roots.is_empty() && q.tool_policy.mcps_attached.is_empty());
    assert_eq!(q.max_output_tokens, Some(4096));
    assert_eq!(q.runtime_options.as_ref().unwrap().max_model_turns, Some(1));
    assert_eq!(
        result["data"]["frozenInput"],
        serde_json::from_str::<Value>(&q.prompt).unwrap()
    );
    assert_eq!(result["data"]["inspection"]["maxSourceFiles"], 1);
    assert_eq!(result["data"]["inspection"]["maxFileBytes"], 24);
    assert_eq!(result["data"]["inputDocument"]["schemaVersion"], 1);
    let retained = result["data"]["inputDocument"]["text"].as_str().unwrap();
    assert!(retained.contains(&q.system_prompt));
    assert!(retained.contains("Reasoning supplied: medium"));
    let supplied = result["data"]["frozenInput"]["sources"][0]["text"]
        .as_str()
        .unwrap();
    assert!(retained.contains(supplied));
    assert!(!result["output"]
        .as_str()
        .unwrap()
        .contains("FROZEN MODEL INPUT"));
    assert!(!result["output"]
        .as_str()
        .unwrap()
        .contains(&q.system_prompt));
}

#[test]
fn missing_malformed_duplicate_or_excessive_classes_never_start_implicit_selection() {
    let f = Fixture::new();
    f.approve(2);
    let runtime = OfflineRuntime::new(ANSWER);
    for classes in [
        Value::Null,
        json!([]),
        json!(["CWE-020"]),
        json!(["CWE-20", "CWE-20"]),
        json!([{}]),
    ] {
        let mut input = f.input();
        input["cwes"] = classes;
        assert!(f.dispatch(input, &runtime).is_err());
    }
    let mut input = f.input();
    input["cwes"] = json!(["CWE-20", "CWE-21"]);
    input["maxCweClasses"] = json!(1);
    assert!(f.dispatch(input, &runtime).is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert_eq!(f.snapshot().committed_calls, 0);
}

#[test]
fn unsupported_stored_or_explicit_stage_controls_are_refused_before_query() {
    let f = Fixture::new();
    f.approve(2);
    let runtime = OfflineRuntime::new(ANSWER);
    for (key, value) in [
        ("whiteboxStatic", json!(false)),
        ("maxSurfaces", json!(50)),
        ("context", json!({})),
        ("SYSTEMS_DEEP_CWE_PROMPT", json!("unused")),
    ] {
        let mut input = f.input();
        input[key] = value;
        assert!(f.dispatch(input, &runtime).is_err());
    }
    use crate::options::{OptionScope, OptionTarget, ToolOptionStore};
    let ctx = f.ctx();
    let mut stored = ToolOptionStore::new();
    stored.set_value(
        OptionScope::Workspace,
        OptionTarget::Tool(TOOL.into()),
        "max_surfaces",
        json!(50),
    );
    let prepared = f
        .registry
        .prepare_dispatch_input(TOOL, f.input(), &ctx, Some(&stored));
    if let Ok(prepared) = prepared {
        assert!(f
            .registry
            .dispatch_prepared_input_with_runtime(
                prepared.authorize_explicit_headless(),
                &ctx,
                Some(&runtime)
            )
            .is_err());
    }
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn malformed_output_invalid_citations_and_wrong_classes_are_charged_without_repair_or_partial_writes(
) {
    let f = Fixture::new();
    f.approve(16);
    let mut invalid = vec![
        "not json".into(),
        json!({"findings":[{}]}).to_string(),
        json!({}).to_string(),
    ];
    let answer: Value = serde_json::from_str(ANSWER).unwrap();
    for (key, value) in [
        ("filePath", json!("../owned.c")),
        ("filePath", json!("missing.c")),
        ("startLine", json!(99)),
        ("cwe", json!(["CWE-21"])),
        ("evidence", json!([])),
        ("evidence", json!(["missing.c:1 - invented"])),
        ("severity", json!("verified")),
        ("patch", json!("inert forbidden field")),
    ] {
        let mut response = answer.clone();
        response["findings"][0][key] = value;
        invalid.push(response.to_string());
    }
    for (number, text) in invalid.iter().enumerate() {
        let runtime = OfflineRuntime::new(text);
        let result = f.dispatch(f.input(), &runtime).unwrap();
        assert_eq!(result["status"], "failed", "{text}");
        assert!(result["data"]["rawAgentText"].is_string());
        assert_eq!(runtime.requests.lock().unwrap().len(), 1);
        assert_eq!(f.snapshot().committed_calls, number as u32 + 1);
        assert!(f.store.list_findings(10).unwrap().is_empty());
        assert!(!f.root.path().join(".kuzushi/systems-hunt").exists());
    }
}

#[test]
fn excessive_output_never_silently_truncates_a_finding_array() {
    let f = Fixture::new();
    f.approve(2);
    let mut answer: Value = serde_json::from_str(ANSWER).unwrap();
    answer["findings"] = json!([answer["findings"][0], answer["findings"][0]]);
    let runtime = OfflineRuntime::new(&answer.to_string());
    let mut input = f.input();
    input["maxFindings"] = json!(1);
    let result = f.dispatch(input, &runtime).unwrap();
    assert_eq!(result["status"], "failed");
    assert!(f.store.list_findings(10).unwrap().is_empty());
    assert_eq!(f.snapshot().committed_calls, 1);
}

#[test]
fn transport_failure_preserves_unresolved_reservation_without_an_automatic_retry() {
    let f = Fixture::new();
    f.approve(2);
    let runtime = OfflineRuntime::new("owned transport failure");
    assert!(f.dispatch(f.input(), &runtime).is_err());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(f.snapshot().committed_calls, 1);
    assert_eq!(f.snapshot().unresolved_calls, 1);
    assert!(f.store.list_findings(10).unwrap().is_empty());
}

#[test]
fn transport_failure_retains_the_exact_prepared_input_before_runtime_entry() {
    let f = Fixture::new();
    f.approve(2);
    let trace = crate::run_artifacts::TraceHandle::jsonl(f.root.path(), "retained-transport");
    let mut ctx = f.ctx();
    ctx.trace = Some(&trace);
    let mut runtime = OfflineRuntime::new("owned transport failure");
    runtime.retained_input = Some(crate::run_artifacts::run_artifact_path(
        f.root.path(),
        "retained-transport",
        "prepared-model-input.json",
    ));
    let prepared = f
        .registry
        .prepare_dispatch_input(TOOL, f.input(), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    assert!(f
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
        .is_err());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(f.snapshot().unresolved_calls, 1);
    let retained: Value =
        serde_json::from_slice(&fs::read(runtime.retained_input.unwrap()).unwrap()).unwrap();
    assert!(retained["data"]["inputDocument"]["text"]
        .as_str()
        .unwrap()
        .contains("Provider delivery is not established"));
    assert!(f.store.list_findings(10).unwrap().is_empty());
}

#[test]
fn refused_input_retention_starts_no_runtime_request_or_reservation() {
    let f = Fixture::new();
    f.approve(2);
    let trace = crate::run_artifacts::TraceHandle::jsonl(f.root.path(), "input-refused");
    let mut ctx = f.ctx();
    ctx.trace = Some(&trace);
    let path = crate::run_artifacts::run_artifact_path(
        f.root.path(),
        "input-refused",
        "prepared-model-input.json",
    );
    fs::create_dir(&path).unwrap();
    let runtime = OfflineRuntime::new(ANSWER);
    let prepared = f
        .registry
        .prepare_dispatch_input(TOOL, f.input(), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    assert!(f
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
        .is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert_eq!(f.snapshot().committed_calls, 0);
}

#[test]
fn cancellation_after_request_retains_input_and_charging_without_findings() {
    let f = Fixture::new();
    f.approve(2);
    let cancellation = Arc::new(crate::scan::ScanCancellation::default());
    let mut runtime = OfflineRuntime::new(ANSWER);
    runtime.cancel_after = Some(cancellation.clone());
    let mut ctx = f.ctx();
    ctx.cancellation = Some(cancellation.as_ref());
    let prepared = f
        .registry
        .prepare_dispatch_input(TOOL, f.input(), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let result = f
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
        .unwrap();
    assert_eq!(result["status"], "failed");
    assert!(result["data"]["frozenInput"].is_object());
    assert!(f.store.list_findings(10).unwrap().is_empty());
    assert_eq!(f.snapshot().committed_calls, 1);
}

#[test]
fn drift_keeps_original_source_identity_and_marks_the_result_partial() {
    let f = Fixture::new();
    f.approve(2);
    let mut runtime = OfflineRuntime::new(ANSWER);
    runtime.mutate_after = Some(f.root.path().join("owned.c"));
    let result = f.dispatch(f.input(), &runtime).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["sourceCheckCurrent"], false);
    assert!(result["data"]["treeHash"].is_string());
    assert_eq!(result["data"]["publicationStatus"], "withheld");
    assert_eq!(
        result["data"]["unpublishedCandidates"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(result["data"]["findings"].as_array().unwrap().is_empty());
    assert!(f.store.list_findings(10).unwrap().is_empty());
    assert_eq!(f.snapshot().committed_calls, 1);
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn exhausted_allowance_cannot_start_another_discovery_or_borrow_protected_review() {
    let f = Fixture::new();
    f.approve(2);
    let runtime = OfflineRuntime::new(ANSWER);
    f.dispatch(f.input(), &runtime).unwrap();
    assert!(f.dispatch(f.input(), &runtime).is_err());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(f.snapshot().protected_review_remaining(), 1);
}

fn scoped_fixture(f: &Fixture) -> crate::workspace::ScanScopeRef {
    use crate::workspace::{
        accept_scan_scope_proposal, create_scan_scope_proposal, ProposedScanScope, ScanScopeDraft,
        ScanScopeRef, ScopeCoverageApproval,
    };
    fs::remove_file(f.root.path().join("owned.c")).unwrap();
    for directory in ["app", "other", "shared"] {
        fs::create_dir_all(f.root.path().join(directory)).unwrap();
        fs::write(
            f.root.path().join(directory).join("owned.c"),
            format!("// owned_{directory}_metadata\n"),
        )
        .unwrap();
    }
    let scope = |id: &str, path: &str| ProposedScanScope {
        id: id.into(),
        name: id.into(),
        paths: vec![path.into()],
        rationale: "Owned source-only scope fixture".into(),
        shared_dependencies: Vec::new(),
        open_questions: Vec::new(),
    };
    let draft = ScanScopeDraft {
        schema_version: 1,
        scopes: vec![
            scope("app", "app"),
            scope("other", "other"),
            scope("integration", "shared"),
        ],
        shared_scope: Some(scope("shared", "shared")),
        shared_discovery: false,
        exclusions: Vec::new(),
    };
    let proposal = create_scan_scope_proposal(&f.ctx(), Some(draft)).unwrap();
    let accepted = accept_scan_scope_proposal(
        &f.ctx(),
        &proposal.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            exclusions: false,
            overlapping_discovery: false,
        },
    )
    .unwrap();
    ScanScopeRef {
        proposal: accepted.reference,
        scope_id: "app".into(),
    }
}

fn answer_for(path: &str) -> String {
    let mut answer: Value = serde_json::from_str(ANSWER).unwrap();
    answer["findings"][0]["filePath"] = json!(path);
    answer["findings"][0]["evidence"] = json!([format!("{path}:1 - supplied owned metadata")]);
    answer.to_string()
}

#[test]
fn accepted_scope_supplies_exact_discovery_and_shared_context_without_other_source() {
    let f = Fixture::new();
    let reference = scoped_fixture(&f);
    f.approve(2);
    let runtime = OfflineRuntime::new(&answer_for("app/owned.c"));
    let mut input = f.input();
    input["scanScopeRef"] = json!(reference);
    input["scanContextRef"] = Value::Null;
    input["threatModelRef"] = Value::Null;
    let result = f.dispatch(input, &runtime).unwrap();
    assert_eq!(result["data"]["count"], 1);
    let prompt = &runtime.requests.lock().unwrap()[0].prompt;
    assert!(prompt.contains("owned_app_metadata") && prompt.contains("owned_shared_metadata"));
    assert!(!prompt.contains("owned_other_metadata"));
    let frozen = &result["data"]["frozenInput"];
    let sources = frozen["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0]["role"], "discovery");
    assert_eq!(sources[1]["role"], "context only");
    assert_eq!(frozen["scope"]["reference"], json!(reference));
    assert_eq!(f.snapshot().committed_calls, 1);
}

#[test]
fn shared_context_and_outside_paths_cannot_turn_into_scoped_findings() {
    let f = Fixture::new();
    let reference = scoped_fixture(&f);
    f.approve(3);
    for path in ["shared/owned.c", "other/owned.c"] {
        let runtime = OfflineRuntime::new(&answer_for(path));
        let mut input = f.input();
        input["scanScopeRef"] = json!(reference);
        let result = f.dispatch(input, &runtime).unwrap();
        assert_eq!(result["status"], "failed");
        assert!(f.store.list_findings(10).unwrap().is_empty());
        assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    }
}

#[test]
fn changed_scope_source_invalid_reference_and_target_rebinding_fail_before_model_work() {
    let f = Fixture::new();
    let reference = scoped_fixture(&f);
    f.approve(2);
    let runtime = OfflineRuntime::new(ANSWER);
    let mut input = f.input();
    input["scanScopeRef"] = json!(reference);
    let other = tempfile::tempdir().unwrap();
    input["target"] = json!(other.path());
    assert!(f.dispatch(input.clone(), &runtime).is_err());
    input.as_object_mut().unwrap().remove("target");
    let mut missing = input.clone();
    missing["scanScopeRef"]["scopeId"] = json!("missing");
    assert!(f.dispatch(missing, &runtime).is_err());
    fs::write(
        f.root.path().join("app/owned.c"),
        "// changed owned source\n",
    )
    .unwrap();
    assert!(f.dispatch(input, &runtime).is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert_eq!(f.snapshot().committed_calls, 0);
}

#[test]
fn empty_non_systems_source_and_precancellation_do_not_consume_capacity() {
    let f = Fixture::new();
    f.approve(2);
    let runtime = OfflineRuntime::new(ANSWER);
    fs::rename(
        f.root.path().join("owned.c"),
        f.root.path().join("owned.txt"),
    )
    .unwrap();
    assert!(f.dispatch(f.input(), &runtime).is_err());
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    let mut ctx = f.ctx();
    ctx.cancellation = Some(&cancellation);
    let prepared = f
        .registry
        .prepare_dispatch_input(TOOL, f.input(), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    assert!(f
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
        .is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert_eq!(f.snapshot().committed_calls, 0);
}

fn project_context(root: &Path, note: &str) {
    let tree = crate::incremental_index::current_workspace_tree_hash(root).unwrap();
    let path = crate::context::context_snapshot_path(root);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        path,
        serde_json::to_vec(&json!({"target":root,"provenance":{"treeHash":tree},
        "enrichedContext":{"architecturalNotes":[{"note":note}]}}))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn frozen_supporting_context_is_consumed_after_active_context_changes() {
    let f = Fixture::new();
    f.approve(2);
    project_context(f.root.path(), "Owned accepted architecture A");
    let mut input = f.input();
    crate::scan::freeze_scan_context(f.root.path(), &mut input).unwrap();
    let reference = input["scanContextRef"].clone();
    project_context(f.root.path(), "Owned later architecture B");
    let path = crate::context::context_snapshot_path(f.root.path());
    let before = fs::read(&path).unwrap();
    let runtime = OfflineRuntime::new(ANSWER);
    let result = f.dispatch(input, &runtime).unwrap();
    let requests = runtime.requests.lock().unwrap();
    assert!(requests[0].prompt.contains("Owned accepted architecture A"));
    assert!(!requests[0].prompt.contains("Owned later architecture B"));
    assert_eq!(
        result["data"]["frozenInput"]["supportingContext"]["selectedScanContextRef"],
        reference
    );
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn publication_failure_keeps_model_input_and_consumption_in_a_failed_result() {
    let f = Fixture::new();
    f.approve(2);
    let mut runtime = OfflineRuntime::new(ANSWER);
    runtime.mutate_after = Some(f.root.path().join(".kuzushi/systems-hunt"));
    let result = f.dispatch(f.input(), &runtime).unwrap();
    assert_eq!(result["status"], "failed");
    assert!(result["data"]["rawAgentText"]
        .as_str()
        .unwrap()
        .contains("Owned metadata"));
    assert!(f.store.list_findings(10).unwrap().is_empty());
    assert_eq!(f.snapshot().committed_calls, 1);
}

#[test]
fn missing_model_never_uses_a_runtime_default() {
    let mut f = Fixture::new();
    f.config.model = None;
    f.approve(2);
    let runtime = OfflineRuntime::new(ANSWER);
    assert!(f.dispatch(f.input(), &runtime).is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert_eq!(f.snapshot().committed_calls, 0);
}

#[test]
fn prompt_source_clipping_is_disclosed_without_claiming_complete_coverage() {
    let f = Fixture::new();
    f.approve(2);
    fs::write(
        f.root.path().join("owned.c"),
        format!("// owned metadata {}\n", "x".repeat(250 * 1024)),
    )
    .unwrap();
    let mut input = f.input();
    input["headBytes"] = json!(256 * 1024);
    input["maxSourceBytes"] = json!(512 * 1024);
    let runtime = OfflineRuntime::new(ANSWER);
    let result = f.dispatch(input, &runtime).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(
        result["data"]["inspection"]["promptTruncatedSourceFiles"],
        1
    );
    assert_eq!(
        result["data"]["frozenInput"]["completeRepositoryCoverage"],
        false
    );
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn repeated_discovery_preserves_each_runs_inert_artifact() {
    let f = Fixture::new();
    f.approve(3);
    let first = f.dispatch(f.input(), &OfflineRuntime::new(ANSWER)).unwrap();
    let path = first["data"]["artifacts"][0].as_str().unwrap();
    let bytes = fs::read(f.root.path().join(path)).unwrap();
    let mut changed: Value = serde_json::from_str(ANSWER).unwrap();
    changed["findings"][0]["analysisPath"] = json!(["Owned second-run metadata"]);
    let second = f
        .dispatch(f.input(), &OfflineRuntime::new(&changed.to_string()))
        .unwrap();
    assert_ne!(
        first["data"]["artifacts"][0],
        second["data"]["artifacts"][0]
    );
    assert_eq!(fs::read(f.root.path().join(path)).unwrap(), bytes);
    assert_eq!(f.snapshot().committed_calls, 2);
}

#[test]
fn missing_ledger_and_target_rebinding_refuse_direct_execution_before_query() {
    let f = Fixture::new();
    let runtime = OfflineRuntime::new(ANSWER);
    let mut ctx = f.ctx();
    ctx.findings_store = None;
    assert!(execute_deep_discovery(&json!({"cwes":["CWE-20"]}), &ctx, Some(&runtime)).is_err());
    let other = tempfile::tempdir().unwrap();
    assert!(execute_deep_discovery(
        &json!({"cwes":["CWE-20"],"target":other.path()}),
        &f.ctx(),
        Some(&runtime)
    )
    .is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
}

fn commit_context(root: &Path, marker: &str) -> crate::capabilities::threat_model::ThreatModelRef {
    use crate::capabilities::threat_model::{
        commit_threat_model_revision, ScopeRef, ThreatModelCommit, ThreatModelRevisionSource,
    };
    commit_threat_model_revision(root,&json!({"version":"1","methodology":"stride","title":marker,
        "dfd":{"nodes":[{"id":"app","type":"process","name":marker,"description":marker,"trustZone":"internal"}],"flows":[],"trustBoundaries":[]},
        "threats":[],"summary":{}}),ThreatModelCommit {model_id:None,new_model:true,label:marker.into(),
        scope:ScopeRef::legacy_root(root,&format!("sha256:{}","1".repeat(64))),methodology:"stride".into(),
        source:ThreatModelRevisionSource::Build,source_revision_id:None,run_id:None,activate:Some(true),actor:"owned-context-test".into()}).unwrap().model_ref
}

#[test]
fn explicit_threat_revision_is_consumed_without_changing_active_context() {
    let f = Fixture::new();
    f.approve(2);
    let first = commit_context(f.root.path(), "Owned accepted threat A");
    let second = commit_context(f.root.path(), "Owned active threat B");
    let runtime = OfflineRuntime::new(ANSWER);
    let mut input = f.input();
    input["threatModelRef"] = json!(first);
    let result = f.dispatch(input, &runtime).unwrap();
    let requests = runtime.requests.lock().unwrap();
    assert!(requests[0].prompt.contains("Owned accepted threat A"));
    assert!(!requests[0].prompt.contains("Owned active threat B"));
    assert_eq!(
        result["data"]["frozenInput"]["supportingContext"]["selectedThreatModelRef"],
        json!(first)
    );
    assert_eq!(
        crate::capabilities::threat_model::load_active_threat_model(f.root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        second
    );
}

#[test]
fn stale_active_supporting_context_is_refused_before_model_work() {
    let f = Fixture::new();
    f.approve(2);
    project_context(f.root.path(), "Owned stale architecture");
    fs::write(f.root.path().join("owned.c"), "// owned changed source\n").unwrap();
    let runtime = OfflineRuntime::new(ANSWER);
    assert!(f.dispatch(f.input(), &runtime).is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert_eq!(f.snapshot().committed_calls, 0);
}

#[test]
fn reviewed_proposal_classes_feed_one_separately_invoked_discovery_request() {
    let f = Fixture::new();
    f.approve(3);
    let selector = OfflineRuntime::new(
        r#"{"cwes":[{"id":"CWE-20","name":"Owned metadata class","reason":"Owned supplied source metadata"}]}"#,
    );
    let ctx = f.ctx();
    let prepared = f.registry.prepare_dispatch_input("systems-hunt:deep-semantic-cwe-select",
        json!({"allowanceRef":{"schemaVersion":1,"investigationId":"owned-deep-discovery","revision":1,"workId":"explicit-class-proposal"}}),
        &ctx, None).unwrap().authorize_explicit_headless();
    let proposal = f
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&selector))
        .unwrap();
    assert_eq!(proposal["data"]["accepted"], false);
    let mut selected = f.input();
    selected["cwes"] = proposal["data"]["cwes"].clone();
    let discovery = OfflineRuntime::new(ANSWER);
    let result = f.dispatch(selected, &discovery).unwrap();
    let requests = discovery.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let supplied: Value = serde_json::from_str(&requests[0].prompt).unwrap();
    assert_eq!(supplied["cwes"], proposal["data"]["cwes"]);
    assert_eq!(selector.requests.lock().unwrap().len(), 1);
    assert_eq!(result["data"]["treeHash"], proposal["data"]["treeHash"]);
    assert_eq!(f.store.list_findings(10).unwrap().len(), 1);
    assert_eq!(f.snapshot().committed_calls, 2);
    assert_eq!(f.snapshot().protected_review_remaining(), 1);
}

#[test]
fn review_receives_unscored_model_claim_and_grounded_source_rows() {
    let f = Fixture::new();
    f.approve(2);
    let result = f.dispatch(f.input(), &OfflineRuntime::new(ANSWER)).unwrap();
    let findings = f.store.list_findings(10).unwrap();
    let finding = &findings[0];
    assert_eq!(finding.evidence.len(), 2);
    assert!(finding.evidence[0].is_unscored_model_claim());
    assert!(finding.evidence[0]
        .rationale
        .contains("no vulnerability is asserted"));
    let source = &finding.evidence[1];
    assert!(source.is_unscored_source_citation());
    assert_eq!(source.file_path, "owned.c");
    assert_eq!(source.line, 1);
    assert_eq!(
        source.snippet,
        "// owned_input owned_sink; inert text, never executed."
    );
    assert!(finding
        .evidence
        .iter()
        .all(|row| row.confidence == 0 && row.has_unscored_confidence()));
    assert_eq!(
        crate::ProofConfidence::classify(finding),
        crate::ProofConfidence::Unverified
    );
    assert_eq!(
        result["data"]["findings"][0]["evidence"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn literal_source_paths_are_preserved_through_normalization_and_evidence_projection() {
    let f = Fixture::new();
    f.approve(2);
    let path = " owned [source].c";
    fs::rename(f.root.path().join("owned.c"), f.root.path().join(path)).unwrap();
    let result = f
        .dispatch(f.input(), &OfflineRuntime::new(&answer_for(path)))
        .unwrap();
    assert_eq!(result["data"]["findings"][0]["file_path"], path);
    let finding = &f.store.list_findings(10).unwrap()[0];
    assert_eq!(finding.file_path, path);
    assert_eq!(finding.evidence[1].file_path, path);
    assert!(finding.evidence[1].is_unscored_source_citation());
}

#[test]
fn source_capture_budget_withholds_candidates_without_extra_requests_or_ledger_import() {
    let f = Fixture::new();
    let runtime = OfflineRuntime::new(ANSWER);
    f.approve(2);
    let mut input = f.input();
    input["maxSnapshotBytes"] = json!(1);
    let result = f.dispatch(input, &runtime).unwrap();
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["publicationStatus"], "withheld");
    assert_eq!(result["data"]["partialLedgerPossible"], false);
    assert_eq!(result["data"]["findings"], json!([]));
    assert!(!result["data"]["unpublishedCandidates"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(f.store.list_findings(10).unwrap().is_empty());
    assert_eq!(f.snapshot().committed_calls, 1);
    assert_eq!(f.snapshot().protected_review_remaining(), 1);
    let output = result["output"].as_str().unwrap();
    assert!(output.contains("Inspect unpublished candidates in Replay"));
    assert!(!output.contains(render::LEDGER_GUIDANCE));
    assert!(output.contains("HISTORICAL CANDIDATE OUTPUT"));
}

#[test]
fn publication_binds_the_observation_to_the_original_workspace_snapshot() {
    let f = Fixture::new();
    f.approve(2);
    let result = f.dispatch(f.input(), &OfflineRuntime::new(ANSWER)).unwrap();
    assert_eq!(result["data"]["publicationStatus"], "published");
    assert!(result["output"]
        .as_str()
        .unwrap()
        .starts_with(render::LEDGER_GUIDANCE));
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("capture limit 16 MiB"));
    assert_eq!(result["data"]["publicationSource"]["capturedFiles"], 1);
    assert!(
        result["data"]["publicationSource"]["capturedBytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    let stored = f.store.list_findings(10).unwrap();
    assert_eq!(stored.len(), 1);
    let observed = f
        .store
        .observed_snapshot_at(stored[0].identity_id.as_deref().unwrap(), u64::MAX)
        .unwrap()
        .unwrap();
    assert_eq!(
        observed.snapshot_hash,
        result["data"]["snapshotHash"].as_str().unwrap()
    );
}

#[test]
fn foreign_ledger_is_refused_before_any_discovery_request() {
    let f = Fixture::new();
    let foreign = Fixture::new();
    f.approve(2);
    foreign.approve(2);
    let mut ctx = f.ctx();
    ctx.findings_store = Some(&foreign.store);
    let runtime = OfflineRuntime::new(ANSWER);
    let prepared = f
        .registry
        .prepare_dispatch_input(TOOL, f.input(), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let error = f
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
        .unwrap_err();
    assert!(format!("{error:#}").contains("findings ledger does not belong"));
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert_eq!(f.snapshot().committed_calls, 0);
    assert_eq!(foreign.snapshot().committed_calls, 0);
}

#[test]
fn empty_later_pass_preserves_prior_observations_and_gives_coverage_guidance() {
    use crate::findings::{ReviewDecision, ReviewDecisionVerdict, TriageAuthor};
    let f = Fixture::new();
    f.approve(3);
    f.dispatch(f.input(), &OfflineRuntime::new(ANSWER)).unwrap();
    let finding = f.store.list_findings(10).unwrap()[0].id.unwrap();
    f.store
        .append_user_review_decision(
            finding,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::RejectedFalsePositive,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "Owned metadata; no vulnerability is asserted".into(),
                dismiss_reason: None,
                actor: None,
            },
        )
        .unwrap();
    let before = f.store.list_findings(10).unwrap();
    let decisions = serde_json::to_value(f.store.list_all_review_decisions().unwrap()).unwrap();
    let mut input = f.input();
    input["allowanceRef"]["workId"] = json!("explicit-empty-pass");
    let result = f
        .dispatch(input, &OfflineRuntime::new(r#"{"findings":[]}"#))
        .unwrap();
    assert_eq!(result["data"]["count"], 0);
    assert!(result["output"]
        .as_str()
        .unwrap()
        .starts_with("No new candidates in this pass"));
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("Previous findings and decisions remain"));
    assert_eq!(f.store.list_findings(10).unwrap(), before);
    assert_eq!(
        serde_json::to_value(f.store.list_all_review_decisions().unwrap()).unwrap(),
        decisions
    );
    assert_eq!(f.snapshot().committed_calls, 2);
}
