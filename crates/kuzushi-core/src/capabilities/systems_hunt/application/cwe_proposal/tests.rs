use super::*;
use crate::allowance::AllowanceBinding;
use crate::runtime::{AgentQueryResponse, TriageRequest};
use crate::{ModuleRegistry, V2Config, WorkspaceTarget};
use std::sync::{Arc, Mutex};

const MODEL: &str = "openai-codex:gpt-5.5";
const ANSWER: &str = r#"{"cwes":[{"id":"CWE-20","name":"Owned source metadata","reason":"owned.c contains owned_input; no vulnerability is asserted"}]}"#;

struct Fixture {
    root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    config: V2Config,
    registry: ModuleRegistry,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("owned.c"),
            "// owned_input owned_sink; inert text, never executed.\n",
        )
        .unwrap();
        Self {
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
            findings_store: None,
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
            json!({"investigationId":"owned-cwe","expectedRevision":0,"model":MODEL,"maxProviderCalls":calls,
                "protectedReviewCalls":1,"reason":"Owned inert metadata proposals; intercepted only"}), &ctx, None)
            .unwrap().authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
            .unwrap();
    }
    fn input(&self) -> Value {
        json!({"allowanceRef":{"schemaVersion":1,"investigationId":"owned-cwe","revision":1,"workId":"one-proposal"}})
    }
    fn snapshot(&self) -> crate::allowance::AllowanceSnapshot {
        crate::SpendLimiter::open(self.workspace.findings_db_path())
            .unwrap()
            .allowance_snapshot("owned-cwe")
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
}

impl OfflineRuntime {
    fn new(text: &str) -> Self {
        Self {
            binding: None,
            requests: Default::default(),
            text: text.into(),
            cancel_after: None,
            mutate_after: None,
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
        let binding = self
            .binding
            .as_ref()
            .context("An unbudgeted proposal reached the transport")?;
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
        anyhow::bail!("No triage belongs to these proposals")
    }
}

#[test]
fn shared_selector_declares_auxiliary_labs_scope_without_findings_or_phase_completion() {
    let f = Fixture::new();
    let tool = f.registry.resolve_tool(TOOL).unwrap();
    assert!(tool.hidden && !tool.phase_result);
    assert_eq!(tool.phase, crate::modules::ToolPhase::Map);
    assert_eq!(
        tool.allowance_category,
        Some(kuzushi_descriptor::AllowanceCategory::Scope)
    );
    assert_eq!(
        tool.discovery_maturity,
        Some(crate::modules::ModuleMaturity::Labs)
    );
    assert_eq!(
        tool.finding_store_requirement,
        crate::modules::FindingStoreRequirement::Optional
    );
    let runtime = OfflineRuntime::new(ANSWER);
    assert!(f
        .dispatch(json!({}), &runtime)
        .unwrap_err()
        .to_string()
        .contains("allowance"));
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn one_scope_request_honors_aliases_retains_inputs_and_protects_review() {
    let f = Fixture::new();
    f.approve(2);
    fs::write(
        f.root.path().join("second.c"),
        "// excluded_by_file_limit\n",
    )
    .unwrap();
    let runtime = OfflineRuntime::new(ANSWER);
    let mut input = f.input();
    input["max_files"] = json!(1);
    input["head_bytes"] = json!(24);
    input["max_source_bytes"] = json!(24);
    let result = f.dispatch(input, &runtime).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["cwes"][0]["id"], "CWE-20");
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    let supplied: Value = serde_json::from_str(&request.prompt).unwrap();
    assert_eq!(request.model, MODEL);
    assert!(request.thinking_level.is_none());
    assert!(request.tool_policy.tools.is_empty() && !request.tool_policy.mcps);
    assert!(request.structured_output.is_none());
    assert_eq!(
        request.runtime_options.as_ref().unwrap().max_model_turns,
        Some(1)
    );
    assert_eq!(request.max_output_tokens, Some(4096));
    assert_eq!(result["data"]["frozenInput"], supplied);
    assert_eq!(supplied["sources"].as_array().unwrap().len(), 1);
    assert!(supplied["sources"][0]["text"].as_str().unwrap().len() <= 24);
    assert!(!request.prompt.contains("excluded_by_file_limit"));
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("explicitly absent"));
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("FROZEN MODEL INPUT"));
    assert_eq!(result["data"]["costUsdExact"], false);
    assert_eq!(result["data"]["sourceCheckCurrent"], true);
    drop(requests);
    let snapshot = f.snapshot();
    assert_eq!(snapshot.committed_calls, 1);
    assert_eq!(snapshot.protected_review_remaining(), 1);
    assert!(f
        .dispatch(f.input(), &runtime)
        .unwrap_err()
        .to_string()
        .contains("allowance exhausted"));
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert!(!f.root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn malformed_excessive_or_duplicate_output_is_charged_once_without_repair() {
    for text in [
        "not json",
        "{\"cwes\":[{}]}",
        r#"{"cwes":[{"id":"invalid","name":"Name","reason":"Reason"}]}"#,
        r#"{"cwes":[{"id":"CWE-+20","name":"Name","reason":"Reason"}]}"#,
        r#"{"cwes":[{"id":"CWE-020","name":"Name","reason":"Reason"}]}"#,
        r#"{"cwes":[{"id":"CWE-20","name":"Name","reason":"Reason","extra":true}]}"#,
        r#"{"cwes":[{"id":"CWE-20","name":"Name","reason":"Reason"},{"id":"CWE-20","name":"Name","reason":"Reason"}]}"#,
    ] {
        let f = Fixture::new();
        f.approve(2);
        let runtime = OfflineRuntime::new(text);
        let result = f.dispatch(f.input(), &runtime).unwrap();
        assert_eq!(result["status"], "failed");
        assert!(result["output"]
            .as_str()
            .unwrap()
            .contains("No repair request"));
        assert!(result["data"]["cwes"].as_array().unwrap().is_empty());
        assert!(!result["data"]["frozenInput"].is_null());
        assert_eq!(runtime.requests.lock().unwrap().len(), 1);
        assert_eq!(f.snapshot().committed_calls, 1);
    }
}

#[test]
fn unsupported_controls_are_refused_even_when_equal_to_legacy_defaults() {
    let f = Fixture::new();
    f.approve(2);
    let runtime = OfflineRuntime::new(ANSWER);
    for (key, value) in [
        ("maxFindings", json!(30)),
        ("maxSurfaces", json!(50)),
        ("artifactDir", json!(".kuzushi/systems-hunt")),
        ("context", json!({})),
        ("cwes", json!([])),
    ] {
        let mut input = f.input();
        input[key] = value;
        let error = f.dispatch(input, &runtime).unwrap_err();
        assert!(
            format!("{error:#}").contains("unsupported by standalone CWE proposals"),
            "{error:#}"
        );
    }
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert_eq!(f.snapshot().committed_calls, 0);
}

#[test]
fn stored_unsupported_controls_are_refused_before_a_request() {
    use crate::options::{OptionScope, OptionTarget, ToolOptionStore};
    let f = Fixture::new();
    f.approve(2);
    let runtime = OfflineRuntime::new(ANSWER);
    for scope in [OptionScope::Global, OptionScope::Workspace] {
        let mut store = ToolOptionStore::new();
        store.set_value(
            scope,
            OptionTarget::Tool(TOOL.into()),
            "max_findings",
            json!(30),
        );
        let ctx = f.ctx();
        let prepared = f
            .registry
            .prepare_dispatch_input(TOOL, f.input(), &ctx, Some(&store))
            .unwrap()
            .authorize_explicit_headless();
        let error = f
            .registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
            .unwrap_err();
        assert!(format!("{error:#}").contains("unsupported by standalone CWE proposals"));
    }
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert_eq!(f.snapshot().committed_calls, 0);
}

#[test]
fn explicit_class_handoff_is_read_by_the_existing_consumer_without_another_request() {
    let f = Fixture::new();
    f.approve(2);
    let runtime = OfflineRuntime::new(ANSWER);
    let result = f.dispatch(f.input(), &runtime).unwrap();
    let supplied = json!({"cwes":result["data"]["cwes"]});
    let options = SystemsHuntInput::from_tool_input(&supplied).unwrap();
    let selected = selected_deep_semantic_cwes(&supplied, &f.ctx(), &runtime, &options).unwrap();
    assert_eq!(
        serde_json::to_value(selected.value).unwrap(),
        result["data"]["cwes"]
    );
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(f.snapshot().committed_calls, 1);
}

#[test]
fn excessive_class_count_and_invalid_limits_never_silently_truncate() {
    let f = Fixture::new();
    f.approve(2);
    let classes = json!({"cwes":[{"id":"CWE-20","name":"First","reason":"Owned source metadata"},
        {"id":"CWE-21","name":"Second","reason":"Owned source metadata"}]})
    .to_string();
    let runtime = OfflineRuntime::new(&classes);
    let mut supplied = f.input();
    supplied["max_cwe_classes"] = json!(1);
    let result = f.dispatch(supplied, &runtime).unwrap();
    assert_eq!(result["status"], "failed");
    assert!(result["output"].as_str().unwrap().contains("class limit"));
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    for input in [
        json!({"maxFiles":0}),
        json!({"maxSourceBytes":16777217}),
        json!({"head_bytes":262145}),
        json!({"maxCweClasses":33}),
        json!({"scopeId":"unapproved-scope"}),
    ] {
        assert!(f.dispatch(input, &runtime).is_err());
    }
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn include_non_production_is_honored_without_widening_to_other_languages() {
    let f = Fixture::new();
    fs::remove_file(f.root.path().join("owned.c")).unwrap();
    fs::create_dir(f.root.path().join("tests")).unwrap();
    fs::write(
        f.root.path().join("tests/owned.c"),
        "// owned_input; inert test text\n",
    )
    .unwrap();
    fs::write(
        f.root.path().join("unrelated.py"),
        "# never selected by systems planning\n",
    )
    .unwrap();
    assert!(context::prepare(
        f.root.path(),
        &input::canonical(&json!({})).unwrap(),
        &f.ctx()
    )
    .is_err());
    let prepared = context::prepare(
        f.root.path(),
        &input::canonical(&json!({"include_non_production":true})).unwrap(),
        &f.ctx(),
    )
    .unwrap();
    assert!(prepared.prompt.contains("tests/owned.c"));
    assert!(!prepared.prompt.contains("unrelated.py"));
}

#[test]
fn explicit_reasoning_is_preserved_and_legacy_aliases_use_descriptor_validation() {
    let f = Fixture::new();
    f.approve(2);
    let runtime = OfflineRuntime::new(ANSWER);
    let mut supplied = f.input();
    supplied["effort"] = json!("medium");
    let result = f.dispatch(supplied, &runtime).unwrap();
    assert!(result["data"]["costUsd"].is_null());
    assert_eq!(
        runtime.requests.lock().unwrap()[0]
            .thinking_level
            .as_deref(),
        Some("medium")
    );
    let canonical = input::canonical(
        &input::legacy_input(&json!({"max_files":1,"head_bytes":16,"maxFindings":30})).unwrap(),
    )
    .unwrap();
    assert_eq!(canonical["maxFiles"], 1);
    assert_eq!(canonical["headBytes"], 16);
    assert!(canonical.get("maxFindings").is_none());
}

#[test]
fn source_drift_and_cancellation_preserve_charging_without_followup_work() {
    let f = Fixture::new();
    f.approve(2);
    let mut runtime = OfflineRuntime::new(ANSWER);
    runtime.mutate_after = Some(f.root.path().join("owned.c"));
    let result = f.dispatch(f.input(), &runtime).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["sourceCheckCurrent"], false);
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(f.snapshot().committed_calls, 1);
    let f = Fixture::new();
    f.approve(2);
    let canceled = Arc::new(crate::scan::ScanCancellation::default());
    let mut runtime = OfflineRuntime::new(ANSWER);
    runtime.cancel_after = Some(canceled.clone());
    let mut ctx = f.ctx();
    ctx.cancellation = Some(&canceled);
    let prepared = f
        .registry
        .prepare_dispatch_input(TOOL, f.input(), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let result = f
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime));
    if let Ok(output) = result {
        assert_ne!(output["status"], "completed");
    }
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(f.snapshot().committed_calls, 1);
}

#[test]
fn transport_failure_is_honest_and_never_retried_by_the_selector() {
    let f = Fixture::new();
    f.approve(2);
    let runtime = OfflineRuntime::new("owned transport failure");
    let error = f.dispatch(f.input(), &runtime).unwrap_err();
    assert!(format!("{error:#}").contains("owned transport failure"));
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(f.snapshot().unresolved_calls, 1);
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
fn exact_context_reference_is_supplied_without_changing_the_active_revision() {
    let f = Fixture::new();
    f.approve(2);
    let first = commit_context(f.root.path(), "owned-accepted-alpha");
    let second = commit_context(f.root.path(), "owned-active-beta");
    let runtime = OfflineRuntime::new(ANSWER);
    let mut supplied = f.input();
    supplied["threat_model_ref"] = json!(first);
    let result = f.dispatch(supplied, &runtime).unwrap();
    let requests = runtime.requests.lock().unwrap();
    assert!(requests[0].prompt.contains("owned-accepted-alpha"));
    assert!(!requests[0].prompt.contains("owned-active-beta"));
    assert_eq!(
        result["data"]["frozenInput"]["selectedThreatModelRef"],
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
fn malformed_stored_context_is_not_silently_omitted_before_model_work() {
    let f = Fixture::new();
    f.approve(2);
    let path = crate::context::context_snapshot_path(f.root.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, "{broken context").unwrap();
    let runtime = OfflineRuntime::new(ANSWER);
    assert!(
        format!("{:#}", f.dispatch(f.input(), &runtime).unwrap_err())
            .contains("Stored project context is malformed")
    );
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert_eq!(f.snapshot().committed_calls, 0);
}

#[test]
fn no_systems_source_or_precanceled_work_never_queries() {
    let f = Fixture::new();
    f.approve(2);
    fs::remove_file(f.root.path().join("owned.c")).unwrap();
    let runtime = OfflineRuntime::new(ANSWER);
    assert!(
        format!("{:#}", f.dispatch(f.input(), &runtime).unwrap_err())
            .contains("No systems source excerpts")
    );
    assert_eq!(f.snapshot().committed_calls, 0);
    assert!(runtime.requests.lock().unwrap().is_empty());
    let mut ctx = f.ctx();
    let canceled = crate::scan::ScanCancellation::default();
    canceled.cancel();
    ctx.cancellation = Some(&canceled);
    assert!(execute_cwe_proposal(&json!({}), &ctx, Some(&runtime)).is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn bounded_inventory_observes_empty_directories_and_excludes_symlink_cycles() {
    let f = Fixture::new();
    let mut path = f.root.path().to_path_buf();
    for _ in 0..160 {
        path = path.join("x");
        fs::create_dir(&path).unwrap();
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(f.root.path(), f.root.path().join("cycle")).unwrap();
    let prepared = context::prepare(
        f.root.path(),
        &input::canonical(&json!({"headBytes":16})).unwrap(),
        &f.ctx(),
    )
    .unwrap();
    assert!(
        prepared.inspection["inventory"]["entries"]
            .as_u64()
            .unwrap()
            >= 160
    );
    assert_eq!(prepared.inspection["indexedFiles"], 1);
    assert_eq!(prepared.inspection["status"], "partial");
    assert!(prepared.prompt.len() < 80 * 1024);
}
