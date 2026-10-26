use super::*;
use crate::{modules::ModuleRegistry, runtime::AgentQueryResponse, V2Config};
use std::sync::{Arc, Mutex};

const MODEL: &str = "openai-codex:gpt-5.5";

mod accounting;
mod context_input;
mod dependencies;
mod rejected_output;

struct Fixture {
    root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    config: V2Config,
    registry: ModuleRegistry,
    original: ScanScopeReview,
    trace: crate::run_artifacts::TraceHandle,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("app")).unwrap();
        std::fs::write(
            root.path().join("app/main.py"),
            "print('labeled scope fixture')\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("README.md"),
            "Labeled architecture fixture\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let mut config = V2Config::default();
        config.model = Some(MODEL.into());
        let registry = ModuleRegistry::with_v2_builtins();
        let trace = crate::run_artifacts::TraceHandle::jsonl(root.path(), "scope-test");
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            trace: Some(&trace),
            findings_store: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let original = create_scan_scope_proposal(&ctx, None).unwrap();
        let approved = registry.prepare_dispatch_input("campaign:approve-allowance",
            json!({"investigationId":"scopes","expectedRevision":0,"model":MODEL,
                "maxProviderCalls":2,"protectedReviewCalls":1,"reason":"Labeled offline scope test"}), &ctx, None)
            .unwrap().authorize_explicit_headless();
        registry
            .dispatch_prepared_input_with_runtime(approved, &ctx, None)
            .unwrap();
        Self {
            root,
            workspace,
            config,
            registry,
            original,
            trace,
        }
    }

    fn context(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            trace: Some(&self.trace),
            findings_store: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }

    fn input(&self) -> Value {
        json!({"proposalRef":self.original.reference, "model":MODEL, "thinkingLevel":"medium",
            "allowanceRef":{"schemaVersion":1,"investigationId":"scopes","revision":1,"workId":"scope-one"}})
    }

    fn dispatch(&self, input: Value, runtime: &OfflineScopeRuntime) -> Result<Value> {
        let ctx = self.context();
        let prepared = self
            .registry
            .prepare_dispatch_input(TOOL, input, &ctx, None)?;
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(runtime))
    }
}

#[derive(Clone)]
struct OfflineScopeRuntime {
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    response: AgentQueryResponse,
    binding: Option<crate::allowance::AllowanceBinding>,
    during_query: Option<Arc<dyn Fn() -> Result<()> + Send + Sync>>,
}

impl OfflineScopeRuntime {
    fn new(value: Value) -> Self {
        Self {
            requests: Default::default(),
            response: AgentQueryResponse {
                structured: Some(value),
                ..Default::default()
            },
            binding: None,
            during_query: None,
        }
    }
}

#[async_trait::async_trait]
impl AgentRuntime for OfflineScopeRuntime {
    fn with_allowance_binding(
        &self,
        binding: crate::allowance::AllowanceBinding,
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
            .context("test requires shared admission")?;
        let reservation = binding.reserve(&request.model)?;
        self.requests.lock().unwrap().push(request);
        binding.settle(reservation, crate::runtime::RuntimeCostReport::UNAVAILABLE)?;
        if let Some(effect) = &self.during_query {
            effect()?;
        }
        Ok(self.response.clone())
    }
    fn triage_finding_blocking(&self, _: crate::TriageRequest) -> Result<crate::TriageOutcome> {
        unreachable!()
    }
}

fn draft() -> Value {
    json!({"schemaVersion":1,"sharedScope":null,"sharedDiscovery":false,"exclusions":[],
    "scopes":[
        {"id":"app","name":"Application","paths":["app"],"rationale":"One coherent fixture package.","sharedDependencies":[],"openQuestions":[]},
        {"id":"root","name":"Root material","paths":["README.md"],"rationale":"Preserve loose root files.","sharedDependencies":[],"openQuestions":[]}
    ]})
}

#[test]
fn one_prepared_query_reuses_inventory_and_saves_only_an_unaccepted_revision() {
    let fixture = Fixture::new();
    let runtime = OfflineScopeRuntime::new(draft());
    let output = fixture.dispatch(fixture.input(), &runtime).unwrap();
    let review: ScanScopeReview = serde_json::from_value(output["data"].clone()).unwrap();
    assert_eq!(
        review.record.inventory_hash,
        fixture.original.record.inventory_hash
    );
    assert_eq!(review.record.source, fixture.original.record.source);
    assert_eq!(
        review.record.previous.as_ref(),
        Some(&fixture.original.reference)
    );
    assert!(review.record.acceptance.is_none());
    assert_eq!(review.coverage.uncovered_files.total, 0);
    let generation = review.record.generation.as_ref().unwrap();
    assert_eq!(generation.model, MODEL);
    assert_eq!(
        (generation.supplied_files, generation.inventoried_files),
        (2, 2)
    );
    assert!(generation.context_ref.is_none());
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert!(request.tool_policy.tools.is_empty() && request.tool_policy.mcp_read_roots.is_empty());
    assert!(!request.tool_policy.mcps);
    assert_eq!(
        request.runtime_options.as_ref().unwrap().max_model_turns,
        Some(1)
    );
    assert_eq!(request.thinking_level.as_deref(), Some("medium"));
    assert!(request.prompt.len() <= input::MAX_PROMPT_BYTES);
    assert_eq!(output["allowanceRef"], fixture.input()["allowanceRef"]);
    assert!(
        crate::strategy::load_strategy_queue(&fixture.workspace).unwrap()[0]
            .tool
            .is_none()
    );
    assert!(!fixture.workspace.state_dir().join("campaigns").exists());
    assert_eq!(
        load_scan_scope_proposal(&fixture.workspace, &fixture.original.reference).unwrap(),
        fixture.original
    );
}

#[test]
fn model_output_cannot_exclude_source_enable_duplicate_work_or_escape_inventory() {
    for (key, value) in [
        (
            "exclusions",
            json!([{"path":"README.md","reason":"model choice"}]),
        ),
        ("sharedDiscovery", json!(true)),
        (
            "scopes",
            json!([{ "id":"outside","name":"Outside","paths":["../outside"],"rationale":"Invalid","sharedDependencies":[],"openQuestions":[]}]),
        ),
    ] {
        let fixture = Fixture::new();
        let mut output = draft();
        output[key] = value;
        let runtime = OfflineScopeRuntime::new(output);
        assert!(fixture.dispatch(fixture.input(), &runtime).is_err());
        assert_eq!(runtime.requests.lock().unwrap().len(), 1);
        assert_eq!(
            load_latest_scan_scope_proposal(&fixture.context())
                .unwrap()
                .unwrap(),
            fixture.original
        );
    }
}

#[test]
fn excessive_scopes_and_invalid_dependencies_preserve_the_previous_draft() {
    for value in [json!((0..9).map(|id| json!({"id":format!("scope-{id}"),"name":"Too many","paths":["app"],"rationale":"Invalid count","sharedDependencies":[],"openQuestions":[]})).collect::<Vec<_>>()),
        json!([{ "id":"app","name":"App","paths":["app"],"rationale":"Invalid dependency","sharedDependencies":["unknown"],"openQuestions":[]}])] {
        let fixture=Fixture::new(); let mut output=draft(); output["scopes"]=value;
        let runtime=OfflineScopeRuntime::new(output);
        assert!(fixture.dispatch(fixture.input(), &runtime).is_err());
        assert_eq!(runtime.requests.lock().unwrap().len(),1);
        assert_eq!(load_latest_scan_scope_proposal(&fixture.context()).unwrap().unwrap(),fixture.original);
    }
}

#[test]
fn malformed_partial_and_oversized_results_never_trigger_repairs() {
    let responses = [
        AgentQueryResponse {
            text: "```json\n{}\n```".into(),
            ..Default::default()
        },
        AgentQueryResponse {
            structured: Some(draft()),
            truncated: true,
            ..Default::default()
        },
        AgentQueryResponse {
            text: "x".repeat(256 * 1024 + 1),
            ..Default::default()
        },
    ];
    for response in responses {
        let fixture = Fixture::new();
        let mut runtime = OfflineScopeRuntime::new(draft());
        runtime.response = response;
        assert!(fixture.dispatch(fixture.input(), &runtime).is_err());
        assert_eq!(runtime.requests.lock().unwrap().len(), 1);
        assert_eq!(
            load_latest_scan_scope_proposal(&fixture.context())
                .unwrap()
                .unwrap(),
            fixture.original
        );
    }
}

#[test]
fn changed_source_and_stale_scope_refs_are_rejected_before_a_query() {
    let fixture = Fixture::new();
    let runtime = OfflineScopeRuntime::new(draft());
    edit_scan_scope_proposal(
        &fixture.context(),
        &fixture.original.reference,
        ScanScopeEdit::Rename {
            scope_id: "repository".into(),
            name: "Changed by operator".into(),
        },
    )
    .unwrap();
    assert!(fixture.dispatch(fixture.input(), &runtime).is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
    let fixture = Fixture::new();
    std::fs::write(fixture.root.path().join("README.md"), "Changed source").unwrap();
    assert!(fixture.dispatch(fixture.input(), &runtime).is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn source_change_during_the_query_retains_the_consumed_call_and_old_draft() {
    let fixture = Fixture::new();
    let mut runtime = OfflineScopeRuntime::new(draft());
    let path = fixture.root.path().join("README.md");
    runtime.during_query = Some(Arc::new(move || {
        std::fs::write(&path, "Source changed during request")?;
        Ok(())
    }));
    assert!(fixture.dispatch(fixture.input(), &runtime).is_err());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(
        load_latest_scan_scope_proposal(&fixture.context())
            .unwrap()
            .unwrap(),
        fixture.original
    );
    let ledger = crate::SpendLimiter::open(fixture.workspace.findings_db_path()).unwrap();
    assert_eq!(
        ledger.allowance_snapshot("scopes").unwrap().committed_calls,
        1
    );
}

#[test]
fn exhausted_allowance_and_model_drift_cannot_make_another_provider_request() {
    let fixture = Fixture::new();
    let runtime = OfflineScopeRuntime::new(draft());
    let mut wrong = fixture.input();
    wrong["model"] = json!("openai-codex:other");
    assert!(fixture.dispatch(wrong, &runtime).is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
    let first = fixture.dispatch(fixture.input(), &runtime).unwrap();
    let mut again = fixture.input();
    again["proposalRef"] = first["data"]["reference"].clone();
    assert!(fixture.dispatch(again, &runtime).is_err());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(
        load_latest_scan_scope_proposal(&fixture.context())
            .unwrap()
            .unwrap()
            .reference
            .revision,
        2
    );
}

#[test]
fn missing_allowance_unknown_controls_and_unbounded_output_requests_fail_preparation() {
    let fixture = Fixture::new();
    let tool = fixture.registry.resolve_tool(TOOL).unwrap();
    assert_eq!(
        tool.options
            .iter()
            .filter(|option| option.name == "allowanceRef")
            .count(),
        1
    );
    assert!(
        tool.options
            .iter()
            .find(|option| option.name == "allowanceRef")
            .unwrap()
            .required
    );
    let mut absent = fixture.input();
    absent.as_object_mut().unwrap().remove("allowanceRef");
    assert!(fixture
        .registry
        .prepare_dispatch_input(TOOL, absent, &fixture.context(), None)
        .is_err());
    for (key, value) in [("recursive", json!(true)), ("maxOutputTokens", json!(8193))] {
        let mut input = fixture.input();
        input[key] = value;
        assert!(fixture
            .registry
            .prepare_dispatch_input(TOOL, input, &fixture.context(), None)
            .is_err());
    }
}

#[test]
fn bounded_input_discloses_omissions_and_preserves_loose_parent_files() {
    let fixture = Fixture::new();
    let (_, mut inventory) =
        current_inventory(&fixture.context(), &fixture.original.reference).unwrap();
    let files = &mut inventory.inspection.as_mut().unwrap().files;
    files.extend((0..5000).map(|id| format!("packages/component-{id}/src/main.rs")));
    let outline=input::build(&inventory,&fixture.original,Some(&json!({"contextSummary":"Architecture","dfd":{"nodes":[{"id":"app","purpose":"Application"}]}})),"Operator priorities").unwrap();
    assert!(serde_json::to_vec(&outline.document).unwrap().len() <= input::MAX_PROMPT_BYTES);
    assert!(outline.supplied_files <= 512);
    assert_eq!(outline.inventoried_files, 5002);
    assert!(outline.document["files"]["omitted"].as_u64().unwrap() > 0);
    assert!(outline.document["directoryGroups"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["path"] == "."));
    assert!(input::build(&inventory, &fixture.original, None, &"x".repeat(2049)).is_err());
}

#[test]
fn legacy_manual_revisions_keep_their_serialized_hash_without_generation_fields() {
    let fixture = Fixture::new();
    let value = serde_json::to_value(&fixture.original.record).unwrap();
    assert!(value.get("generation").is_none());
    let roundtrip: ScanScopeRevision = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(roundtrip).unwrap(), value);
}
