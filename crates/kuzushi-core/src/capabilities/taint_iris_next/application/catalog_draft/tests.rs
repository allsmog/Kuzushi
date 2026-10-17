use super::*;
use crate::allowance::AllowanceBinding;
use crate::modules::ModuleRegistry;
use std::sync::{Arc, Mutex};

const MODEL: &str = "openai-codex:gpt-5.5";

#[derive(Clone)]
struct Runtime {
    binding: Option<AllowanceBinding>,
    response: Value,
    raw_text: Option<String>,
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    mutate_source: Option<PathBuf>,
}

impl AgentRuntime for Runtime {
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
            .context("Unbudgeted fixture request")?;
        let reservation = binding.reserve(&request.model)?;
        self.requests.lock().unwrap().push(request);
        if let Some(path) = &self.mutate_source {
            fs::write(path, "// source changed during the intercepted request\n")?;
        }
        let response = AgentQueryResponse {
            text: self
                .raw_text
                .clone()
                .unwrap_or_else(|| self.response.to_string()),
            structured: self.raw_text.is_none().then(|| self.response.clone()),
            ..Default::default()
        };
        binding.settle(reservation, response.checked_cost_report()?)?;
        Ok(response)
    }
    fn triage_finding_blocking(&self, _: crate::TriageRequest) -> Result<crate::TriageOutcome> {
        anyhow::bail!("Owned fixture supports no triage or further work")
    }
}

struct Fixture {
    root: tempfile::TempDir,
    workspace: crate::WorkspaceTarget,
    config: crate::V2Config,
    registry: ModuleRegistry,
    store: crate::findings::FindingStore,
    runtime: Runtime,
}

impl Fixture {
    fn new(response: Value) -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("owned café.c"),
            "// Owned inert metadata. Never executed.\n// owned_input -> owned_sink\n",
        )
        .unwrap();
        let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
        let store = crate::findings::FindingStore::open(workspace.findings_db_path()).unwrap();
        Self {
            root,
            workspace,
            store,
            config: crate::V2Config {
                model: Some(MODEL.into()),
                ..Default::default()
            },
            registry: ModuleRegistry::with_v2_builtins_without_optional_adapters(),
            runtime: Runtime {
                binding: None,
                response,
                raw_text: None,
                requests: Default::default(),
                mutate_source: None,
            },
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
    fn dispatch(&self, tool: &str, input: Value, model: bool) -> Result<Value> {
        let ctx = self.ctx();
        let prepared = self
            .registry
            .prepare_dispatch_input(tool, input, &ctx, None)?
            .authorize_explicit_headless();
        self.registry.dispatch_prepared_input_with_runtime(
            prepared,
            &ctx,
            model.then_some(&self.runtime as &dyn AgentRuntime),
        )
    }
    fn approve(&self, calls: u64) {
        self.dispatch("campaign:approve-allowance",json!({"investigationId":"owned-catalog","expectedRevision":0,"model":MODEL,
            "maxProviderCalls":calls,"protectedReviewCalls":0,"reason":"Owned intercepted catalog fixture; no provider transport"}),false).unwrap();
    }
    fn generate(&self, extra: Value) -> Value {
        let mut input = json!({"allowanceRef":{"schemaVersion":1,"investigationId":"owned-catalog","revision":1,"workId":"owned-catalog-draft"}});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        self.dispatch(TOOL, input, true).unwrap()
    }
    fn count(&self) -> usize {
        self.runtime.requests.lock().unwrap().len()
    }
}

fn valid() -> Value {
    json!({"catalog":[{"cwe":"CWE-20","name":"Owned input review","taintClass":"owned-input",
        "languages":["any"],"sourceSignals":["owned_input"],"sinkSignals":["owned_sink"],
        "sanitizerSignals":[],"structuralQueries":[],"regexMarkers":[],"score":0,"reasons":["Owned source markers only"]}]})
}

#[test]
fn prepared_generation_freezes_a_draft_then_explicit_review_and_acceptance_pin_the_consumer() {
    let f = Fixture::new(valid());
    f.approve(1);
    let output = f.generate(json!({}));
    assert_eq!(output["status"], "completed");
    assert_eq!(output["data"]["status"], "draft");
    assert!(!taint_iris_next_target_catalog_path(f.root.path()).exists());
    let reference = output["data"]["draftRef"].as_str().unwrap();
    let read = f
        .dispatch(
            "taint-iris-next:catalog-read",
            json!({"draftRef":reference,"section":"inputs"}),
            false,
        )
        .unwrap();
    assert!(read["output"].as_str().unwrap().contains("owned_input"));
    assert_eq!(read["data"]["sourceFreshnessVerified"], false);
    let accepted = f
        .dispatch(
            "taint-iris-next:catalog-accept",
            json!({"draftRef":reference}),
            false,
        )
        .unwrap();
    let digest = accepted["data"]["catalogDigestRef"].as_str().unwrap();
    assert!(selected_catalog(f.root.path(), None).is_err());
    let entries = selected_catalog(f.root.path(), Some(digest))
        .unwrap()
        .unwrap();
    assert_eq!(entries[0].source_signals, vec!["owned_input"]);
    assert_eq!(entries[0].score, 0);
    let repeat = f
        .dispatch(
            "taint-iris-next:catalog-accept",
            json!({"draftRef":reference}),
            false,
        )
        .unwrap();
    assert_eq!(repeat["data"]["catalogDigestRef"], digest);
    assert_eq!(f.count(), 1);
}

#[test]
fn catalog_request_is_one_turn_no_tools_and_uses_only_frozen_source_and_selected_model() {
    let f = Fixture::new(valid());
    f.approve(1);
    f.generate(json!({}));
    let requests = f.runtime.requests.lock().unwrap();
    let request = &requests[0];
    assert_eq!(requests.len(), 1);
    assert_eq!(request.model, MODEL);
    assert!(request.tool_policy.tools.is_empty());
    assert!(!request.tool_policy.mcps);
    assert_eq!(
        request.runtime_options.as_ref().unwrap().max_model_turns,
        Some(1)
    );
    assert_eq!(request.max_output_tokens, Some(4096));
    assert!(request.prompt.contains("owned_input"));
    assert!(!request.prompt.contains("pullf_"));
    assert!(!f.root.path().join(".kuzushi/cpg-rs").exists());
}

#[test]
fn malformed_ungrounded_excessive_or_out_of_range_catalogs_preserve_active_bytes() {
    let mut bad = valid();
    bad["catalog"][0]["sourceSignals"] = json!(["absent_from_frozen_source"]);
    let mut score = valid();
    score["catalog"][0]["score"] = json!(9999);
    let many = json!({"catalog":vec![valid()["catalog"][0].clone();13]});
    for response in [json!({}), bad, score, many] {
        let f = Fixture::new(response);
        f.approve(1);
        let path = taint_iris_next_target_catalog_path(f.root.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "Owned prior metadata").unwrap();
        let output = f.generate(json!({}));
        assert_eq!(output["status"], "failed");
        assert_eq!(fs::read_to_string(&path).unwrap(), "Owned prior metadata");
        assert_eq!(f.count(), 1);
        assert_eq!(output["data"]["priorCatalogPreserved"], true);
        assert!(output["data"]["rawAgentOutput"].is_object());
    }
}

#[test]
fn missing_allowance_or_exhausted_calls_refuse_before_a_provider_request() {
    let f = Fixture::new(valid());
    assert!(f.dispatch(TOOL, json!({}), true).is_err());
    assert_eq!(f.count(), 0);
    f.approve(0);
    let input = json!({"allowanceRef":{"schemaVersion":1,"investigationId":"owned-catalog","revision":1,"workId":"owned-catalog-draft"}});
    assert!(f.dispatch(TOOL, input, true).is_err());
    assert_eq!(f.count(), 0);
}

#[test]
fn source_drift_refuses_acceptance_but_keeps_historical_inputs_readable() {
    let f = Fixture::new(valid());
    f.approve(1);
    let output = f.generate(json!({}));
    let reference = &output["data"]["draftRef"];
    fs::write(
        f.root.path().join("owned café.c"),
        "// Changed owned source metadata\n",
    )
    .unwrap();
    let error = f
        .dispatch(
            "taint-iris-next:catalog-accept",
            json!({"draftRef":reference}),
            false,
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("Source changed"));
    assert!(f
        .dispatch(
            "taint-iris-next:catalog-read",
            json!({"draftRef":reference,"section":"inputs"}),
            false
        )
        .unwrap()["output"]
        .as_str()
        .unwrap()
        .contains("owned_input"));
    assert!(!taint_iris_next_target_catalog_path(f.root.path()).exists());
    assert_eq!(f.count(), 1);
}

#[test]
fn concurrently_changed_active_catalog_is_never_overwritten_by_an_older_draft() {
    let f = Fixture::new(valid());
    f.approve(1);
    let output = f.generate(json!({}));
    let path = taint_iris_next_target_catalog_path(f.root.path());
    fs::write(&path, "New operator catalog bytes").unwrap();
    assert!(f
        .dispatch(
            "taint-iris-next:catalog-accept",
            json!({"draftRef":output["data"]["draftRef"]}),
            false
        )
        .is_err());
    assert_eq!(
        fs::read_to_string(path).unwrap(),
        "New operator catalog bytes"
    );
    assert_eq!(f.count(), 1);
}

#[test]
fn invalid_pins_and_malformed_catalogs_never_fall_back_to_static_implicitly() {
    let f = Fixture::new(valid());
    let path = taint_iris_next_target_catalog_path(f.root.path());
    fs::write(&path, "{malformed").unwrap();
    assert!(selected_catalog(f.root.path(), None).is_err());
    assert!(selected_catalog(f.root.path(), Some("wrong")).is_err());
    let digest = persistence::active_digest(f.root.path()).unwrap().unwrap();
    assert!(selected_catalog(f.root.path(), Some(&digest)).is_err());
    assert!(selected_catalog(f.root.path(), Some("static"))
        .unwrap()
        .is_none());
}

#[test]
fn draft_read_does_not_create_missing_content_stores_and_rejects_invalid_refs() {
    let root = tempfile::tempdir().unwrap();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    assert!(persistence::load(root.path(), &"a".repeat(64)).is_err());
    assert!(!workspace.objects_dir().exists());
    assert!(persistence::reference(&json!({"draftRef":"../../outside"})).is_err());
}

#[test]
fn descriptors_keep_generation_experimental_and_acceptance_explicit_without_phase_credit() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let generation = registry.resolve_tool(TOOL).unwrap();
    assert_eq!(generation.phase, crate::modules::ToolPhase::Map);
    assert_eq!(
        generation.allowance_category,
        Some(kuzushi_descriptor::AllowanceCategory::Context)
    );
    assert_eq!(
        generation.discovery_maturity,
        Some(crate::modules::ModuleMaturity::Labs)
    );
    for name in [
        TOOL,
        "taint-iris-next:catalog-read",
        "taint-iris-next:catalog-accept",
    ] {
        assert!(!registry.resolve_tool(name).unwrap().phase_result);
    }
    let accept = registry
        .resolve_tool("taint-iris-next:catalog-accept")
        .unwrap();
    assert_eq!(accept.approval, crate::modules::ApprovalPolicy::Explicit);
    assert_eq!(
        accept.runtime_requirement,
        crate::modules::RuntimeRequirement::Never
    );
}

#[test]
fn pinned_accepted_catalog_survives_active_changes_and_unaccepted_drafts_cannot_be_used() {
    let f = Fixture::new(valid());
    f.approve(1);
    let output = f.generate(json!({}));
    let draft = &output["data"]["draftRef"];
    assert!(selected_catalog(f.root.path(), draft.as_str()).is_err());
    let accepted = f
        .dispatch(
            "taint-iris-next:catalog-accept",
            json!({"draftRef":draft}),
            false,
        )
        .unwrap();
    let pin = accepted["data"]["catalogDigestRef"].as_str().unwrap();
    fs::write(
        taint_iris_next_target_catalog_path(f.root.path()),
        "Different active bytes",
    )
    .unwrap();
    let selected = selected_catalog(f.root.path(), Some(pin)).unwrap().unwrap();
    assert_eq!(selected[0].source_signals, vec!["owned_input"]);
    let read = f
        .dispatch(
            "taint-iris-next:catalog-read",
            json!({"catalogDigestRef":pin,"section":"inputs"}),
            false,
        )
        .unwrap();
    assert!(read["data"]["systemPrompt"]
        .as_str()
        .unwrap()
        .contains("untrusted data"));
    assert_eq!(f.count(), 1);
}

#[test]
fn prompt_only_truncation_is_explicit_and_partial_acceptance_requires_acknowledgement() {
    let f = Fixture::new(valid());
    fs::write(
        f.root.path().join("owned café.c"),
        format!("// owned_input owned_sink\n//{}", "é".repeat(3000)),
    )
    .unwrap();
    f.approve(1);
    let output = f.generate(json!({"headBytes":16384}));
    assert_eq!(output["status"], "partial");
    assert_eq!(
        output["data"]["inspection"]["promptTruncatedSourceFiles"],
        1
    );
    let reference = &output["data"]["draftRef"];
    assert!(f
        .dispatch(
            "taint-iris-next:catalog-accept",
            json!({"draftRef":reference}),
            false
        )
        .is_err());
    f.dispatch(
        "taint-iris-next:catalog-accept",
        json!({"draftRef":reference,"acknowledgePartial":true}),
        false,
    )
    .unwrap();
    assert_eq!(f.count(), 1);
}

#[test]
fn malformed_context_refuses_before_model_work_without_replacing_active_context() {
    let f = Fixture::new(valid());
    f.approve(1);
    let path = crate::context::context_snapshot_path(f.root.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "{malformed context").unwrap();
    let input = json!({"allowanceRef":{"schemaVersion":1,"investigationId":"owned-catalog","revision":1,"workId":"owned-catalog-draft"}});
    let error = f.dispatch(TOOL, input, true).unwrap_err();
    assert!(format!("{error:#}").contains("Stored context is malformed"));
    assert_eq!(f.count(), 0);
    assert_eq!(fs::read_to_string(path).unwrap(), "{malformed context");
}

#[test]
fn empty_profile_read_is_an_honest_runtime_free_empty_state() {
    let f = Fixture::new(valid());
    let output = f
        .dispatch("taint-iris-next:catalog-read", json!({}), false)
        .unwrap();
    assert_eq!(output["data"]["status"], "absent");
    assert_eq!(f.count(), 0);
    assert!(output["output"]
        .as_str()
        .unwrap()
        .contains("Built-in patterns remain available"));
}

#[test]
fn source_changes_during_model_work_retain_paid_output_without_an_acceptable_draft() {
    let mut f = Fixture::new(valid());
    f.approve(1);
    f.runtime.mutate_source = Some(f.root.path().join("owned café.c"));
    let output = f.generate(json!({}));
    assert_eq!(output["status"], "failed");
    assert_eq!(output["data"]["sourceCheckCurrent"], false);
    assert!(output["data"]["rawAgentOutput"].is_object());
    assert!(output["data"]["frozenInput"]["sources"].is_array());
    assert!(output["data"].get("draftRef").is_none());
    assert!(!taint_iris_next_target_catalog_path(f.root.path()).exists());
    assert_eq!(f.count(), 1);
}

#[test]
fn repeated_acceptance_cannot_mistake_an_edited_profile_for_the_original_draft() {
    let f = Fixture::new(valid());
    f.approve(1);
    let output = f.generate(json!({}));
    let draft = &output["data"]["draftRef"];
    f.dispatch(
        "taint-iris-next:catalog-accept",
        json!({"draftRef":draft}),
        false,
    )
    .unwrap();
    let path = taint_iris_next_target_catalog_path(f.root.path());
    let mut profile: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    profile["catalog"][0]["score"] = json!(99);
    let bytes = serde_json::to_vec(&profile).unwrap();
    fs::write(&path, &bytes).unwrap();
    assert!(f
        .dispatch(
            "taint-iris-next:catalog-accept",
            json!({"draftRef":draft}),
            false
        )
        .is_err());
    assert_eq!(fs::read(path).unwrap(), bytes);
    assert_eq!(f.count(), 1);
}

#[test]
fn reviewed_active_change_can_be_replaced_explicitly_without_another_model_request() {
    let f = Fixture::new(valid());
    f.approve(1);
    let output = f.generate(json!({}));
    let draft = &output["data"]["draftRef"];
    let path = taint_iris_next_target_catalog_path(f.root.path());
    fs::write(&path, "Owned operator edit").unwrap();
    let read = f
        .dispatch("taint-iris-next:catalog-read", json!({}), false)
        .unwrap();
    assert_eq!(read["status"], "failed");
    assert_eq!(read["data"]["status"], "unreadable");
    let expected = read["data"]["catalogDigestRef"].as_str().unwrap();
    assert!(f
        .dispatch(
            "taint-iris-next:catalog-accept",
            json!({"draftRef":draft,"expectedActiveDigest":"a".repeat(64)}),
            false
        )
        .is_err());
    f.dispatch(
        "taint-iris-next:catalog-accept",
        json!({"draftRef":draft,"expectedActiveDigest":expected}),
        false,
    )
    .unwrap();
    let archived = persistence::raw_profile(f.root.path(), Some(expected))
        .unwrap()
        .unwrap();
    assert_eq!(archived.1, b"Owned operator edit");
    assert_eq!(f.count(), 1);
}

#[test]
fn accepted_catalog_pins_still_refuse_source_drift_after_later_active_changes() {
    let f = Fixture::new(valid());
    f.approve(1);
    let output = f.generate(json!({}));
    let accepted = f
        .dispatch(
            "taint-iris-next:catalog-accept",
            json!({"draftRef":output["data"]["draftRef"]}),
            false,
        )
        .unwrap();
    fs::write(f.root.path().join("owned café.c"), "// Different source\n").unwrap();
    assert!(
        selected_catalog(f.root.path(), accepted["data"]["catalogDigestRef"].as_str()).is_err()
    );
    let read = f
        .dispatch(
            "taint-iris-next:catalog-read",
            json!({"catalogDigestRef":accepted["data"]["catalogDigestRef"]}),
            false,
        )
        .unwrap();
    assert_eq!(read["data"]["sourceFreshnessVerified"], false);
    assert_eq!(f.count(), 1);
}

#[test]
fn non_json_and_oversized_text_remain_bounded_readable_paid_output_without_repair() {
    for text in [
        "Owned incomplete response, not JSON".into(),
        "é".repeat(MAX_RESPONSE_BYTES),
    ] {
        let mut fixture = Fixture::new(valid());
        fixture.runtime.raw_text = Some(text.clone());
        fixture.approve(1);
        let result = fixture.generate(json!({}));
        assert_eq!(result["status"], "failed");
        let retained = result["data"]["rawAgentText"].as_str().unwrap();
        assert!(retained.len() <= MAX_RESPONSE_BYTES);
        assert!(text.starts_with(retained));
        assert_eq!(
            result["data"]["rawAgentTextTruncated"],
            retained.len() < text.len()
        );
        assert!(result["data"].get("draftRef").is_none());
        assert_eq!(fixture.count(), 1);
        assert!(!taint_iris_next_target_catalog_path(fixture.root.path()).exists());
    }
}

#[test]
fn draft_reader_prioritizes_entries_and_exposes_exact_base_and_actual_truncation() {
    let f = Fixture::new(valid());
    fs::write(
        f.root.path().join("owned café.c"),
        format!("// owned_input owned_sink\n// {}", "owned ".repeat(50)),
    )
    .unwrap();
    let path = taint_iris_next_target_catalog_path(f.root.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "Owned prior profile bytes").unwrap();
    let base = persistence::active_digest(f.root.path()).unwrap().unwrap();
    f.approve(1);
    let output = f.generate(json!({"headBytes":32}));
    assert_eq!(output["status"], "partial");
    assert_eq!(output["data"]["baseCatalogDigestRef"], base);
    let text = output["output"].as_str().unwrap();
    assert!(text.contains("1 entry") && !text.contains("1 entries"));
    assert!(text.contains("Truncated inspected source prefixes: 1"));
    assert!(text.contains(&base));
    assert!(text.find("priority 0").unwrap() < text.find("Inspected source tree").unwrap());
    assert!(text.contains("Sources: owned_input") && text.contains("Sinks: owned_sink"));
}
