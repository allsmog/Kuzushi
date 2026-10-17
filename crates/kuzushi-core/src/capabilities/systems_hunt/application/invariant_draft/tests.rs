use super::*;
use crate::allowance::AllowanceBinding;
use crate::runtime::{AgentQueryResponse, TriageRequest};
use crate::{ModuleRegistry, V2Config, WorkspaceTarget};
use std::sync::{Arc, Mutex};

const MODEL: &str = "openai-codex:gpt-5.5";
fn answer() -> Value {
    json!({"invariants":[{"id":"assumption-1","surfaceId":"surface-1","kind":"owned-safety-assumption",
        "summary":"Review the owned guard","statement":"The owned guard is an assumption to review",
        "rationale":"The supplied comment names owned_input","evidence":["owned_input"],
        "attackerControlledFields":[],"cheapVerifiable":false}]})
}

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
            "// owned_input owned_sink; guard metadata, never executed.\n",
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
            json!({"investigationId":"owned-invariants","expectedRevision":0,"model":MODEL,"maxProviderCalls":calls,
                "protectedReviewCalls":1,"reason":"Owned inert context drafts; intercepted only"}), &ctx, None)
            .unwrap().authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
            .unwrap();
    }
    fn input(&self) -> Value {
        json!({"context":self.surface_context(),"allowanceRef":{"schemaVersion":1,"investigationId":"owned-invariants","revision":1,"workId":"one-draft"}})
    }
    fn surface_context(&self) -> Value {
        json!({"surfaces":[{"id":"surface-1","filePath":"owned.c","startLine":1,
            "displayName":"Owned inert metadata","kind":"source-note","score":0,"domains":[],
            "reasons":[],"attackerControlledFields":[],"hardeningSignals":[],"evidence":[]}],
            "surfacePacks":[],"metadata":{"codeqlAvailable":false,"bashProbingUsed":false}})
    }
    fn snapshot(&self) -> crate::allowance::AllowanceSnapshot {
        crate::SpendLimiter::open(self.workspace.findings_db_path())
            .unwrap()
            .allowance_snapshot("owned-invariants")
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
            .context("An unbudgeted invariant draft reached the transport")?;
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
        anyhow::bail!("No triage belongs to these drafts")
    }
}

#[test]
fn auxiliary_labs_context_requires_an_allowance_and_never_completes_scan() {
    let f = Fixture::new();
    let tool = f.registry.resolve_tool(TOOL).unwrap();
    assert!(tool.hidden && !tool.phase_result);
    assert_eq!(tool.phase, crate::modules::ToolPhase::Map);
    assert_eq!(
        tool.allowance_category,
        Some(kuzushi_descriptor::AllowanceCategory::Context)
    );
    assert_eq!(
        tool.discovery_maturity,
        Some(crate::modules::ModuleMaturity::Labs)
    );
    assert_eq!(
        tool.finding_store_requirement,
        crate::modules::FindingStoreRequirement::Optional
    );
    let runtime = OfflineRuntime::new(&answer().to_string());
    let error = f
        .dispatch(json!({"context":f.surface_context()}), &runtime)
        .unwrap_err();
    assert!(format!("{error:#}").contains("allowance"));
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn one_tool_free_context_request_freezes_inputs_and_preserves_review_capacity() {
    let f = Fixture::new();
    f.approve(2);
    let runtime = OfflineRuntime::new(&answer().to_string());
    let mut input = f.input();
    input["head_bytes"] = json!(32);
    input["max_files"] = json!(1);
    input["max_source_bytes"] = json!(64);
    let result = f.dispatch(input, &runtime).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["invariants"], answer()["invariants"]);
    assert_eq!(result["data"]["accepted"], false);
    assert_eq!(result["data"]["sourceCheckCurrent"], true);
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let query = &requests[0];
    assert_eq!(query.model, MODEL);
    assert!(query.thinking_level.is_none());
    assert!(query.tool_policy.tools.is_empty() && !query.tool_policy.mcps);
    assert_eq!(
        query.runtime_options.as_ref().unwrap().max_model_turns,
        Some(1)
    );
    assert_eq!(query.max_output_tokens, Some(4096));
    assert_eq!(
        result["data"]["frozenInput"],
        serde_json::from_str::<Value>(&query.prompt).unwrap()
    );
    assert_eq!(result["data"]["inputDocument"]["schemaVersion"], 1);
    let document = result["data"]["inputDocument"]["text"].as_str().unwrap();
    assert!(document.contains("owned_input") && document.contains("not explicitly supplied"));
    assert!(document.contains("Surface source: owned.c:1"));
    assert!(document.find("Source: owned.c").unwrap() < document.find("Model supplied:").unwrap());
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("Source: owned.c:1"));
    assert!(!result["output"]
        .as_str()
        .unwrap()
        .contains("FROZEN MODEL INPUT"));
    assert!(result["data"]["costUsd"].is_null());
    assert_eq!(result["data"]["costUsdExact"], false);
    drop(requests);
    let snapshot = f.snapshot();
    assert_eq!(
        (
            snapshot.committed_calls,
            snapshot.protected_review_remaining()
        ),
        (1, 1)
    );
    assert!(f
        .dispatch(f.input(), &runtime)
        .unwrap_err()
        .to_string()
        .contains("allowance exhausted"));
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert!(!f.root.path().join(".kuzushi/v3/campaigns").exists());
    assert!(!f.root.path().join(".kuzushi/systems-hunt").exists());
}

#[test]
fn malformed_or_unsupported_claims_are_retained_and_charged_once_without_repair() {
    let mut duplicate = answer();
    duplicate["invariants"]
        .as_array_mut()
        .unwrap()
        .push(answer()["invariants"][0].clone());
    let mut foreign = answer();
    foreign["invariants"][0]["surfaceId"] = json!("foreign");
    let mut invented = answer();
    invented["invariants"][0]["evidence"] = json!(["not supplied"]);
    let mut blank = answer();
    blank["invariants"][0]["evidence"] = json!([" "]);
    let mut extra = answer();
    extra["invariants"][0]["verdict"] = json!("verified");
    let mut malformed = answer();
    malformed["invariants"][0]["cheapVerifiable"] = json!("true");
    for text in [
        "not json".into(),
        "{\"invariants\":[{}]}".into(),
        duplicate.to_string(),
        foreign.to_string(),
        invented.to_string(),
        blank.to_string(),
        extra.to_string(),
        malformed.to_string(),
    ] {
        let f = Fixture::new();
        f.approve(2);
        let runtime = OfflineRuntime::new(&text);
        let result = f.dispatch(f.input(), &runtime).unwrap();
        assert_eq!(result["status"], "failed");
        assert!(result["output"]
            .as_str()
            .unwrap()
            .contains("No repair request"));
        assert_eq!(result["data"]["invariants"], json!([]));
        assert_eq!(result["data"]["rawAgentText"], text);
        assert!(result["data"]["inputDocument"]["text"]
            .as_str()
            .unwrap()
            .contains("owned_input"));
        assert_eq!(runtime.requests.lock().unwrap().len(), 1);
        assert_eq!(f.snapshot().committed_calls, 1);
    }
}

#[test]
fn invalid_context_and_scope_controls_fail_before_transport() {
    let f = Fixture::new();
    f.approve(2);
    let runtime = OfflineRuntime::new(&answer().to_string());
    for path in ["../foreign.c", "/tmp/foreign.c", "missing.c"] {
        let mut input = f.input();
        input["context"]["surfaces"][0]["filePath"] = json!(path);
        assert!(f.dispatch(input, &runtime).is_err(), "{path}");
    }
    let mut duplicate = f.input();
    duplicate["context"]["surfaces"]
        .as_array_mut()
        .unwrap()
        .push(f.surface_context()["surfaces"][0].clone());
    let mut oversized = f.input();
    oversized["context"]["unused"] = json!("x".repeat(4 * 1024 * 1024));
    let mut late = f.input();
    late["context"]["surfaces"][0]["startLine"] = json!(100);
    for input in [duplicate, oversized, late, json!({}), json!({"context":{}})] {
        assert!(f.dispatch(input, &runtime).is_err());
    }
    for (key, value) in [
        ("maxFindings", json!(30)),
        ("artifactDir", json!(".kuzushi/systems-hunt")),
        ("whiteboxStatic", json!(true)),
        ("triggers", json!([])),
        ("scanScopeRef", json!({})),
        ("maxInvariants", json!(65)),
        ("headBytes", json!(262145)),
    ] {
        let mut input = f.input();
        input[key] = value;
        assert!(f.dispatch(input, &runtime).is_err(), "{key}");
    }
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert_eq!(f.snapshot().committed_calls, 0);
}

#[test]
fn stored_legacy_controls_are_not_silently_consumed() {
    use crate::options::{OptionScope, OptionTarget, ToolOptionStore};
    let f = Fixture::new();
    f.approve(2);
    let runtime = OfflineRuntime::new(&answer().to_string());
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
        assert!(format!("{error:#}").contains("unsupported by standalone invariant drafts"));
    }
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn omitted_surfaces_and_literal_whitespace_paths_remain_honest() {
    let f = Fixture::new();
    f.approve(2);
    fs::rename(
        f.root.path().join("owned.c"),
        f.root.path().join(" owned.c "),
    )
    .unwrap();
    let runtime = OfflineRuntime::new(&answer().to_string());
    let mut input = f.input();
    input["context"]["surfaces"][0]["filePath"] = json!(" owned.c ");
    // The literal trailing space is preserved, including its extension. It is not a supported systems path.
    assert!(f.dispatch(input, &runtime).is_err());
    fs::rename(
        f.root.path().join(" owned.c "),
        f.root.path().join(" owned.c"),
    )
    .unwrap();
    let mut input = f.input();
    input["context"]["surfaces"][0]["filePath"] = json!(" owned.c");
    let mut missing = input["context"]["surfaces"][0].clone();
    missing["id"] = json!("omitted");
    missing["filePath"] = json!("absent.c");
    input["context"]["surfaces"]
        .as_array_mut()
        .unwrap()
        .push(missing);
    let result = f.dispatch(input, &runtime).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(
        result["data"]["inspection"]["omittedSurfaces"][0]["id"],
        "omitted"
    );
    assert_eq!(
        result["data"]["frozenInput"]["sources"][0]["path"],
        " owned.c"
    );
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn actual_bounded_context_is_consumed_without_implicit_gathering_or_acceptance() {
    let f = Fixture::new();
    f.approve(2);
    fs::write(
        f.root.path().join("owned.c"),
        "// owned_input guard memcpy lexical metadata, never executed.\n",
    )
    .unwrap();
    let gathered = gather_bounded_context(f.root.path(), &json!({}), &f.ctx()).unwrap();
    let id = gathered["data"]["surfaces"][0]["id"].as_str().unwrap();
    let mut response = answer();
    response["invariants"][0]["surfaceId"] = json!(id);
    let runtime = OfflineRuntime::new(&response.to_string());
    let mut input = f.input();
    input["context"] = gathered["data"].clone();
    input["reasoningEffort"] = json!("low");
    let result = f.dispatch(input, &runtime).unwrap();
    assert_ne!(result["status"], "failed");
    assert_eq!(result["data"]["invariants"][0]["surfaceId"], id);
    assert_eq!(
        runtime.requests.lock().unwrap()[0]
            .thinking_level
            .as_deref(),
        Some("low")
    );
    assert_eq!(result["data"]["accepted"], false);
}

#[test]
fn canceled_paid_work_retains_inputs_without_valid_drafts() {
    let f = Fixture::new();
    f.approve(2);
    let cancellation = Arc::new(crate::scan::ScanCancellation::default());
    let mut runtime = OfflineRuntime::new(&answer().to_string());
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
    assert_eq!(result["data"]["invariants"], json!([]));
    assert_eq!(result["data"]["inputDocument"]["schemaVersion"], 1);
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(f.snapshot().committed_calls, 1);
}

#[test]
fn source_drift_marks_success_partial_and_oversized_output_is_not_repaired() {
    let f = Fixture::new();
    f.approve(3);
    let mut runtime = OfflineRuntime::new(&answer().to_string());
    runtime.mutate_after = Some(f.root.path().join("owned.c"));
    let result = f.dispatch(f.input(), &runtime).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["sourceCheckCurrent"], false);
    let runtime = OfflineRuntime::new(&"x".repeat(64 * 1024 + 1));
    let result = f.dispatch(f.input(), &runtime).unwrap();
    assert_eq!(result["status"], "failed");
    assert_eq!(result["data"]["rawAgentTextTruncated"], true);
    assert!(result["data"]["rawAgentOutput"].is_null());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn excessive_distinct_drafts_and_oversized_structured_responses_are_rejected() {
    let f = Fixture::new();
    f.approve(2);
    let mut response = answer();
    let mut second = response["invariants"][0].clone();
    second["id"] = json!("different-id");
    response["invariants"].as_array_mut().unwrap().push(second);
    let runtime = OfflineRuntime::new(&response.to_string());
    let mut input = f.input();
    input["max_invariants"] = json!(1);
    let result = f.dispatch(input, &runtime).unwrap();
    assert_eq!(result["status"], "failed");
    assert!(result["output"].as_str().unwrap().contains("draft limit"));
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    let excessive = AgentQueryResponse {
        structured: Some(json!({"invariants":[],"oversized":"x".repeat(64 * 1024)})),
        ..Default::default()
    };
    assert!(response::raw_value(&excessive).is_err());
}

#[cfg(unix)]
#[test]
fn symlink_sources_are_omitted_without_reading_external_material() {
    let f = Fixture::new();
    f.approve(2);
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.c"), "outside_owned_sentinel").unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("secret.c"),
        f.root.path().join("linked.c"),
    )
    .unwrap();
    let mut input = f.input();
    let mut linked = input["context"]["surfaces"][0].clone();
    linked["id"] = json!("linked-surface");
    linked["filePath"] = json!("linked.c");
    input["context"]["surfaces"]
        .as_array_mut()
        .unwrap()
        .push(linked);
    let runtime = OfflineRuntime::new(&answer().to_string());
    let result = f.dispatch(input, &runtime).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(
        result["data"]["inspection"]["omittedSurfaces"][0]["id"],
        "linked-surface"
    );
    assert!(!runtime.requests.lock().unwrap()[0]
        .prompt
        .contains("outside_owned_sentinel"));
}

#[test]
fn default_bounded_producer_hands_many_source_files_to_one_draft_request() {
    let f = Fixture::new();
    f.approve(2);
    for index in 0..64 {
        let mut text = String::from("pub fn parse_frame(owned_input: &[u8]) -> Option<&[u8]> {\n    let packet = owned_input;\n");
        for guard in 0..16 {
            text.push_str(&format!("    let frame_segment_length_guard_{guard} = packet.get(0..packet.len()).filter(|frame| frame.len().checked_add(0).is_some());\n"));
        }
        text.push_str("    packet.get(..)\n}\n");
        fs::write(f.root.path().join(format!("parser_{index:02}.rs")), text).unwrap();
    }
    let gathered = gather_bounded_context(f.root.path(), &json!({}), &f.ctx()).unwrap();
    let bytes = serde_json::to_vec(&gathered["data"]).unwrap().len();
    eprintln!(
        "default producer handoff: {bytes} bytes, {} surfaces",
        gathered["data"]["surfaces"].as_array().unwrap().len()
    );
    assert!(bytes > 128 * 1024);
    let id = gathered["data"]["surfaces"][0]["id"].as_str().unwrap();
    let mut response = answer();
    response["invariants"][0]["surfaceId"] = json!(id);
    let runtime = OfflineRuntime::new(&response.to_string());
    let mut input = f.input();
    input["context"] = gathered["data"].clone();
    let result = f.dispatch(input, &runtime).unwrap();
    assert_ne!(result["status"], "failed");
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(result["data"]["accepted"], false);
    assert_eq!(result["data"]["inspection"]["suppliedSurfaces"], 50);
    assert_eq!(result["data"]["inspection"]["omittedSurfacePacks"], 50);
    let frozen = &result["data"]["frozenInput"];
    let anchors = frozen["surfaces"].as_array().unwrap();
    assert!(!anchors.is_empty() && anchors.len() <= 24);
    assert!(anchors
        .iter()
        .all(|anchor| anchor.as_object().unwrap().len() == 3));
    assert!(serde_json::to_vec(frozen).unwrap().len() <= 80 * 1024);
    assert!(frozen["sources"][0]["text"]
        .as_str()
        .unwrap()
        .contains("checked_add"));
    assert_eq!(f.snapshot().committed_calls, 1);
}

#[test]
fn caller_annotation_bulk_does_not_enter_frozen_model_input() {
    let f = Fixture::new();
    f.approve(2);
    let mut input = f.input();
    input["context"]["surfaces"][0]["reasons"] = json!(["caller-only-marker".repeat(10_000)]);
    let runtime = OfflineRuntime::new(&answer().to_string());
    let result = f.dispatch(input, &runtime).unwrap();
    let frozen = result["data"]["frozenInput"].to_string();
    assert!(!frozen.contains("caller-only-marker"));
    assert!(frozen.contains("owned_input"));
    assert!(result["data"]["inputDocument"]["text"]
        .as_str()
        .unwrap()
        .contains("Lexical annotations"));
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn excessive_supplied_surface_count_fails_before_transport() {
    let f = Fixture::new();
    f.approve(2);
    let mut input = f.input();
    let surface = input["context"]["surfaces"][0].clone();
    input["context"]["surfaces"] = json!((0..1001)
        .map(|index| {
            let mut surface = surface.clone();
            surface["id"] = json!(format!("surface-{index}"));
            surface
        })
        .collect::<Vec<_>>());
    let runtime = OfflineRuntime::new(&answer().to_string());
    let error = f.dispatch(input, &runtime).unwrap_err();
    assert!(format!("{error:#}").contains("1..1000 surfaces"));
    assert!(runtime.requests.lock().unwrap().is_empty());
}
