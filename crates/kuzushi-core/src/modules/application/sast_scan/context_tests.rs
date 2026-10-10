use super::*;
use crate::capabilities::threat_model::{commit_test_model, load_active_threat_model};
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, TriageRequest};
use crate::{V2Config, WorkspaceTarget};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Default)]
struct RecordingContextRuntime {
    captured: Mutex<Vec<String>>,
    change_source: Option<PathBuf>,
}

impl AgentRuntime for RecordingContextRuntime {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        if let Some(path) = &self.change_source {
            std::fs::write(path, "pub fn changed_during_scan() {}\n")?;
        }
        let mut context = decoded_derived_context(&request.prompt);
        for attachment in &request.tool_policy.mcps_attached {
            if attachment.name == "threat-model" {
                context.push_str(&std::fs::read_to_string(&attachment.artifact_path).unwrap());
            }
        }
        self.captured.lock().unwrap().push(context);
        Ok(AgentQueryResponse {
            structured: Some(json!({"findings": []})),
            cost_usd_reported: true,
            ..Default::default()
        })
    }

    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<crate::findings::TriageOutcome> {
        panic!("discovery context test must not invoke triage")
    }
}

fn decoded_derived_context(prompt: &str) -> String {
    use crate::runbooks::untrusted::{
        decode_untrusted_record, UNTRUSTED_DERIVED_BEGIN, UNTRUSTED_DERIVED_END,
    };
    let mut remaining = prompt;
    let mut content = Vec::new();
    while let Some(start) = remaining.find(UNTRUSTED_DERIVED_BEGIN) {
        let frame = &remaining[start..];
        let end = frame.find(UNTRUSTED_DERIVED_END).unwrap() + UNTRUSTED_DERIVED_END.len();
        content.push(decode_untrusted_record(&frame[..end]).unwrap().content);
        remaining = &frame[end..];
    }
    content.join("\n")
}

struct ContextFixture {
    root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    store: FindingStore,
    config: V2Config,
    registry: ModuleRegistry,
}

impl ContextFixture {
    fn new(source: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("lib.rs"), source).unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config {
            model: Some("openai:gpt-5.5".into()),
            ..Default::default()
        };
        Self {
            root,
            workspace,
            store,
            config,
            registry: ModuleRegistry::with_v2_builtins(),
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

    fn run(&self, input: Value, runtime: &RecordingContextRuntime) -> Value {
        self.registry
            .execute_tool_with_runtime("sast:scan", input, &self.ctx(), Some(runtime))
            .unwrap()
    }

    fn equivalence(&self, input: &Value) -> crate::capabilities::campaign::BatchEquivalenceKey {
        crate::capabilities::campaign::capture_batch_equivalence(
            self.root.path(),
            input,
            &self.config,
            &self.registry,
        )
        .unwrap()
    }

    fn write_context(&self, note: &str) {
        let tree = crate::incremental_index::current_workspace_tree_hash(self.root.path()).unwrap();
        let path = crate::context::context_snapshot_path(self.root.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let snapshot = json!({"target":self.root.path(), "provenance":{"treeHash":tree}, "enrichedContext":{"architecturalNotes":[{"note":note}]}});
        std::fs::write(path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    }
}

fn discovery_input(reference: Value) -> Value {
    json!({"taskMode":"manual", "tasks":["agentic-sast"], "threatModelRef":reference,
        "triage":false, "verify":false, "autoPatch":false})
}

fn assert_prompt_context(runtime: &RecordingContextRuntime, expected: &str, omitted: &str) {
    let prompts = runtime.captured.lock().unwrap();
    assert!(!prompts.is_empty());
    assert!(
        prompts.iter().all(|prompt| prompt.contains(expected)),
        "{prompts:#?}"
    );
    assert!(
        prompts.iter().all(|prompt| !prompt.contains(omitted)),
        "{prompts:#?}"
    );
}

fn assert_observation_snapshot(root: &std::path::Path, output: &Value) {
    let run = output["data"]["runId"].as_str().unwrap();
    let (_, text) = crate::run_artifacts::read_run_artifact_text(root, run, "findings.json")
        .require("discovery observations")
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap(),
        output["data"]["coreFindings"]
    );
}

fn assert_active_context(root: &std::path::Path, expected: &crate::ThreatModelRef) {
    assert_eq!(
        &load_active_threat_model(root).unwrap().unwrap().model_ref,
        expected
    );
}

#[test]
fn sast_dispatch_consumes_frozen_supporting_context_after_live_edits() {
    let fixture = ContextFixture::new("pub fn greeting() {}\n");
    fixture.write_context("FROZEN_SUPPORTING_CONTEXT");
    let mut input = discovery_input(Value::Null);
    crate::scan::freeze_scan_context(fixture.root.path(), &mut input).unwrap();
    let before = fixture.equivalence(&input);
    fixture.write_context("LATER_SUPPORTING_CONTEXT");
    assert_eq!(before, fixture.equivalence(&input));
    let runtime = RecordingContextRuntime::default();
    let output = fixture.run(input, &runtime);
    assert_eq!(output["status"], "completed", "{output}");
    assert_prompt_context(
        &runtime,
        "FROZEN_SUPPORTING_CONTEXT",
        "LATER_SUPPORTING_CONTEXT",
    );
}

#[test]
fn sast_dispatch_consumes_each_selected_revision_without_changing_the_active_model() {
    let fixture = ContextFixture::new("pub fn service() {}\n");
    let first = commit_test_model(fixture.root.path(), "ACCEPTED_CONTEXT_ALPHA");
    let second = commit_test_model(fixture.root.path(), "ACCEPTED_CONTEXT_BETA");
    let cases = [
        (
            json!(first),
            "ACCEPTED_CONTEXT_ALPHA",
            "ACCEPTED_CONTEXT_BETA",
        ),
        (
            json!(second),
            "ACCEPTED_CONTEXT_BETA",
            "ACCEPTED_CONTEXT_ALPHA",
        ),
        (Value::Null, "", "ACCEPTED_CONTEXT_"),
    ];
    for (reference, expected, omitted) in cases {
        let runtime = RecordingContextRuntime::default();
        let output = fixture.run(discovery_input(reference.clone()), &runtime);
        assert_eq!(output["status"], "completed", "{output:#}");
        let run_id = output["data"]["runId"].as_str().unwrap();
        let summary = crate::run_artifacts::load_run_summary(fixture.root.path(), run_id).unwrap();
        assert_eq!(
            summary.threat_model_sha256,
            reference
                .get("sha256")
                .and_then(Value::as_str)
                .map(str::to_owned)
        );
        assert_observation_snapshot(fixture.root.path(), &output);
        assert_eq!(output["data"]["treeHash"].as_str().unwrap().len(), 64);
        assert_prompt_context(&runtime, expected, omitted);
        assert_active_context(fixture.root.path(), &second);
    }
}

#[test]
fn source_drift_keeps_the_start_identity_and_partial_observation_snapshot() {
    let fixture = ContextFixture::new("pub fn before_scan() {}\n");
    let before =
        crate::incremental_index::current_workspace_tree_hash(fixture.root.path()).unwrap();
    let runtime = RecordingContextRuntime {
        change_source: Some(fixture.root.path().join("lib.rs")),
        ..Default::default()
    };
    let output = fixture.run(discovery_input(Value::Null), &runtime);
    assert_eq!(output["status"], "partial", "{output}");
    assert_eq!(output["data"]["treeHash"], before);
    assert!(output["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning.as_str().unwrap().contains("source changed")));
    let run_id = output["data"]["runId"].as_str().unwrap();
    assert_eq!(
        crate::run_artifacts::load_run_summary(fixture.root.path(), run_id)
            .unwrap()
            .status,
        "partial"
    );
    assert_observation_snapshot(fixture.root.path(), &output);
}

#[test]
fn selected_context_options_survive_sast_engine_preparation() {
    let root = tempfile::tempdir().unwrap();
    let reference = commit_test_model(root.path(), "selected-context");
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    for name in [
        "agentic-sast:scan",
        "offense-review:threat-hunt",
        "carlini-threat-hunt:run",
        "taint-iris-next:hunt",
        "systems-hunt:systems-hunt",
        "triage:run",
    ] {
        let input = registry
            .prepare_tool_input_for_dispatch(
                name,
                json!({"threat_model_ref": reference}),
                &ctx,
                None,
            )
            .unwrap();
        assert_eq!(input["threatModelRef"], json!(reference), "{name}");
    }
}
