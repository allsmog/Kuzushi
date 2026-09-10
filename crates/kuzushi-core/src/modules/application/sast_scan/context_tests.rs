use super::*;
use crate::{V2Config, WorkspaceTarget};
use crate::capabilities::threat_model::{commit_test_model, load_active_threat_model};
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, TriageRequest};
use std::sync::Mutex;

#[derive(Default)]
struct RecordingContextRuntime(Mutex<Vec<String>>);

impl AgentRuntime for RecordingContextRuntime {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        let mut context = decoded_derived_context(&request.prompt);
        for attachment in &request.tool_policy.mcps_attached {
            if attachment.name == "threat-model" {
                context.push_str(&std::fs::read_to_string(&attachment.artifact_path).unwrap());
            }
        }
        self.0.lock().unwrap().push(context);
        Ok(AgentQueryResponse {
            structured: Some(json!({"findings": []})), cost_usd_reported: true,
            ..Default::default()
        })
    }

    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<crate::findings::TriageOutcome> {
        panic!("discovery context test must not invoke triage")
    }
}

fn decoded_derived_context(prompt: &str) -> String {
    use crate::runbooks::untrusted::{decode_untrusted_record, UNTRUSTED_DERIVED_BEGIN, UNTRUSTED_DERIVED_END};
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

#[test]
fn sast_dispatch_consumes_each_selected_revision_without_changing_the_active_model() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("lib.rs"), "pub fn service() {}\n").unwrap();
    let first = commit_test_model(root.path(), "ACCEPTED_CONTEXT_ALPHA");
    let second = commit_test_model(root.path(), "ACCEPTED_CONTEXT_BETA");
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = V2Config { model: Some("openai:gpt-5.5".to_string()), ..Default::default() };
    let ctx = ToolExecutionContext { config: &config, workspace: Some(&workspace), findings_store: Some(&store),
        trace: None, cancellation: None, authorization: Default::default() };
    let registry = ModuleRegistry::with_v2_builtins();
    for (reference, expected, omitted) in [
        (json!(first), "ACCEPTED_CONTEXT_ALPHA", "ACCEPTED_CONTEXT_BETA"),
        (json!(second), "ACCEPTED_CONTEXT_BETA", "ACCEPTED_CONTEXT_ALPHA"),
        (Value::Null, "", "ACCEPTED_CONTEXT_"),
    ] {
        let runtime = RecordingContextRuntime::default();
        let output = registry.execute_tool_with_runtime("sast:scan", json!({
            "taskMode": "manual", "tasks": ["agentic-sast"], "threatModelRef": reference,
            "triage": false, "verify": false, "autoPatch": false
        }), &ctx, Some(&runtime)).unwrap();
        assert_eq!(output["status"], "completed", "{output:#}");
        let prompts = runtime.0.lock().unwrap();
        assert!(!prompts.is_empty());
        assert!(prompts.iter().all(|prompt| prompt.contains(expected)), "{prompts:#?}");
        assert!(prompts.iter().all(|prompt| !prompt.contains(omitted)), "{prompts:#?}");
        assert_eq!(load_active_threat_model(root.path()).unwrap().unwrap().model_ref, second);
    }
}

#[test]
fn selected_context_options_survive_sast_engine_preparation() {
    let root = tempfile::tempdir().unwrap();
    let reference = commit_test_model(root.path(), "selected-context");
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext { config: &config, workspace: Some(&workspace), findings_store: None,
        trace: None, cancellation: None, authorization: Default::default() };
    let registry = ModuleRegistry::with_v2_builtins();
    for name in ["agentic-sast:scan", "offense-review:threat-hunt", "carlini-threat-hunt:run", "taint-iris-next:hunt", "systems-hunt:systems-hunt", "triage:run"] {
        let input = registry.prepare_tool_input_for_dispatch(name, json!({"threat_model_ref": reference}), &ctx, None).unwrap();
        assert_eq!(input["threatModelRef"], json!(reference), "{name}");
    }
}
