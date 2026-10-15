use crate::modules::trace::run_trace_expand;
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime};
use crate::{FindingStore, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::json;

#[test]
fn cancellation_after_a_response_prevents_static_evidence_publication() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("hello.txt"),
        "Owned greeting. Never executed.\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let finding = crate::findings::Finding::new_tool(
        "owned-fixture",
        "greeting",
        "hello.txt",
        1,
        None,
        crate::findings::Severity::Info,
        "Labeled greeting observation. No defect is claimed.",
    );
    store
        .record_run_started("owned-observation", root.path(), "running")
        .unwrap();
    store.insert_finding("owned-observation", &finding).unwrap();
    let config = V2Config {
        model: Some("openai:gpt-4.1".into()),
        ..Default::default()
    };
    let cancel = crate::scan::ScanCancellation::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: Some(&cancel),
        authorization: Default::default(),
    };
    let result = run_trace_expand(
        json!({"fingerprint":finding.fingerprint}),
        &ctx,
        Some(&CancelingRuntime(cancel.clone())),
    );
    assert!(result.is_err());
    let evidence = crate::static_evidence::StaticEvidenceStore::open(&workspace).unwrap();
    assert!(evidence
        .list_nodes_for_finding(&finding.fingerprint)
        .unwrap()
        .is_empty());
}

struct CancelingRuntime(crate::scan::ScanCancellation);
impl AgentRuntime for CancelingRuntime {
    fn query_blocking(&self, _: AgentQueryRequest) -> anyhow::Result<AgentQueryResponse> {
        self.0.cancel();
        Ok(AgentQueryResponse {
            structured: Some(json!({"version":1,"findingFingerprint":"ignored",
            "steps":[{"symbol":"Owned greeting claim","filePath":"hello.txt","line":1,
                "annotation":"Labeled synthetic source claim. No defect is asserted."}],
            "openQuestions":[],"evidenceDeltas":[]})),
            ..Default::default()
        })
    }
    fn triage_finding_blocking(
        &self,
        _: crate::runtime::TriageRequest,
    ) -> anyhow::Result<crate::findings::TriageOutcome> {
        anyhow::bail!("Owned cancellation fixture forbids triage")
    }
}
