use super::*;

#[derive(Clone, Default)]
struct SourceChangingRuntime {
    inner: OfflineContextRuntime,
}

impl AgentRuntime for SourceChangingRuntime {
    fn with_allowance_binding(
        &self,
        binding: AllowanceBinding,
    ) -> Result<Box<dyn AgentRuntime + '_>> {
        let mut runtime = self.clone();
        runtime.inner.binding = Some(binding);
        Ok(Box::new(runtime))
    }

    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        let response = self.inner.query_blocking(request.clone())?;
        std::fs::write(
            request.cwd.join("main.rs"),
            "// Owned changed greeting fixture. Never executed.\nfn main() {}\n",
        )?;
        Ok(response)
    }

    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
        unreachable!()
    }
}

#[test]
fn changed_source_preserves_original_context_identity_and_marks_run_partial() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("main.rs"),
        "fn main() { println!(\"hello\"); }\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let trace = crate::run_artifacts::TraceHandle::jsonl(root.path(), "changing-context");
    let mut ctx = context(&workspace, &config);
    ctx.trace = Some(&trace);
    let registry = ModuleRegistry::with_v2_builtins();
    draft(&registry, &ctx, json!({})).unwrap();
    let receipt = load_context_study(root.path(), "context-draft").unwrap();
    approve(&registry, &ctx, approval(&receipt)).unwrap();
    let allowance = receipt.load_allowance(root.path()).unwrap().unwrap();
    let original = crate::incremental_index::current_workspace_tree_hash(root.path()).unwrap();
    let prepared = registry
        .prepare_dispatch_input(TOOL, receipt.bound_input(&allowance).unwrap(), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let runtime = SourceChangingRuntime::default();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
        .unwrap();
    assert_eq!(result["status"], "partial", "{result}");
    assert_eq!(result["data"]["treeHash"], original);
    assert!(result["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|w| w.as_str().unwrap().contains("source changed")));
    let reference: crate::ThreatModelRef =
        serde_json::from_value(result["data"]["modelRef"].clone()).unwrap();
    let inspected = registry
        .execute_tool(
            "threat-model:read",
            json!({"threatModelRef":reference}),
            &ctx,
        )
        .unwrap();
    assert_eq!(
        inspected["data"]["document"]["provenance"]["treeHash"],
        original
    );
    assert_eq!(inspected["data"]["sourceState"]["status"], "drifted");
    assert!(inspected["data"]["document"].get("verification").is_none());
    assert_eq!(runtime.inner.requests.lock().unwrap().len(), 1);
    assert_eq!(
        receipt
            .load_allowance(root.path())
            .unwrap()
            .unwrap()
            .committed_calls,
        1
    );
    assert!(
        crate::capabilities::threat_model::load_active_threat_model(root.path())
            .unwrap()
            .is_none()
    );
}
