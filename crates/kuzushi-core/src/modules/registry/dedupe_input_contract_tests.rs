use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime};
use crate::{
    Finding, FindingStore, ModuleRegistry, Severity, ToolExecutionContext, V2Config,
    WorkspaceTarget,
};
use serde_json::json;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Default)]
struct NoQueryRuntime {
    calls: Arc<AtomicUsize>,
    binding: Option<crate::allowance::AllowanceBinding>,
}

impl AgentRuntime for NoQueryRuntime {
    fn allowance_binding(&self) -> Option<&crate::allowance::AllowanceBinding> {
        self.binding.as_ref()
    }

    fn with_allowance_binding(
        &self,
        binding: crate::allowance::AllowanceBinding,
    ) -> anyhow::Result<Box<dyn AgentRuntime + '_>> {
        Ok(Box::new(Self {
            calls: self.calls.clone(),
            binding: Some(binding),
        }))
    }

    fn query_blocking(&self, _: AgentQueryRequest) -> anyhow::Result<AgentQueryResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("No model request is permitted in this test")
    }

    fn triage_finding_blocking(
        &self,
        _: crate::runtime::TriageRequest,
    ) -> anyhow::Result<crate::findings::TriageOutcome> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("No model triage is permitted in this test")
    }
}

fn approve(registry: &ModuleRegistry, ctx: &ToolExecutionContext<'_>) {
    let input = registry.prepare_dispatch_input("campaign:approve-allowance", json!({
        "investigationId":"dedupe-bounds", "expectedRevision":0,"model":ctx.config.model,
        "maxProviderCalls":3,"protectedReviewCalls":2,"reason":"Owned bounded input test; no provider requests"
    }), ctx, None).unwrap().authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(input, ctx, None)
        .unwrap();
}

fn seed(store: &FindingStore, root: &std::path::Path) {
    for name in ["alpha", "beta"] {
        store
            .with_run_lifecycle(name, root, || {
                let finding = Finding::new_tool(
                    name,
                    name,
                    "hello.txt",
                    1,
                    None,
                    Severity::Info,
                    "Labeled source metadata; no security defect claimed",
                );
                store.insert_finding(name, &finding)?;
                Ok(((), 1usize))
            })
            .unwrap();
    }
}

#[test]
fn prepared_dedupe_limits_refuse_before_query_or_reservation_and_keep_findings() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("hello.txt"), "Owned inert greeting.\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    seed(&store, root.path());
    let config = test_config();
    let ctx = execution_context(&config, &workspace, &store);
    let registry = ModuleRegistry::with_v2_builtins();
    approve(&registry, &ctx);
    let runtime = NoQueryRuntime::default();
    for option in [
        "maxLedgerObservations",
        "maxLedgerBytes",
        "maxJudgePromptBytes",
    ] {
        let mut value = json!({"maxEscalations":0,"allowanceRef":{"schemaVersion":1,
            "investigationId":"dedupe-bounds","revision":1,"workId":"dedupe-read"}});
        value[option] = json!(1);
        let input = registry
            .prepare_dispatch_input("triage:dedupe", value, &ctx, None)
            .unwrap()
            .authorize_explicit_headless();
        let result = registry.dispatch_prepared_input_with_runtime(input, &ctx, Some(&runtime));
        assert!(result.is_err(), "{option} must refuse the input");
        assert!(format!("{:#}", result.err().unwrap()).contains(option));
    }
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    let ledger = crate::SpendLimiter::open(workspace.findings_db_path()).unwrap();
    assert_eq!(
        ledger
            .allowance_snapshot("dedupe-bounds")
            .unwrap()
            .committed_calls,
        0
    );
    assert_eq!(store.list_all_findings().unwrap().len(), 2);
}

#[test]
fn dedupe_limits_are_declared_canonical_validated_and_alias_compatible() {
    let registry = ModuleRegistry::with_v2_builtins();
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = test_config();
    let ctx = execution_context(&config, &workspace, &store);
    let value = registry.prepare_dispatch_input("triage:dedupe",
        json!({"max_ledger_observations":2,"max_ledger_bytes":4096,"max_ledger_read_ms":1000,"max_judge_prompt_bytes":8192,"max_confirmation_bytes":1024}), &ctx, None).unwrap();
    for (key, expected) in [
        ("maxLedgerObservations", 2),
        ("maxLedgerBytes", 4096),
        ("maxLedgerReadMs", 1000),
        ("maxJudgePromptBytes", 8192),
        ("maxConfirmationBytes", 1024),
    ] {
        assert_eq!(value.value()[key], json!(expected));
    }
    for (key, maximum) in [
        ("maxLedgerObservations", 100000),
        ("maxLedgerBytes", 134217728),
        ("maxLedgerReadMs", 60000),
        ("maxJudgePromptBytes", 524288),
        ("maxConfirmationBytes", 8388608),
    ] {
        for invalid in [0, maximum + 1] {
            let mut input = json!({});
            input[key] = json!(invalid);
            assert!(registry
                .prepare_dispatch_input("triage:dedupe", input, &ctx, None)
                .is_err());
        }
    }
    assert!(registry
        .prepare_dispatch_input("triage:dedupe", json!({"unknownReadLimit":1}), &ctx, None)
        .is_err());
}

fn test_config() -> V2Config {
    V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    }
}

fn execution_context<'a>(
    config: &'a V2Config,
    workspace: &'a WorkspaceTarget,
    store: &'a FindingStore,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}
