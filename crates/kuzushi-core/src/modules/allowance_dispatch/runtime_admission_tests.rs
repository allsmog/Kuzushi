use super::tests::{approval, context};
use super::*;
use crate::{AgentQueryRequest, AgentQueryResponse, V2Config, WorkspaceTarget};
use std::sync::atomic::{AtomicUsize, Ordering};

mod inherited_category;
mod inherited_receipt;
mod repository_preparation;

const MODEL: &str = "openai-codex:gpt-5.5";

#[derive(Clone, Default)]
struct AccountingRuntime {
    binding: Option<AllowanceBinding>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl AgentRuntime for AccountingRuntime {
    fn allowance_binding(&self) -> Option<&AllowanceBinding> {
        self.binding.as_ref()
    }

    fn with_allowance_binding(
        &self,
        binding: AllowanceBinding,
    ) -> Result<Box<dyn AgentRuntime + '_>> {
        if let Some(existing) = &self.binding {
            existing.require_same_work(&binding)?;
        }
        Ok(Box::new(Self {
            binding: Some(binding),
            calls: Arc::clone(&self.calls),
        }))
    }

    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        let binding = self
            .binding
            .as_ref()
            .context("test request is not accounted")?;
        let reservation = binding.reserve(&request.model)?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        binding.settle(
            reservation,
            crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO),
        )?;
        Ok(AgentQueryResponse {
            text: "Owned accounting fixture".into(),
            cost_usd_reported: true,
            ..Default::default()
        })
    }

    fn triage_finding_blocking(&self, _: crate::TriageRequest) -> Result<crate::TriageOutcome> {
        panic!("refused work must not reach the triage runtime")
    }
}

fn approve_context(ctx: &ToolExecutionContext<'_>) {
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input("campaign:approve-allowance", approval(), ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, ctx, None)
        .unwrap();
}

fn bound_runtime(ctx: &ToolExecutionContext<'_>, runtime: &AccountingRuntime) -> AccountingRuntime {
    AccountingRuntime {
        binding: Some(
            AllowanceBinding::new(
                open_ledger(ctx).unwrap(),
                AllowanceWork {
                    investigation_id: "study".into(),
                    revision: 1,
                    work_id: "pass-1".into(),
                    run_id: "parent-approved-work".into(),
                    model: MODEL.into(),
                    work: InvestigationWork::Context,
                },
            )
            .unwrap(),
        ),
        calls: Arc::clone(&runtime.calls),
    }
}

fn assert_allowance_refused(error: anyhow::Error) {
    assert_eq!(
        crate::runtime::runtime_failure_metadata(&error)
            .unwrap()
            .error_class,
        crate::RuntimeFailureClass::AllowanceRefused,
        "{error:#}"
    );
}

#[test]
fn zero_call_approval_refuses_model_tools_before_the_runtime_is_called() {
    let (_root, workspace, config) = fixture();
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    let mut input = approval();
    input["maxProviderCalls"] = json!(0);
    input["protectedReviewCalls"] = json!(0);
    let prepared = registry
        .prepare_dispatch_input("campaign:approve-allowance", input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    let runtime = bound_runtime(&ctx, &AccountingRuntime::default());
    for tool in ["context:build", "threat-model:build", "triage:run"] {
        let descriptor = registry.resolve_tool(tool).unwrap();
        let error = bind_runtime(
            descriptor,
            &json!({"enrichment":true}),
            &ctx,
            Some(&runtime),
        )
        .err()
        .unwrap();
        assert_allowance_refused(error);
    }
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    let snapshot = open_ledger(&ctx)
        .unwrap()
        .allowance_snapshot("study")
        .unwrap();
    assert_eq!(snapshot.committed_calls, 0);
    assert_eq!(snapshot.unresolved_calls, 0);
}

#[test]
fn unbound_model_tools_refuse_before_executor_or_ledger_creation() {
    let (root, workspace, config) = fixture();
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    for (tool, input) in [
        ("context:build", json!({"enrichment":true})),
        ("threat-model:build", json!({})),
        ("triage:run", json!({"strategy":"standard"})),
    ] {
        let prepared = registry
            .prepare_dispatch_input(tool, input, &ctx, None)
            .unwrap()
            .authorize_explicit_headless();
        let runtime = AccountingRuntime::default();
        let error = registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("approved investigation allowance"),
            "{tool}: {error:#}"
        );
        assert_allowance_refused(error);
        assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    }
    assert!(!workspace.findings_db_path().exists());
    assert!(!root.path().join(".kuzushi/context.json").exists());
}

#[test]
fn supplied_runtime_does_not_make_deterministic_context_model_backed() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("note.md"), "Owned inert source.").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    let runtime = AccountingRuntime::default();
    let prepared = registry
        .prepare_dispatch_input("context:build", json!({"enrichment":false}), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
        .unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn nested_work_keeps_its_existing_allowance_and_reserves_only_provider_calls() {
    let (_root, workspace, config) = fixture();
    let ctx = context(&workspace, &config);
    approve_context(&ctx);
    let runtime = bound_runtime(&ctx, &AccountingRuntime::default());
    let registry = ModuleRegistry::with_v2_builtins();
    let descriptor = registry.resolve_tool("context:build").unwrap();
    for _ in 0..2 {
        let inherited = bind_runtime(
            descriptor,
            &json!({"enrichment":true}),
            &ctx,
            Some(&runtime),
        )
        .unwrap();
        assert!(
            inherited.is_none(),
            "nested work keeps the existing wrapper"
        );
        query_fixture(&runtime, workspace.root());
    }
    let snapshot = open_ledger(&ctx)
        .unwrap()
        .allowance_snapshot("study")
        .unwrap();
    assert_eq!(snapshot.committed_calls, 2);
    assert_eq!(snapshot.review_calls, 0);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 2);
    assert_allowance_refused(
        bind_runtime(
            descriptor,
            &json!({"enrichment":true}),
            &ctx,
            Some(&runtime),
        )
        .err()
        .unwrap(),
    );
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn inherited_accounting_cannot_cross_workspaces_or_switch_models() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(first.path()).unwrap();
    let other = WorkspaceTarget::new(second.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let ctx = context(&workspace, &config);
    approve_context(&ctx);
    let other_ctx = context(&other, &config);
    approve_context(&other_ctx);
    let runtime = bound_runtime(&ctx, &AccountingRuntime::default());
    let registry = ModuleRegistry::with_v2_builtins();
    let descriptor = registry.resolve_tool("context:build").unwrap();
    assert_allowance_refused(
        bind_runtime(
            descriptor,
            &json!({"enrichment":true}),
            &other_ctx,
            Some(&runtime),
        )
        .err()
        .unwrap(),
    );
    assert_allowance_refused(
        bind_runtime(
            descriptor,
            &json!({"enrichment":true,"model":"openai-codex:other"}),
            &ctx,
            Some(&runtime),
        )
        .err()
        .unwrap(),
    );
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn routing_and_trace_wrappers_preserve_inherited_accounting_without_spend() {
    let (root, workspace, config) = fixture();
    let ctx = context(&workspace, &config);
    approve_context(&ctx);
    let runtime = bound_runtime(&ctx, &AccountingRuntime::default());
    let handle = crate::agent_router::RuntimeHandle::Borrowed(&runtime);
    let routed = crate::agent_router::RoutedRuntime::borrowed(
        &runtime,
        Arc::new(crate::agent_router::AgentRouter::empty()),
        Some(MODEL.into()),
    );
    let observation =
        crate::run_lifecycle::RunObservationHandle::jsonl(root.path(), "parent-approved-work")
            .unwrap();
    let traced = crate::runtime::TracedRuntime::new(&routed, observation.trace_handle());
    let registry = ModuleRegistry::with_v2_builtins();
    let descriptor = registry.resolve_tool("context:build").unwrap();
    for wrapper in [&runtime as &dyn AgentRuntime, &handle, &routed, &traced] {
        assert_eq!(
            wrapper.allowance_binding().unwrap().work(),
            runtime.binding.as_ref().unwrap().work()
        );
        assert!(
            bind_runtime(descriptor, &json!({"enrichment":true}), &ctx, Some(wrapper))
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(
        open_ledger(&ctx)
            .unwrap()
            .allowance_snapshot("study")
            .unwrap()
            .committed_calls,
        0
    );
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn inherited_runtime_refuses_a_changed_approval_revision_before_spend() {
    let (_root, workspace, config) = fixture();
    let ctx = context(&workspace, &config);
    approve_context(&ctx);
    let runtime = bound_runtime(&ctx, &AccountingRuntime::default());
    let registry = ModuleRegistry::with_v2_builtins();
    let mut changed = approval();
    changed["expectedRevision"] = json!(1);
    changed["maxProviderCalls"] = json!(4);
    let prepared = registry
        .prepare_dispatch_input("campaign:approve-allowance", changed, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    let descriptor = registry.resolve_tool("context:build").unwrap();
    assert_allowance_refused(
        bind_runtime(
            descriptor,
            &json!({"enrichment":true}),
            &ctx,
            Some(&runtime),
        )
        .err()
        .unwrap(),
    );
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}

fn fixture() -> (tempfile::TempDir, WorkspaceTarget, V2Config) {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    (root, workspace, config)
}

fn query_fixture(runtime: &AccountingRuntime, root: &std::path::Path) {
    runtime
        .query_blocking(AgentQueryRequest::new(
            MODEL,
            root,
            "Owned fixture",
            "Validate existing accounting",
        ))
        .unwrap();
}
