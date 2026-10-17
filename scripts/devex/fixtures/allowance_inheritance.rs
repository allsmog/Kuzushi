//! Owned refusal fixture. No model transport, target execution or new jobs.
use anyhow::{Context, Result};
use kuzushi_core::allowance::{
    AllowanceApprovalV1, AllowanceBinding, AllowanceLimits, AllowanceWork, InvestigationWork,
};
use kuzushi_core::run_artifacts::{
    record_tool_run_started, try_record_tool_run_failed_settled, ToolRunRecord, TraceHandle,
};
use kuzushi_core::{
    AgentQueryRequest, AgentQueryResponse, AgentRuntime, ModuleRegistry, SpendLimiter,
    ToolExecutionContext, TriageOutcome, TriageRequest, V2Config, WorkspaceTarget,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

const MODEL: &str = "openai-codex:gpt-5.5";
const RUN: &str = "owned-inherited-context";
const INVESTIGATION: &str = "owned-inherited";

struct RefusalRuntime {
    binding: AllowanceBinding,
    queries: AtomicUsize,
}
impl AgentRuntime for RefusalRuntime {
    fn allowance_binding(&self) -> Option<&AllowanceBinding> {
        Some(&self.binding)
    }
    fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("Owned fixture forbids provider transport")
    }
    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
        anyhow::bail!("Owned fixture forbids triage")
    }
}

fn approve(workspace: &WorkspaceTarget) -> Result<Arc<SpendLimiter>> {
    workspace.ensure_state_dir()?;
    let ledger = Arc::new(SpendLimiter::open(&workspace.findings_db_path())?);
    ledger.approve_allowance(&AllowanceApprovalV1 {
        schema_version: 1,
        investigation_id: INVESTIGATION.into(),
        expected_revision: 0,
        model: MODEL.into(),
        limits: AllowanceLimits {
            max_provider_calls: 1,
            protected_review_calls: 1,
        },
        reason: "Owned parent Review fixture; no model transport or new work.".into(),
        work_plan: None,
    })?;
    Ok(ledger)
}

fn runtime(ledger: Arc<SpendLimiter>) -> Result<RefusalRuntime> {
    Ok(RefusalRuntime {
        binding: AllowanceBinding::new(
            ledger,
            AllowanceWork {
                investigation_id: INVESTIGATION.into(),
                revision: 1,
                work_id: "parent-review".into(),
                run_id: "owned-parent-review".into(),
                model: MODEL.into(),
                work: InvestigationWork::Review,
            },
        )?,
        queries: AtomicUsize::new(0),
    })
}

fn refuse(workspace: &WorkspaceTarget, runtime: &RefusalRuntime) -> Result<()> {
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let trace = TraceHandle::jsonl(workspace.root(), RUN);
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: None,
        trace: Some(&trace),
        cancellation: None,
        authorization: Default::default(),
    };
    let record = ToolRunRecord::new(workspace.root(), RUN, "tool", "context:build");
    let input = "{\"enrichment\":true}".parse()?;
    record_tool_run_started(record, &input);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let prepared = registry
        .prepare_dispatch_input("context:build", input, &ctx, None)?
        .authorize_explicit_headless();
    let dispatched =
        registry.dispatch_prepared_input_observed_with_runtime(prepared, &ctx, Some(runtime))?;
    let error = dispatched
        .execution
        .err()
        .context("Wrong-category child was unexpectedly admitted")?;
    let message = refusal_message(&error)?;
    let observation = ctx.run_observation().context("Missing observation")?;
    try_record_tool_run_failed_settled(record, &message, &observation, dispatched.completion)?;
    observation.flush()?;
    let projection = kuzushi_core::run_lifecycle::load_run_projection(workspace.root(), RUN)?;
    anyhow::ensure!(
        projection.projection.health == kuzushi_core::run_lifecycle::ProjectionHealth::Healthy,
        "Refused work must retain a healthy typed receipt"
    );
    Ok(())
}

fn refusal_message(error: &anyhow::Error) -> Result<String> {
    let metadata = kuzushi_core::runtime::runtime_failure_metadata(error)
        .context("Missing admission failure class")?;
    anyhow::ensure!(
        metadata.error_class == kuzushi_core::RuntimeFailureClass::AllowanceRefused,
        "Wrong refusal class"
    );
    let message = format!("{error:#}");
    anyhow::ensure!(
        message.contains("parent Review allowance"),
        "Unexpected refusal: {message}"
    );
    Ok(message)
}

fn revise(workspace: &WorkspaceTarget) -> Result<()> {
    let ledger = SpendLimiter::open(&workspace.findings_db_path())?;
    ledger.approve_allowance(&AllowanceApprovalV1 {
        schema_version: 1,
        investigation_id: INVESTIGATION.into(),
        expected_revision: 1,
        model: MODEL.into(),
        limits: AllowanceLimits {
            max_provider_calls: 3,
            protected_review_calls: 1,
        },
        reason: "Owned revised grant for read-only history checks. No provider transport.".into(),
        work_plan: None,
    })?;
    let snapshot = ledger.allowance_snapshot(INVESTIGATION)?;
    anyhow::ensure!(snapshot.revision == 2 && snapshot.committed_calls == 0);
    println!("{{\"revision\":2,\"committedCalls\":0,\"liveProviderRequests\":0}}");
    Ok(())
}

fn main() -> Result<()> {
    let root = std::env::args()
        .nth(1)
        .context("Owned target path required")?;
    let workspace = WorkspaceTarget::new(std::path::Path::new(&root))?;
    if let Some(operation) = std::env::args().nth(2) {
        anyhow::ensure!(operation == "revise", "Unknown owned-fixture operation");
        return revise(&workspace);
    }
    let ledger = approve(&workspace)?;
    let runtime = runtime(Arc::clone(&ledger))?;
    refuse(&workspace, &runtime)?;
    let snapshot = ledger.allowance_snapshot(INVESTIGATION)?;
    anyhow::ensure!(
        runtime.queries.load(Ordering::SeqCst) == 0,
        "Provider was reached"
    );
    anyhow::ensure!(
        snapshot.committed_calls == 0
            && snapshot.review_calls == 0
            && snapshot.protected_review_remaining() == 1,
        "Refusal changed parent accounting"
    );
    println!("{{\"runId\":\"{RUN}\",\"investigationId\":\"{INVESTIGATION}\",\"queries\":0,\"projectionHealthy\":true,\"committedCalls\":0,\"protectedReviewRemaining\":1,\"liveProviderRequests\":0}}");
    Ok(())
}
