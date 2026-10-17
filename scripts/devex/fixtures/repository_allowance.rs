//! Owned preparation refusals. Provider transport and target execution forbidden.
use anyhow::{Context, Result};
use kuzushi_core::allowance::{AllowanceApprovalV1, AllowanceBinding, AllowanceLimits};
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
const TOOL: &str = "taint-iris-next:codeql-db";
const INVESTIGATION: &str = "owned-db-preparation";

#[derive(Default)]
struct RefusalRuntime {
    binding: Option<AllowanceBinding>,
    queries: Arc<AtomicUsize>,
}

impl AgentRuntime for RefusalRuntime {
    fn allowance_binding(&self) -> Option<&AllowanceBinding> {
        self.binding.as_ref()
    }

    fn with_allowance_binding(
        &self,
        binding: AllowanceBinding,
    ) -> Result<Box<dyn AgentRuntime + '_>> {
        Ok(Box::new(Self {
            binding: Some(binding),
            queries: Arc::clone(&self.queries),
        }))
    }

    fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("Owned fixture forbids provider transport")
    }

    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
        anyhow::bail!("Owned fixture forbids triage")
    }
}

fn approve(workspace: &WorkspaceTarget) -> Result<SpendLimiter> {
    workspace.ensure_state_dir()?;
    let ledger = SpendLimiter::open(&workspace.findings_db_path())?;
    ledger.approve_allowance(&AllowanceApprovalV1 {
        schema_version: 1,
        investigation_id: INVESTIGATION.into(),
        expected_revision: 0,
        model: MODEL.into(),
        limits: AllowanceLimits {
            max_provider_calls: 2,
            protected_review_calls: 1,
        },
        reason: "Owned refusal fixture; no provider transport or target build.".into(),
        work_plan: None,
    })?;
    Ok(ledger)
}

fn refuse(
    workspace: &WorkspaceTarget,
    runtime: &RefusalRuntime,
    run: &str,
    execution_consent: bool,
) -> Result<()> {
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let trace = TraceHandle::jsonl(workspace.root(), run);
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: None,
        trace: Some(&trace),
        cancellation: None,
        authorization: Default::default(),
    };
    record_refusal(&ctx, runtime, run, execution_consent)
}

fn preparation_input(execution_consent: bool) -> &'static str {
    if execution_consent {
        return "{}";
    }
    r#"{"allowanceRef":{"schemaVersion":1,"investigationId":"owned-db-preparation","revision":1,"workId":"owned-prepare"}}"#
}

fn record_refusal(
    ctx: &ToolExecutionContext<'_>,
    runtime: &RefusalRuntime,
    run: &str,
    execution_consent: bool,
) -> Result<()> {
    let workspace = ctx.workspace.context("Owned workspace required")?;
    let record = ToolRunRecord::new(workspace.root(), run, "tool", TOOL);
    let input = preparation_input(execution_consent).parse()?;
    record_tool_run_started(record, &input);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    eprintln!("{run}: preparing bound input");
    let prepared = registry.prepare_dispatch_input(TOOL, input, ctx, None)?;
    let prepared = if execution_consent {
        prepared.authorize_explicit_headless()
    } else {
        prepared
    };
    eprintln!("{run}: dispatching prepared refusal");
    let dispatched =
        registry.dispatch_prepared_input_observed_with_runtime(prepared, ctx, Some(runtime))?;
    let error = dispatched
        .execution
        .err()
        .context("Preparation unexpectedly admitted")?;
    let message = validate_refusal(&error, execution_consent)?;
    let observation = ctx.run_observation().context("Missing observation")?;
    eprintln!("{run}: recording refusal");
    try_record_tool_run_failed_settled(record, &message, &observation, dispatched.completion)?;
    observation.flush()?;
    eprintln!("{run}: validating receipt");
    assert_healthy(workspace, run)
}

fn validate_refusal(error: &anyhow::Error, execution_consent: bool) -> Result<String> {
    let message = format!("{error:#}");
    let expected = if execution_consent {
        let metadata = kuzushi_core::runtime::runtime_failure_metadata(error)
            .context("Missing admission failure class")?;
        anyhow::ensure!(
            metadata.error_class == kuzushi_core::RuntimeFailureClass::AllowanceRefused
        );
        "needs an approved investigation allowance"
    } else {
        "requires explicit operator authorization"
    };
    anyhow::ensure!(message.contains(expected), "Unexpected refusal: {message}");
    Ok(message)
}

fn assert_healthy(workspace: &WorkspaceTarget, run: &str) -> Result<()> {
    let projection = kuzushi_core::run_lifecycle::load_run_projection(workspace.root(), run)?;
    anyhow::ensure!(
        projection.projection.health == kuzushi_core::run_lifecycle::ProjectionHealth::Healthy,
        "Refused work must retain a healthy typed receipt"
    );
    Ok(())
}

fn main() -> Result<()> {
    let root = std::env::args()
        .nth(1)
        .context("Owned target path required")?;
    let workspace = WorkspaceTarget::new(std::path::Path::new(&root))?;
    let ledger = approve(&workspace)?;
    let runtime = RefusalRuntime::default();
    refuse(&workspace, &runtime, "owned-db-unfunded", true)?;
    refuse(&workspace, &runtime, "owned-db-unapproved", false)?;
    let snapshot = ledger.allowance_snapshot(INVESTIGATION)?;
    anyhow::ensure!(
        runtime.queries.load(Ordering::SeqCst) == 0,
        "Provider was reached"
    );
    anyhow::ensure!(
        snapshot.committed_calls == 0
            && snapshot.review_calls == 0
            && snapshot.protected_review_remaining() == 1,
        "Refusals changed accounting"
    );
    anyhow::ensure!(
        !workspace.root().join(".git/worktrees").exists(),
        "Execution worktree created"
    );
    println!("{{\"queries\":0,\"committedCalls\":0,\"protectedReviewRemaining\":1,\"projectionHealthy\":true,\"liveProviderRequests\":0}}");
    Ok(())
}
